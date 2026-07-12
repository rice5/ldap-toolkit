#!/bin/bash
#===============================================================================
# OpenLDAP TLS 证书生成工具
# 生成自签名 CA 和节点证书，用于 LDAPS/StartTLS。
#
# 用法：
#   ./gen-certs.sh                              # 为本地主机名生成
#   ./gen-certs.sh ldap01.example.com ldap02.example.com # 为指定主机生成
#   ./gen-certs.sh --ca-only                     # 仅生成 CA
#
# 输出：
#   /etc/openldap/certs/ca.crt             # CA 证书（分发到所有节点和客户端）
#   /etc/openldap/certs/ca.key             # CA 私钥（务必安全保存！）
#   /etc/openldap/certs/<hostname>.crt     # 各节点的服务器证书
#   /etc/openldap/certs/<hostname>.key     # 各节点的服务器私钥
#
# 兼容性：
#   - RHEL/CentOS 7 (OpenSSL 1.0.x)：使用简化模式（无 SAN 扩展）
#   - RHEL 8/9 (OpenSSL 1.1+/3.x)：使用完整 SAN 扩展
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# 默认配置参数
#------------------------------------------------------------------------------
CERT_DIR="${LDAP_TLS_CERT_DIR:-/etc/openldap/certs}"
CA_CERT="${CERT_DIR}/ca.crt"
CA_KEY="${CERT_DIR}/ca.key"
SERVER_CERT="${CERT_DIR}/server.crt"
SERVER_KEY="${CERT_DIR}/server.key"
CA_DAYS="${CA_DAYS:-36500}"       # CA 证书有效期 100 年
CERT_DAYS="${CERT_DAYS:-3650}"    # 服务器证书有效期 10 年
COUNTRY="${TLS_COUNTRY:-CN}"
STATE="${TLS_STATE:-Beijing}"
CITY="${TLS_CITY:-Beijing}"
ORG="${TLS_ORG:-HPC}"
OU="${TLS_OU:-IT}"

#------------------------------------------------------------------------------
# 使用说明
#------------------------------------------------------------------------------
usage() {
    cat << EOF
用法: $(basename "$0") [选项] [主机名...]

生成 OpenLDAP 自签名 TLS 证书。

选项:
  --ca-only         仅生成 CA 证书
  -o, --output DIR  输出目录（默认: ${CERT_DIR}）
  --country CODE    国家代码（默认: ${COUNTRY}）
  --state NAME      省份（默认: ${STATE}）
  --city NAME       城市（默认: ${CITY}）
  --org NAME        组织（默认: ${ORG}）
  --ou NAME         部门（默认: ${OU}）
  -h, --help        显示帮助信息

不指定主机名时，使用本地主机名。
EOF
    exit 0
}

#------------------------------------------------------------------------------
# 工具函数
#------------------------------------------------------------------------------

# 输出带时间戳的日志
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# 错误退出
error_exit() {
    echo "错误: $*" >&2
    exit 1
}

# 检测 OpenSSL 版本（主版本号）
# 返回: 1 表示 1.0.x, 3 表示 3.x, 其他
openssl_major_version() {
    openssl version | grep -oP '(?<=OpenSSL )\d+' | head -1
}

#------------------------------------------------------------------------------
# 解析命令行参数
#------------------------------------------------------------------------------
CA_ONLY=false
HOSTNAMES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-only)       CA_ONLY=true; shift ;;
        -o|--output)     CERT_DIR="$2"; shift 2 ;;
        --country)       COUNTRY="$2"; shift 2 ;;
        --state)         STATE="$2"; shift 2 ;;
        --city)          CITY="$2"; shift 2 ;;
        --org)           ORG="$2"; shift 2 ;;
        --ou)            OU="$2"; shift 2 ;;
        -h|--help)       usage ;;
        --) shift; HOSTNAMES+=("$@"); break ;;
        -*) error_exit "未知选项: $1" ;;
        *)  HOSTNAMES+=("$1"); shift ;;
    esac
done

# 未指定主机名时使用本地主机名
if [ ${#HOSTNAMES[@]} -eq 0 ] && [ "$CA_ONLY" = false ]; then
    HOSTNAMES+=("$(hostname -f 2>/dev/null || hostname)")
fi

CA_CERT="${CERT_DIR}/ca.crt"
CA_KEY="${CERT_DIR}/ca.key"
OSSL_VER=$(openssl_major_version)

log "开始生成 TLS 证书..."
log "输出目录: ${CERT_DIR}"
log "OpenSSL 主版本: ${OSSL_VER}"

# 创建证书目录
mkdir -p "${CERT_DIR}"
chmod 750 "${CERT_DIR}"

#------------------------------------------------------------------------------
# 步骤 1：生成 CA（证书颁发机构）
# 生成自签名 CA 证书，用于签发所有服务器证书
#------------------------------------------------------------------------------
log "步骤 1: 生成 CA 根证书..."

# 如果 CA 私钥已存在，先备份
if [ -f "${CA_KEY}" ]; then
    log "CA 私钥已存在: ${CA_KEY}"
    log "备份现有私钥到 ${CA_KEY}.bak.$(date +%s)"
    cp "${CA_KEY}" "${CA_KEY}.bak.$(date +%s)"
fi

# 检查是否覆盖已有 CA 证书
if [ -f "${CA_CERT}" ]; then
    log "CA 证书已存在: ${CA_CERT}"
    read -rp "CA 证书已存在，是否覆盖？[y/N]: " confirm
    if [ "${confirm,,}" != "y" ]; then
        log "保留现有 CA 证书，跳过 CA 生成。"
    else
        NEED_CA=true
    fi
else
    NEED_CA=true
fi

if [ "${NEED_CA:-false}" = true ]; then
    # 生成 CA 私钥（4096 位 RSA）
    openssl genrsa -out "${CA_KEY}" 4096 || error_exit "CA 私钥生成失败"
    chmod 400 "${CA_KEY}"

    # 生成自签名 CA 证书
    openssl req -new -x509 -days "${CA_DAYS}" \
        -key "${CA_KEY}" \
        -out "${CA_CERT}" \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=LDAP CA" \
        || error_exit "CA 证书生成失败"

    chmod 444 "${CA_CERT}"
    log "CA 证书已生成: ${CA_CERT}"
else
    log "使用现有 CA: ${CA_CERT}"
fi

#------------------------------------------------------------------------------
# 步骤 2：生成各节点的服务器证书
# 为每个主机名生成独立的服务器证书
#------------------------------------------------------------------------------
if [ "$CA_ONLY" = true ]; then
    log "仅 CA 模式，跳过服务器证书生成。"
    echo ""
    echo "=== CA 证书信息 ==="
    echo "CA 证书: ${CA_CERT}"
    echo "CA 私钥: ${CA_KEY}"
    echo ""
    echo "将 ${CA_CERT} 分发到所有 LDAP 服务器和客户端。"
    echo "妥善保管 ${CA_KEY}，仅在签发新证书时需要。"
    exit 0
fi

for HOSTNAME in "${HOSTNAMES[@]}"; do
    log "步骤 2: 为 ${HOSTNAME} 生成服务器证书..."

    # 确定输出文件名（单主机时使用 server.crt/key，多主机时使用 <hostname>.crt/key）
    if [ ${#HOSTNAMES[@]} -eq 1 ]; then
        local_srv_cert="${SERVER_CERT}"
        local_srv_key="${SERVER_KEY}"
    else
        local_srv_cert="${CERT_DIR}/${HOSTNAME}.crt"
        local_srv_key="${CERT_DIR}/${HOSTNAME}.key"
    fi

    # 生成服务器私钥
    openssl genrsa -out "${local_srv_key}" 2048 || error_exit "服务器私钥生成失败: ${HOSTNAME}"
    chmod 400 "${local_srv_key}"

    # 生成证书签名请求（CSR）
    openssl req -new \
        -key "${local_srv_key}" \
        -out "${CERT_DIR}/${HOSTNAME}.csr" \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=${HOSTNAME}" \
        || error_exit "CSR 生成失败: ${HOSTNAME}"

    # 签发证书（兼容 OpenSSL 1.0.x 和 1.1+）
    # OpenSSL 1.0.x 不支持 extfile 中的 authorityKeyIdentifier，使用简化签发
    if [ "${OSSL_VER}" -le 1 ] 2>/dev/null; then
        # OpenSSL 1.0.x 简化模式：不使用 SAN 扩展文件
        log "检测到 OpenSSL 1.0.x，使用兼容模式签发证书"
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${CERT_DIR}/${HOSTNAME}.csr" \
            -CA "${CA_CERT}" \
            -CAkey "${CA_KEY}" \
            -CAcreateserial \
            -out "${local_srv_cert}" \
            || error_exit "服务器证书签发失败: ${HOSTNAME}（OpenSSL 1.0.x 模式）"
    else
        # OpenSSL 1.1+：使用完整 SAN 扩展
        log "使用完整 SAN 扩展模式签发证书"
        cat > "${CERT_DIR}/${HOSTNAME}.ext" << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${HOSTNAME}
EOF

        # FQDN 额外添加短主机名作为 SAN
        if [[ "${HOSTNAME}" == *.* ]]; then
            SHORT_NAME="${HOSTNAME%%.*}"
            echo "DNS:${SHORT_NAME}" >> "${CERT_DIR}/${HOSTNAME}.ext"
        fi

        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${CERT_DIR}/${HOSTNAME}.csr" \
            -CA "${CA_CERT}" \
            -CAkey "${CA_KEY}" \
            -CAcreateserial \
            -out "${local_srv_cert}" \
            -extfile "${CERT_DIR}/${HOSTNAME}.ext" \
            || error_exit "服务器证书签发失败: ${HOSTNAME}"
        rm -f "${CERT_DIR}/${HOSTNAME}.ext"
    fi

    chmod 444 "${local_srv_cert}"

    # 清理 CSR 临时文件
    rm -f "${CERT_DIR}/${HOSTNAME}.csr"

    log "${HOSTNAME} 服务器证书已生成。"

    # 单主机模式：创建符号链接 server.crt → <hostname>.crt
    if [ ${#HOSTNAMES[@]} -gt 1 ]; then
        if [ "${HOSTNAME}" = "$(hostname -f 2>/dev/null || hostname)" ] || \
           [ "${HOSTNAME}" = "$(hostname 2>/dev/null)" ]; then
            log "创建本机符号链接 server.crt → ${HOSTNAME}.crt"
            ln -sf "${HOSTNAME}.crt" "${SERVER_CERT}" 2>/dev/null || true
            ln -sf "${HOSTNAME}.key" "${SERVER_KEY}" 2>/dev/null || true
        fi
    fi
done

#------------------------------------------------------------------------------
# 步骤 3：设置文件所有权和权限
#------------------------------------------------------------------------------
log "步骤 3: 设置证书文件权限..."

# 尝试设置 ldap:ldap 所有权（适用于 slapd）
if getent group ldap &>/dev/null; then
    chown -R root:ldap "${CERT_DIR}" 2>/dev/null || true
elif getent group openldap &>/dev/null; then
    chown -R root:openldap "${CERT_DIR}" 2>/dev/null || true
fi

chmod 750 "${CERT_DIR}"
# 私钥仅 root 和 ldap 组可读，证书所有人可读
find "${CERT_DIR}" -type f -name "*.key" ! -name "ca.key" -exec chmod 440 {} \; 2>/dev/null || true
find "${CERT_DIR}" -type f -name "ca.key" -exec chmod 400 {} \; 2>/dev/null || true
find "${CERT_DIR}" -type f -name "*.crt" -exec chmod 444 {} \; 2>/dev/null || true

#------------------------------------------------------------------------------
# 完成摘要
#------------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  TLS 证书生成完成"
echo "=========================================="
echo ""
echo "生成的文件:"
ls -la "${CERT_DIR}/"*.crt "${CERT_DIR}/"*.key 2>/dev/null || ls -la "${CERT_DIR}/"
echo ""
echo "=== 后续步骤 ==="
echo ""
echo "1. 妥善保管 CA 私钥（仅在签发新证书时需要）:"
echo "     chmod 400 ${CA_KEY}"
echo ""
echo "2. 将 CA 证书分发到所有 LDAP 服务器和客户端:"
echo "     scp ${CA_CERT} root@<host>:${CA_CERT}"
echo ""
echo "3. 在每台 LDAP 服务器上确保证书对 ldap 用户可读:"
echo "     chown root:ldap ${CERT_DIR}/*.key"
echo "     chmod 440 ${CERT_DIR}/*.key"
echo ""
echo "4. 运行 ldap.master 或 ldap.slave 应用 TLS 配置。"
echo ""
echo "5. 在客户端配置 /etc/openldap/ldap.conf:"
echo "     TLS_CACERT ${CA_CERT}"
echo "     TLS_REQCERT demand"
echo ""
echo "6. 验证 TLS 连接:"
echo "     openssl s_client -connect \$(hostname):636 -showcerts < /dev/null"
echo "     ldapsearch -x -H ldaps://\$(hostname):636 -D 'cn=Manager,${LDAP_SUFFIX:-dc=example,dc=com}' -W -b '${LDAP_SUFFIX:-dc=example,dc=com}'"
