# OpenLDAP TLS/SSL 部署指南

本文档介绍如何为 OpenLDAP 生成 TLS 证书，并配置 LDAPS（端口 636）和 StartTLS（端口 389）。

## 快速开始：自签名证书

对于内部/HPC 部署，自签名证书是最简单的方式。

### 步骤 1：生成证书

```bash
cd server/tls
chmod +x gen-certs.sh

# 为所有 LDAP 服务器生成证书
./gen-certs.sh ldap01.example.com ldap02.example.com
```

生成的文件：
```
/etc/openldap/certs/
├── ca.crt              # CA 证书 → 分发到所有节点和客户端
├── ca.key              # CA 私钥 → 仅在 CA 主机上安全保存！
├── ca.srl              # CA 序列号
├── server.crt          # 本机服务器证书
├── server.key          # 本机服务器私钥
├── ldap01.example.com.crt
├── ldap01.example.com.key
├── ldap02.example.com.crt
└── ldap02.example.com.key
```

### 步骤 2：分发证书

```bash
# 将 CA 证书复制到所有节点
for host in ldap02 client01 client02; do
    scp /etc/openldap/certs/ca.crt $host:/etc/openldap/certs/ca.crt
done

# 如果在 ldap01 上生成，需分发 ldap02 的服务器证书
scp /etc/openldap/certs/ldap02.example.com.crt ldap02:/etc/openldap/certs/server.crt
scp /etc/openldap/certs/ldap02.example.com.key ldap02:/etc/openldap/certs/server.key
```

### 步骤 3：设置权限

在每台 LDAP 服务器上：
```bash
chown -R root:ldap /etc/openldap/certs
chmod 750 /etc/openldap/certs
chmod 400 /etc/openldap/certs/*.key
chmod 444 /etc/openldap/certs/*.crt
```

### 步骤 4：配置 slapd 启用 LDAPS

运行 `ldap.master` 或 `ldap.slave` 会自动配置 TLS（当 `LDAP_TLS_ENABLED=yes` 时）。

或手动配置：
```bash
# 创建 TLS LDIF
cat > /tmp/tls.ldif << 'EOF'
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key
-
add: olcTLSCipherSuite
olcTLSCipherSuite: HIGH:!aNULL:!eNULL:!SSLv2:!SSLv3
-
add: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
-
add: olcLocalSSF
olcLocalSSF: 256
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/tls.ldif

# 更新 SLAPD_URLS 加入 ldaps://
sed -i 's|^SLAPD_URLS=.*|SLAPD_URLS="ldapi:/// ldap:/// ldaps:///"|' /etc/sysconfig/slapd
systemctl restart slapd
```

### 步骤 5：验证 TLS

```bash
# 检查 slapd 是否在 LDAPS 端口监听
ss -tlnp | grep 636

# 使用 openssl 验证证书
openssl s_client -connect localhost:636 -showcerts < /dev/null

# 测试 LDAPS 连接
ldapsearch -x -H ldaps://localhost:636 \
  -b 'dc=example,dc=com' \
  -D 'cn=Manager,dc=example,dc=com' -W

# 测试 StartTLS
ldapsearch -x -H ldap://localhost:389 -Z \
  -b 'dc=example,dc=com' \
  -D 'cn=Manager,dc=example,dc=com' -W
```

---

## 手动创建证书（OpenSSL）

### 生成 CA

```bash
# CA 私钥
openssl genrsa -out /etc/openldap/certs/ca.key 4096
chmod 400 /etc/openldap/certs/ca.key

# 自签名 CA 证书（有效期 10 年）
openssl req -new -x509 -days 3650 \
  -key /etc/openldap/certs/ca.key \
  -out /etc/openldap/certs/ca.crt \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=HPC/OU=IT/CN=LDAP CA"
```

### 生成服务器证书

```bash
HOSTNAME=$(hostname -f)

# 服务器私钥
openssl genrsa -out /etc/openldap/certs/server.key 2048
chmod 400 /etc/openldap/certs/server.key

# 证书签名请求
openssl req -new \
  -key /etc/openldap/certs/server.key \
  -out /tmp/server.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=HPC/OU=IT/CN=${HOSTNAME}"

# SAN 扩展（主题备用名称）
cat > /tmp/san.ext << EOF
subjectAltName=DNS:${HOSTNAME},DNS:${HOSTNAME%%.*}
EOF

# 用 CA 签名
openssl x509 -req -days 1825 \
  -in /tmp/server.csr \
  -CA /etc/openldap/certs/ca.crt \
  -CAkey /etc/openldap/certs/ca.key \
  -CAcreateserial \
  -out /etc/openldap/certs/server.crt \
  -extfile /tmp/san.ext

chmod 444 /etc/openldap/certs/server.crt
rm -f /tmp/server.csr /tmp/san.ext
```

---

## Client Configuration

### /etc/openldap/ldap.conf

```ini
BASE    dc=example,dc=com
URI     ldaps://ldap01.example.com ldaps://ldap02.example.com

TLS_CACERT      /etc/openldap/certs/ca.crt
TLS_REQCERT     demand
```

### SSSD 客户端（/etc/sssd/sssd.conf）

```ini
[domain/LDAP]
ldap_uri = ldaps://ldap01.example.com, ldaps://ldap02.example.com
ldap_tls_cacert = /etc/openldap/certs/ca.crt
ldap_tls_reqcert = demand
ldap_id_use_start_tls = false
```

---

## 证书续期

证书默认有效期为 5 年。续期方法：

### 方法 1：重新运行 gen-certs.sh

```bash
# 使用现有 CA 生成新证书
./gen-certs.sh ldap01.example.com ldap02.example.com

# 在每台服务器上重启 slapd
systemctl restart slapd
```

### 方法 2：手动续期

```bash
# 生成新服务器密钥和 CSR
openssl genrsa -out /etc/openldap/certs/server.key.new 2048
openssl req -new -key /etc/openldap/certs/server.key.new \
  -out /tmp/server.csr \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=HPC/OU=IT/CN=$(hostname -f)"

# 用现有 CA 签名
openssl x509 -req -days 1825 \
  -in /tmp/server.csr \
  -CA /etc/openldap/certs/ca.crt \
  -CAkey /etc/openldap/certs/ca.key \
  -out /etc/openldap/certs/server.crt.new

# 替换旧证书
mv /etc/openldap/certs/server.key.new /etc/openldap/certs/server.key
mv /etc/openldap/certs/server.crt.new /etc/openldap/certs/server.crt
chmod 400 /etc/openldap/certs/server.key
chmod 444 /etc/openldap/certs/server.crt
chown root:ldap /etc/openldap/certs/server.*

systemctl restart slapd
```

### CA 证书过期时

1. 生成新的 CA
2. 用新 CA 签发新的服务器证书
3. 在所有服务器和客户端上替换 CA 证书
4. 在所有服务器上重启 slapd
5. 在所有客户端上重启 SSSD

---

## 常见错误及修复

### 错误：`TLS: peer cert untrusted or revoked`

**原因**：客户端未安装 CA 证书或不被信任。

**修复**：
```bash
# 确认 CA 证书存在
ls -la /etc/openldap/certs/ca.crt

# 检查客户端配置
grep TLS_CACERT /etc/openldap/ldap.conf
grep ldap_tls_cacert /etc/nslcd.conf
```

### 错误：`TLS: hostname does not match CN in peer certificate`

**原因**：服务器证书的 CN 与 LDAP URI 中使用的主机名不匹配。

**修复**：使用与证书 CN 匹配的 FQDN，或重新生成包含正确主机名的证书。

### 错误：`ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)`

**原因**：TLS 握手失败 — 证书权限或加密套件不匹配。

**修复**：
```bash
# 检查证书权限
ls -la /etc/openldap/certs/
# 密钥应为 0400，证书应为 0444，属主为 root:ldap

# 调试命令
openssl s_client -connect localhost:636 -showcerts
ldapsearch -d -1 -H ldaps://localhost:636 ...
```

### 错误：`cannot open /etc/openldap/certs/server.key: Permission denied`

**原因**：slapd 以 `ldap` 用户运行，无法读取密钥文件。

**修复**：
```bash
chown root:ldap /etc/openldap/certs/server.key
chmod 440 /etc/openldap/certs/server.key
```

### 警告：`TLS: could not set cipher list`

**原因**：加密套件字符串在当前 OpenSSL 版本中不受支持。

**修复**：调整加密套件：
```bash
# RHEL/CentOS 7（OpenSSL 1.0.x）
olcTLSCipherSuite: HIGH:!aNULL:!MD5

# RHEL 8+（OpenSSL 1.1+/3.x）
olcTLSCipherSuite: HIGH:!aNULL:!eNULL:!SSLv2:!SSLv3
```
