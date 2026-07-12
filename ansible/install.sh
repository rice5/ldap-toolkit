#!/bin/bash
#===============================================================================
# LDAP Ansible 文件部署脚本
# 将 ansible playbook、变量、证书部署到 /etc/ansible/
#
# 用法：
#   cd /opt/ldap-toolkit/ansible
#   bash install.sh
#===============================================================================

set -euo pipefail

ANSIBLE_DIR="/etc/ansible"
BACKUP_DIR="/etc/ansible.bak.$(date +%Y%m%d_%H%M%S)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  LDAP Ansible 部署"
echo "========================================"
echo "  目标目录: ${ANSIBLE_DIR}"
echo "  备份目录: ${BACKUP_DIR}"
echo ""

#------------------------------------------------------------------------------
# 1. 备份现有 /etc/ansible
#------------------------------------------------------------------------------
if [ -d "${ANSIBLE_DIR}" ]; then
    echo "备份现有 ${ANSIBLE_DIR} → ${BACKUP_DIR} ..."
    cp -a "${ANSIBLE_DIR}" "${BACKUP_DIR}"
    echo "[OK] 备份完成。"
else
    echo "${ANSIBLE_DIR} 不存在，将全新创建。"
    mkdir -p "${ANSIBLE_DIR}"
fi

#------------------------------------------------------------------------------
# 2. 创建目录结构
#------------------------------------------------------------------------------
echo "创建目录结构..."
mkdir -p "${ANSIBLE_DIR}"/{files,group_vars,host_vars,templates}

#------------------------------------------------------------------------------
# 3. 部署 LDAP 客户端 playbook
#------------------------------------------------------------------------------
echo "部署 playbook..."
cp "${SCRIPT_DIR}/deploy-ldap-client.yml" "${ANSIBLE_DIR}/"
echo "  [OK] deploy-ldap-client.yml"

#------------------------------------------------------------------------------
# 4. 部署变量文件
#------------------------------------------------------------------------------
echo "部署变量文件..."
if [ -f "${SCRIPT_DIR}/group_vars/all.yml" ]; then
    cp "${SCRIPT_DIR}/group_vars/all.yml" "${ANSIBLE_DIR}/group_vars/all.yml"
    echo "  [OK] group_vars/all.yml"
fi

#------------------------------------------------------------------------------
# 5. 部署 CA 证书
#------------------------------------------------------------------------------
echo "部署证书文件..."
if [ -f "${SCRIPT_DIR}/files/ca.crt" ]; then
    cp "${SCRIPT_DIR}/files/ca.crt" "${ANSIBLE_DIR}/files/ca.crt"
    chmod 444 "${ANSIBLE_DIR}/files/ca.crt"
    echo "  [OK] files/ca.crt"
else
    echo "  [警告] files/ca.crt 不存在，请从 ldap01 获取:"
    echo "    scp root@192.168.1.12:/etc/openldap/certs/ca.crt ${ANSIBLE_DIR}/files/"
fi

#------------------------------------------------------------------------------
# 6. 部署清单（不覆盖已有 inventory）
#------------------------------------------------------------------------------
echo "部署主机清单..."
if [ -f "${ANSIBLE_DIR}/inventory.ini" ]; then
    echo "  [跳过] inventory.ini 已存在，保留现有文件。"
    echo "  参考模板: ${SCRIPT_DIR}/inventory.ini"
else
    cp "${SCRIPT_DIR}/inventory.ini" "${ANSIBLE_DIR}/inventory.ini"
    echo "  [OK] inventory.ini（模板，请按实际环境编辑）"
fi

#------------------------------------------------------------------------------
# 7. 部署 README
#------------------------------------------------------------------------------
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${ANSIBLE_DIR}/README.md"
    echo "  [OK] README.md"
fi

#------------------------------------------------------------------------------
# 8. ansible.cfg（仅在不存在时创建）
#------------------------------------------------------------------------------
if [ ! -f "${ANSIBLE_DIR}/ansible.cfg" ]; then
    cat > "${ANSIBLE_DIR}/ansible.cfg" << 'EOF'
[defaults]
inventory      = /etc/ansible/inventory.ini
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = /etc/ansible/facts_cache
fact_caching_timeout = 3600
stdout_callback = yaml

[ssh_connection]
pipelining = True
control_path = /tmp/ansible-%%h-%%p-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
EOF
    echo "  [OK] ansible.cfg（默认配置）"
else
    echo "  [跳过] ansible.cfg 已存在。"
fi

echo ""
echo "========================================"
echo "  部署完成"
echo "========================================"
echo ""
echo "  文件列表:"
find "${ANSIBLE_DIR}" -type f | sort | while read f; do
    echo "    ${f}"
done
echo ""
echo "  备份目录: ${BACKUP_DIR}"
echo ""
echo "  下一步:"
echo "    1. 编辑 ${ANSIBLE_DIR}/inventory.ini 添加节点"
echo "    2. 加密密码: ansible-vault encrypt_string --name 'vault_ldap_ro_pw'"
echo "    3. 试运行:   ansible-playbook deploy-ldap-client.yml -l test-node --check"
echo ""
