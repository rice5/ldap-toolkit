# Ansible LDAP 客户端部署

> 配合 `/etc/ansible/deploy-ldap-client.yml` 使用，详见 [README-ETC-ANSIBLE.md](README-ETC-ANSIBLE.md)

## 文件结构

```
ansible/
├── deploy-ldap-client.yml       # ★ 主 Playbook（自动检测 nslcd/SSSD）
├── group_vars/
│   └── all.yml                  # 变量 + vault_ldap_ro_pw（chmod 600）
├── files/
│   └── ca.crt                   # LDAP CA 证书（从 ldap01 复制）
├── README-ETC-ANSIBLE.md        # /etc/ansible 完整运维文档
├── README.md                    # 本文件
└── inventory-ldap.ini           # LDAP 清单模板
```

## 快速开始

```bash
# 1. 设置密码
vi group_vars/all.yml        # 改 vault_ldap_ro_pw = 真实密码
chmod 600 group_vars/all.yml

# 2. 试运行（不修改任何文件）
ansible-playbook -i /etc/ansible/hosts deploy-ldap-client.yml \
  -l target-node --check --diff

# 3. 正式部署
ansible-playbook -i /etc/ansible/hosts deploy-ldap-client.yml \
  -l target-node
```

## 部署模式

| 场景 | 部署模式 | 说明 |
|------|---------|------|
| **新机器**（任何 OS） | SSSD | 自动检测，统一安装 SSSD |
| 已有 nslcd 的 CentOS 7 | nslcd | 沿用存量，升级 TLS |
| 已有 SSSD 的节点 | SSSD | 更新配置 |

## 部署内容一览

| 文件 | nslcd | SSSD | 说明 |
|------|-------|------|------|
| `/etc/openldap/ldap.conf` | ✅ | ✅ | ldaps:// URI + TLS demand |
| `/etc/nslcd.conf` | ✅ | — | ssl on + readonly bind |
| `/etc/sssd/sssd.conf` | — | ✅ | 精简配置（对齐原始） |
| `/etc/autofs_ldap_auth.conf` | ✅ | ✅ | 权限 0600 |
| `/etc/sudo-ldap.conf` | ✅ | ✅ | ldaps:// URI |
| CA 证书 | ✅ | ✅ | `/etc/openldap/certs/ca.crt` |
| autofs / nslcd / SSSD | ✅ | ✅ | 服务重启 + enable |

## 验证

```bash
# 检查部署后状态
ansible target-node -m shell -a \
  "ldapsearch -x -H ldaps://ldap01.example.com:636 -b '' -s base dn"

ansible target-node -m shell -a "id testuser && sudo -l && ls /share/home/"
```
