# /etc/ansible — HPC 集群 Ansible 管理

> Ansible `core 2.13.13` | 主机: `mgmt01.example.com` (192.168.1.14)

## 目录结构

```
/etc/ansible/
├── ansible.cfg                   # 全局配置（forks=50, pipelining, log）
├── hosts                         # ★ 主主机清单
├── deploy-ldap-client.yml        # ★ LDAP 客户端 TLS 部署（支持 nslcd + SSSD）
│
├── group_vars/
│   └── all.yml                   # LDAP 变量 + 密码（chmod 600）
│
├── files/
│   └── ca.crt                    # LDAP CA 证书
│
├── playbook/                     # 14 个 playbook
│   ├── system-init.yml           # 系统初始化（15→1）
│   ├── firewall.yml              # 防火墙规则（3→1）
│   ├── install-zabbix.yml        # Zabbix Agent 2（3→1）
│   ├── install-telegraf.yml      # Telegraf 监控（3→1）
│   ├── install-supervisor.yml    # Supervisor + LM（4→1）
│   ├── user-setup.yml            # 用户/Sudo 配置（3→1）
│   ├── deploy-pypi.yml / deploy-autofs.yml / deploy-modules.yml
│   ├── security-dirtyfrag.yml / add_rdma_user.yml / _vault.yml
│   ├── edauser_passwd.yaml / root_passwd.yaml
│   ├── power-on-servers.yml / add_cdns-edk.yml / nj_ping.yml
│   └── ipmi_credentials.yml / ipmi_host.ini
│
├── roles/                        # 标准 Ansible Role（autofs, common, modules, pypi）
├── scripts/                      # 运维脚本（30 个）
├── conf/                         # 主机配置管理
├── bak/                          # 备份 & 归档
├── ipmi/ / ssh_keys/ / nj_hosts/ / tmp/
└── README.md / README-LDAP.md
```

## LDAP 客户端部署

### 快速开始

```bash
# 1. 设置密码
vi /etc/ansible/group_vars/all.yml   # 改 vault_ldap_ro_pw
chmod 600 /etc/ansible/group_vars/all.yml

# 2. 试运行
ansible-playbook -i hosts deploy-ldap-client.yml -l test-node --check --diff

# 3. 正式部署
ansible-playbook -i hosts deploy-ldap-client.yml -l target-group

# 4. 滚动部署（每次10台）
ansible-playbook -i hosts deploy-ldap-client.yml --serial 10
```

### 部署模式

| 模式 | 适用 | 自动检测条件 |
|------|------|-------------|
| **nslcd** | CentOS 7 存量节点 | `systemctl is-active nslcd` |
| **sssd** | CentOS 7 新装 / Rocky 8+ | `systemctl is-active sssd` 或 OS ≥ 8 |

- 自动检测：`ldap_client_mode: auto`（默认）
- 强制指定：在 inventory 中设 `ldap_client_mode=sssd`

### 部署内容

| 配置项 | nslcd 模式 | SSSD 模式 |
|--------|-----------|----------|
| `/etc/openldap/ldap.conf` | ✅ ldaps:// + TLS demand | ✅ 同左 |
| `/etc/nslcd.conf` | ✅ ssl on + bind 凭据 | — |
| `/etc/sssd/sssd.conf` | — | ✅ 精简配置，对齐原始 |
| `/etc/autofs_ldap_auth.conf` | ✅ 0600 权限 | ✅ 同左 |
| `/etc/sudo-ldap.conf` | ✅ ldaps:// URI | ✅ 同左 |
| `/etc/nsswitch.conf` | automount: files ldap<br>sudoers: files ldap | automount: sss files<br>sudoers: files sss |
| CA 证书 | ✅ | ✅ |
| autofs 重启 | ✅ | ✅ |
| 只读账号 bind | ✅ | ✅ |

## 脚本→Playbook 转换

| 原脚本数量 | Playbook | 说明 |
|-----------|----------|------|
| 15 | **system-init.yml** | yum, ipv6, coredump, abrt, limits, chronyd, sshd, etc. |
| 3 | **firewall.yml** | firewalld-prod/etx/lm |
| 3 | **install-zabbix.yml** | Zabbix Agent 2 安装 |
| 3 | **install-telegraf.yml** | Telegraf 监控 |
| 4 | **install-supervisor.yml** | Supervisor + License Manager |
| 3 | **user-setup.yml** | 用户/Sudo 配置 |

> 已归档 34 个脚本 → `bak/scripts-archived-20260707/`

## 常用操作

```bash
# 基础
ansible all -m ping
ansible all -m shell -a "uptime"

# 系统初始化
ansible-playbook playbook/system-init.yml -l new-node --check --diff
ansible-playbook playbook/system-init.yml -l new-node -e skip_firewall_base=true

# 监控部署
ansible-playbook playbook/install-zabbix.yml -l t01hpc
ansible-playbook playbook/install-telegraf.yml -l t01hpc

# 防火墙
ansible-playbook playbook/firewall.yml -l etx

# 批量脚本执行（剩余 30 个脚本）
ansible all -m script -a "/etc/ansible/scripts/os_version.sh" --become
```

## 主机清单分组

| 组 | 说明 |
|----|------|
| `t01hpc` / `t02hpc` | HPC 计算节点 |
| `etx` | ETX 登录/管理节点 |
| `lm` | License Manager 服务器 |
| `ms` | 测试节点 |

## ansible.cfg 关键配置

| 配置 | 值 | 说明 |
|------|-----|------|
| `inventory` | `/etc/ansible/hosts` | 默认清单 |
| `forks` | `50` | 并行数 |
| `host_key_checking` | `False` | 跳过主机密钥 |
| `pipelining` | `True` | 减少 SSH 连接 |
| `log_path` | `/var/log/ansible.log` | 日志 |

## 备份

```bash
cp -a /etc/ansible /etc/ansible.bak.$(date +%Y%m%d)
```
