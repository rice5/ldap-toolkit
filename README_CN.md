# LDAP 部署工具包

OpenLDAP 多主镜像模式部署工具包，适用于 RHEL/CentOS 7（兼容 8/9）。

## 架构

```
                          ┌──────────────────┐
                          │   LDAP 客户端    │
                          │   (SSSD)         │
                          └────────┬─────────┘
                                   │ ldaps://
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐  ┌────▼──────┐
              │  ldap01   │  │  ldap02   │
              │ (ServerID │  │ (ServerID │
              │    1)     │  │    2)     │
              └─────┬─────┘  └────┬──────┘
                    │              │
                    └── 镜像模式 ──┘
                       复制
```

- **多主镜像模式**：两个节点均为可读写同位节点。
- **LDAPS/StartTLS**：所有连接使用 TLS 1.2+ 加密。
- **ShadowAccount**：完整的账号生命周期管理（密码过期、启用/禁用）。
- **严格 ACL**：匿名仅可认证，只读账号可查询，其他拒绝访问。
- **只读账号**：`cn=readonly` 专用于查询操作，保护管理员凭据。

## 快速开始

### 1. 配置

```bash
# 编辑配置文件
vi config/ldap.conf

# 必须设置的变量：
#   LDAP_DC1, LDAP_DC2, LDAP_SUFFIX, LDAP_ROOTDN
#   LDAP_MASTER1, LDAP_MASTER2
#   LDAP_ROOTPW（通过环境变量设置或留空交互式输入）
```

### 2. 生成 TLS 证书

```bash
cd server/tls
chmod +x gen-certs.sh
./gen-certs.sh ldap01.example.com ldap02.example.com

# 将 CA 证书分发到所有客户端节点
scp /etc/openldap/certs/ca.crt ldap02:/etc/openldap/certs/ca.crt
for host in client01 client02; do
    scp /etc/openldap/certs/ca.crt $host:/etc/openldap/certs/ca.crt
done
```

详见 [docs/TLS-SETUP.md](docs/TLS-SETUP.md)。

### 3. 安装 LDAP 服务器

```bash
# 在 ldap01 上（主节点，服务器 ID 1）
cd server
chmod +x ldap.master
./ldap.master

# 在 ldap02 上（从节点，服务器 ID 2）
cd server
chmod +x ldap.slave
./ldap.slave
```

### 4. 配置 LDAP 客户端

**推荐：Ansible 批量部署**（`ansible/deploy-ldap-client.yml`）
- 自动检测已有客户端（nslcd/SSSD）
- 新机器统一安装 SSSD
- 支持 `--check --diff` 试运行，`--serial 10` 滚动部署
- 详见 `ansible/README-ETC-ANSIBLE.md`

**备选：Shell 脚本单机部署**（`client/ldap.client`）
```bash
cd client
chmod +x ldap.client
./ldap.client    # 或 ./ldap.client --mode sssd
```

### 5. 管理用户（ldapadmin.py）

```bash
cd admin
# 最简单的用法：自动生成 10 位密码，放在默认 OU
./ldapadmin.py user add zhangsan
```

#### user add — 新建用户

```
./ldapadmin.py user add <uid> [options]
```

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--ou` | `People` | 所属 OU，用户 DN 为 `cn=<uid>,ou=<ou>,ou=People,dc=...`（OU 不存在则自动创建） |
| `--password` / `--passwd` | 自动生成 10 位 | 含大写+小写+数字+特殊字符，命令行指定时用引号包裹 |
| `--home` | `/share/home/<uid>` | 家目录 |
| `--shell` | `/bin/csh` | 登录 Shell |
| `--uid` | 自动（max+1, ≥5000） | 指定 UID，同时扫描 posixAccount uidNumber + posixGroup gidNumber，取最大值 +1 确保不冲突 |
| `--gid` | = UID | UID/GID 统一 |
| `--group` | = 用户名 | 主组（不存在则自动创建） |
| `--groups` | 无 | 附加组，逗号分隔 |
| `--mail` | `<uid>@example.com` | 邮箱，传空字符串 `--mail ''` 则不设置 |
| `--expire` | 无（永不过期） | 过期日期 `YYYY-MM-DD` |
| `--max-days` | 90 | 密码有效期（天） |
| `--disabled` | false | 创建为禁用状态 |
| `--must-change` | false | 首次登录强制改密 |
| `--dry-run` / `-n` | false | 预演模式：打印摘要，不实际写入 LDAP |

**默认规则速记**：不加参数 = 自动 ID + 10 位强密码打印 + `/share/home/<uid>` + `/bin/csh` + `ou=People`。用户 DN 为 `cn=<uid>,ou=<ou>,ou=People,dc=...`，组 DN 为 `cn=<name>,ou=Group,dc=...`。

```bash
# ★ 推荐：先用 --dry-run/-n 预演，确认无误后再正式执行
./ldapadmin.py user add zhangsan --ou dv --dry-run
./ldapadmin.py user add zhangsan --ou dv

# 指定所有属性
./ldapadmin.py user add vendor1 --ou dv --home /opt/vendor/vendor1 \
  --shell /bin/csh --expire 2026-12-31 --groups dialout

# 禁用 + 首次必须改密
./ldapadmin.py user add intern --ou dv --disabled --must-change

# 密码含特殊字符用引号包裹（--password / --passwd / -p 等价）
./ldapadmin.py user add testuser --passwd 'P@ssw0rd!'
```

#### user mod — 修改用户

```
./ldapadmin.py user mod <uid> <action> [value]
```

| action | 说明 | 原理 |
|--------|------|------|
| `status` | 查看完整状态 | 显示 DN、UID/GID、密码状态、组成员 |
| `disable` | 禁用账号 | `shadowExpire = 1` |
| `enable` | 启用账号 | 删除 `shadowExpire` |
| `lock` | 锁定密码 | `shadowMax = 0` |
| `unlock` | 解锁密码 | `shadowMax = 90` |
| `pwd-expire` | 强制下次改密 | `shadowLastChange = 0` |
| `expire YYYY-MM-DD` | 设置过期日期 | `shadowExpire = 日期` |
| `shell <path>` | 修改 Shell | 如 `/bin/csh` |
| `home <path>` | 修改家目录 | 如 `/data/home/<uid>` |

#### user passwd — 改密码

强密码要求：8 位 + 大写 + 小写 + 数字 + 特殊字符 + 不含用户名。

```bash
./ldapadmin.py user passwd zhangsan
# 交互式输入新密码，不符合强度会拒绝
```

#### user search — 查询用户

输出字段对应的 LDAP 属性：

| 显示 | 属性 | 含义 |
|------|------|------|
| 账号过期 | `shadowExpire` | 账号绝对过期日，到期不可登录 |
| 上次改密 | `shadowLastChange` | 最后修改密码的日期 |
| 密码过期 | `shadowMax + LastChange` | 密码失效日，过期强制改密 |
| 过期宽限天数 | `shadowInactive` | 密码过期后额外宽限天数 |

#### user del — 删除用户

```bash
./ldapadmin.py user del zhangsan           # 基本删除
./ldapadmin.py user del zhangsan --force --remove-groups --backup-home
```

#### group — 组管理

```bash
./ldapadmin.py group add devteam
./ldapadmin.py group search devteam    # 查看组详情（GID/成员/描述）
./ldapadmin.py group del devteam
```

#### 批量导入

```bash
# CSV 格式: uid,password,ou,mail,shell,groups
./ldapadmin.py batch add users.csv
./ldapadmin.py batch del users.csv
```

#### automount — autofs 挂载管理

```bash
# 添加 NFS 挂载条目（--dry-run/-n 预演）
./ldapadmin.py automount add /share/reg_scratch/gtl \
  --target nfs01.example.com:/gtl --dry-run
./ldapadmin.py automount add /share/reg_scratch/gtl \
  --target nfs01.example.com:/gtl

# 自定义挂载选项
./ldapadmin.py automount add /share/project/new \
  --target lif01:/new --opts "vers=4,rw,noatime"

# 删除 / 列出
./ldapadmin.py automount del /share/reg_scratch/gtl
./ldapadmin.py automount list
```

### 6. 客户端查询工具（ldapquery.sh）

> 部署在客户端节点上，普通用户即可查询 LDAP 信息。

```bash
# 分发到客户端
scp ldap01:/opt/ldap-toolkit/client/ldapquery.sh /usr/local/bin/
chmod +x /usr/local/bin/ldapquery.sh

# 使用
ldapquery.sh self                  # 查当前用户
ldapquery.sh user zhangsan         # 查用户详情（DN/UID/Shell/邮箱/账号状态/密码过期）
ldapquery.sh group devteam         # 查组详情（含成员列表）
ldapquery.sh user-list             # 列出所有用户（用户名/UID/GID/状态/Shell/家目录/改密/过期）
ldapquery.sh group-list            # 列出所有组
```

> 依赖：仅需 openldap-clients（ldapsearch）。密码自动从 /etc/sssd/sssd.conf 或 /etc/nslcd.conf 读取。

## 自助密码修改平台

> 详细部署参考 `docs/SELFSERVICE-DEPLOY.md`

用户访问 `https://<server>/passwd/`，自行修改密码。强密码策略：8位+四类字符。

```bash
# 快速部署
mkdir -p /opt/ldap-selfservice
cp -r web/selfservice/* /opt/ldap-selfservice/
# Apache 配置见 docs/SELFSERVICE-DEPLOY.md
systemctl restart httpd24-httpd
```

## 目录结构

```
D:/workspace/ldap/
├── README.md                   # 本文件
├── config/
│   └── ldap.conf               # 统一配置文件
├── server/
│   ├── ldap.master             # 主节点安装脚本
│   ├── ldap.slave              # 从节点安装脚本
│   ├── eraseldap               # LDAP 清理/卸载
│   └── tls/
│       └── gen-certs.sh        # TLS 证书生成工具
├── ansible/                     # ★ Ansible 批量部署（推荐）
│   ├── deploy-ldap-client.yml   #   客户端 Playbook
│   ├── group_vars/all.yml       #   变量 + 密码
│   ├── files/ca.crt             #   CA 证书
│   └── README-ETC-ANSIBLE.md    #   部署文档
├── client/
│   ├── ldap.client              # 单机 Shell 部署（备选）
│   └── ldapquery.sh             # 客户端查询工具（普通用户可用）
├── admin/
│   └── ldapadmin.py            # 统一管理工具: user/group/batch/automount
├── batch/
│   ├── addjaguar.sh            # 批量用户导入
│   └── deljaguar.sh            # 批量用户删除
├── web/
│   └── selfservice/            # 自助密码修改门户
│       ├── index.php
│       ├── change.php
│       ├── config.inc.php
│       ├── functions.inc.php
│       ├── style.css
│       └── logout.php
└── docs/
    └── TLS-SETUP.md            # TLS 部署指南
```

## 安全

- ✅ 无硬编码密码 — 通过环境变量或交互式提示
- ✅ 所有 LDAP 操作使用 TLS/SSL（LDAPS 端口 636 + StartTLS）
- ✅ 客户端强制验证 CA 证书
- ✅ 密码强度校验（最小长度、大小写、数字要求）
- ✅ 自助门户：CSRF 防护、频率限制、Session 超时
- ✅ 日志中不含密码 — 操作记录中不含凭据
- ✅ ShadowAccount 账号生命周期管理
- ✅ 严格 ACL：只读账号 + 匿名仅认证

## RHEL/CentOS 兼容性

| 特性 | RHEL/CentOS 7 | RHEL 8/9 |
|------|--------------|----------|
| 认证配置 | `authconfig`（已弃用） | `authselect` |
| SSSD | 支持 | 支持 |
| Python 3 | EPEL 安装 | 系统自带 |
| OpenLDAP | 2.4.x | 2.4.x / 2.5+ |
| 数据库后端 | hdb | mdb（推荐） |
| TLS 最低版本 | TLS 1.2 | TLS 1.2+ |

脚本内置 `detect_os()` 函数，会自动适配行为。

## 故障排查

| 问题 | 检查方法 |
|------|---------|
| LDAP 连接被拒绝 | `systemctl status slapd`，检查防火墙端口 389/636 |
| TLS 握手失败 | 证书权限（`ldap:ldap`，key=0400），客户端 CA 证书 |
| 用户登录被拒 | 账号是否禁用？`python3 ldapadmin.py user mod <uid> status` |
| 复制延迟 | 检查 `olcSyncRepl` 配置、网络、节点间防火墙 |
| 自助服务无法连接 | PHP LDAP 模块已加载？`php -m \| grep ldap` |
| 密码修改失败 | TLS 是否开启？检查配置中的 `ldaps://` |
| SSSD 无法启动 | `sssctl domain-status LDAP`，`journalctl -u sssd` 查看详细日志 |
