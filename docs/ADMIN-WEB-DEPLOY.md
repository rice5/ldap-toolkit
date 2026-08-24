# LDAP 管理员 Web 管理站点 — 部署文档

面向管理员的 Web 管理站点，图形化管理 LDAP 用户 / 组（重点）、批量操作、automount、sudo 策略。
功能参考 `admin/ldapadmin.py`，提供 Web 界面。

## 架构

```
管理员浏览器 → nginx(443) → 本服务(127.0.0.1:8080)
                              ├─ 独立管理员账号登录（与 LDAP 账号分离）
                              ├─ Manager 凭据仅存服务端（600 权限 env 文件），绝不暴露给前端
                              └─ LDAP 操作走系统 ldapsearch/ldapmodify/ldapadd/ldapdelete
```

- **零第三方依赖**：Python3 标准库 `http.server` + 系统 OpenLDAP 客户端命令。
- 与 `password_expiry_notify.py` / `pwd_change_audit_sync.py` 技术风格一致。
- 可运行于 Python 3.6+（CentOS 7）与 Python 3.12。

## 文件

| 文件 | 用途 |
|------|------|
| `admin/ldap_admin_web.py` | 后端（HTTP 服务 + 认证 + LDAP CRUD 逻辑） |
| `admin/web/index.html` | 前端单页应用（内嵌 CSS/JS） |
| `config/ldap_admin_web.env.example` | 配置模板（占位符，可提交） |
| `config/ldap_admin_web.env` | 实际配置（含 Manager 密码，600 权限，gitignore） |

## 部署步骤（以 ldap01 为例，域名/密码均为占位符，部署时替换）

### 1. 上传文件

```bash
mkdir -p /opt/ldap-admin-web
scp admin/ldap_admin_web.py root@<server>:/opt/ldap-admin-web/
scp -r admin/web root@<server>:/opt/ldap-admin-web/
```

### 2. 创建配置

```bash
cat > /opt/ldap-admin-web/ldap_admin_web.env << 'EOF'
WEB_LISTEN=127.0.0.1
WEB_PORT=8080
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<强密码>
SESSION_TIMEOUT=28800
LDAP_HOST=<ldap-server-fqdn>
LDAP_PORT=636
LDAP_SUFFIX=dc=example,dc=com
LDAP_MANAGER_DN=cn=Manager,dc=example,dc=com
LDAP_MANAGER_PW=<Manager密码>
LDAP_TLS_CACERT=/etc/openldap/certs/ca.crt
LDAP_USER_BASE=ou=People,dc=example,dc=com
LDAP_GROUP_BASE=ou=Group,dc=example,dc=com
LDAP_SUDO_BASE=ou=sudoers,dc=example,dc=com
LDAP_AUTOMOUNT_BASE=nisMapName=auto.nfs,ou=automapper,dc=example,dc=com
DEFAULT_SHELL=/bin/csh
DEFAULT_HOME_BASE=/share/home
MAIL_DOMAIN=example.com
UID_MIN=5000
SHADOW_MAX_DAYS=90
SHADOW_WARN_DAYS=7
SHADOW_INACTIVE=30
EOF
chmod 600 /opt/ldap-admin-web/ldap_admin_web.env
```

> **Manager 密码更安全的做法**：不写在 env 里，改为启动时从密码文件
> （如 `/root/ldap/.passwdfile_manager`）读取。

### 3. 创建 systemd 服务

```bash
cat > /etc/systemd/system/ldap-admin-web.service << 'EOF'
[Unit]
Description=LDAP Admin Web
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ldap-admin-web
ExecStart=/usr/bin/python3 /opt/ldap-admin-web/ldap_admin_web.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ldap-admin-web
systemctl status ldap-admin-web
```

### 4. 反向代理（统一入口 + TLS）

> **生产拓扑**：ldap01 / ldap02 只装了 httpd（httpd24 + rh-php70 SCL），**没有 nginx**。
> 对外访问统一经 **yum01 服务器的 1Panel** 反代（与 self-service 门户相同方式），
> 做负载均衡/入口收敛。本节给出两种方式，生产用 1Panel 即可。

#### 方式 A：yum01 的 1Panel 反代（生产实际用法）

在 yum01 的 1Panel「网站」里创建站点 `ldapadmin.example.com`，反向代理目标指向
ldap01（和 ldap02，做负载均衡）的 `127.0.0.1:8080`：

```
# 1Panel 反代目标（upstream）
ldap01:8080   (weight=1)
ldap02:8080   (weight=1, 若两节点都部署了本服务)
```

1Panel 会自动生成 nginx 配置并配好 TLS 证书。等价的手写 nginx 配置如下：

```nginx
upstream ldapadmin {
    server ldap01.example.com:8080 weight=1 max_fails=2 fail_timeout=30s;
    server ldap02.example.com:8080 weight=1 max_fails=2 fail_timeout=30s;
}

server {
    listen 443 ssl;
    server_name ldapadmin.example.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # 强烈建议：限制管理网段访问
    # allow 192.0.2.0/24;
    # deny all;

    location / {
        proxy_pass http://ldapadmin;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> 管理站点务必限制访问来源（1Panel 里配 IP 白名单，或加一层 Basic Auth 双保险），
> 因为它持有 LDAP Manager 写权限。

#### 方式 B：ldap01 本机 httpd 反代（若需单机直连）

ldap01 若需本机 httpd 反代（httpd24 已装，非 nginx），用 mod_proxy：

```apache
# /opt/rh/httpd24/root/etc/httpd/conf.d/ldapadmin.conf
<VirtualHost *:80>
    ServerName ldapadmin.example.com
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

### 5. 验证

```bash
# 健康检查
curl -s http://127.0.0.1:8080/api/health   # {"status": "ok"}

# 登录
curl -s -X POST http://127.0.0.1:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<密码>"}'
```

浏览器访问 `https://ldapadmin.example.com/`，用配置的管理员账号登录。

## 功能清单

### Phase 1（user / group，重点）

| 模块 | 功能 |
|------|------|
| 用户管理 | 列表（搜索/按 OU 过滤）、创建（自动分配 UID/GID、自动建主组/OU、密码强度校验）、编辑（shell/home/邮箱/电话）、启用/禁用、锁定/解锁、强制改密、同步改密日期、重置密码、删除（含清理空主组）、详情（含组成员/密码过期日） |
| 组管理 | 列表（搜索）、创建、删除、详情、成员管理（添加/移除 memberUid） |

### Phase 2（batch / automount / sudo）

| 模块 | 功能 |
|------|------|
| 批量操作 | 批量创建用户（CSV: `uid,group[,shell[,password[,home[,groups]]]]`）、批量删除用户（每行一个 uid），逐行返回结果 |
| Automount | NFS 挂载条目列表、添加、删除（nisObject，`nisMapName=auto.nfs`） |
| Sudo 策略 | sudoRole 规则列表、详情、添加、删除（sudoUser/sudoHost/sudoCommand/sudoOption/sudoRunAsUser/sudoRunAsGroup/sudoOrder/description） |

## 安全设计

1. **独立管理员账号**：web 登录账号与 LDAP 账号分离，Manager 密码不经过前端。
2. **Manager 密码隔离**：仅存服务端 600 权限 env 文件；LDAP 操作经 `-y` 密码文件，密码不出现在进程命令行。
3. **会话管理**：登录返回随机 token，服务端内存存储，超时失效；`Cache-Control: no-store`。
4. **LDAP 过滤器转义**：所有用户输入经 `ldap_filter_escape` 转义，防 LDAP 注入。
5. **密码强度校验**：与 `ldapadmin.py` 相同的三层校验（长度/复杂度/不含用户名）。

## 已知行为（与 ldapadmin.py 对齐）

- UID/GID 恒等（`gid == uid`），扫描 uidNumber+gidNumber 取 max+1。
- 用户 DN 用 `cn=<uid>`（RDN 是 cn 非 uid）。
- 删除用户时自动清理同名空主组（user private group）。
- `shadowLastChange` 是 UTC 天数，时区处理正确。
- 密码存储为 SSHA 哈希（非明文）。
