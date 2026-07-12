# LDAP 自助密码修改平台 — 部署文档

## Architecture

```
用户 → nginx (SSL) → ldap01:80/passwd/
                    → ldap02:80/passwd/
```

- 两台 LDAP 服务器均部署 Apache + PHP 自助平台
- 前置 nginx 做 SSL 终止和负载均衡
- PHP 通过 ldaps:// 连接本地 LDAP

## 1. 安装 httpd24 + PHP 7 (CentOS SCL)

CentOS 7 系统自带 PHP 5.4 不支持 `ldap_exop_passwd`、`random_bytes` 等函数，需通过 SCL 安装 PHP 7。

```bash
# 安装 SCL 仓库和所需包
yum install -y centos-release-scl
yum install -y httpd24 rh-php70 rh-php70-php rh-php70-php-ldap \
    rh-php70-php-cli rh-php70-php-common rh-php70-php-xml rh-php70-php-gd
```

## 2. 停止系统 httpd，启用 httpd24

```bash
systemctl stop httpd
systemctl disable httpd
```

httpd24 使用 `apachectl` 手动管理，或通过以下 systemd 方式：
```bash
# 创建 systemd 服务（可选）
cat > /etc/systemd/system/httpd24.service << 'EOF'
[Unit]
Description=Apache HTTP Server 2.4 (SCL)
After=network.target
[Service]
Type=forking
EnvironmentFile=/opt/rh/httpd24/service-environment
ExecStart=/usr/bin/scl enable httpd24 rh-php70 -- /opt/rh/httpd24/root/usr/sbin/apachectl start
ExecStop=/usr/bin/scl enable httpd24 -- /opt/rh/httpd24/root/usr/sbin/apachectl stop
ExecReload=/usr/bin/scl enable httpd24 -- /opt/rh/httpd24/root/usr/sbin/apachectl graceful
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable httpd24
systemctl start httpd24
```

## 3. 部署 ldap-selfservice

```bash
# 创建目录并上传文件
mkdir -p /opt/ldap-selfservice
cp /opt/ldap-toolkit/web/selfservice/* /opt/ldap-selfservice/

# 确认 config.local.php 配置正确
cat > /opt/ldap-selfservice/config.local.php << 'EOF'
<?php
// 从文件读取 LDAP 管理员密码
$pwfile = "/etc/openldap/certs/.ro_token_file";
if (file_exists($pwfile)) {
    define("LDAP_ROOTPW", trim(file_get_contents($pwfile)));
}
define("LDAP_HOST", "ldap01.example.com");  # 或 ldap02
define("LDAP_PORT", 636);
define("LDAP_BASE_DN", "dc=example,dc=com");
define("LDAP_USE_TLS", true);
define("LDAP_TLS_CACERT", "/etc/openldap/certs/ca.crt");
define("LDAP_TLS_REQCERT", "demand");
define("LOG_FILE", "/var/log/ldap-selfservice.log");
EOF
```

## 4. 配置密码文件（安全方式）

```bash
# 复制密码文件到 apache 可读位置（ldap 组）
cp /root/ldap/.ldap_passfile /etc/openldap/certs/.ro_token_file
chown root:ldap /etc/openldap/certs/.ro_token_file
chmod 440 /etc/openldap/certs/.ro_token_file
```

## 5. 权限设置

```bash
usermod -a -G ldap apache
setsebool -P httpd_can_network_connect on

chown -R root:apache /opt/ldap-selfservice
chmod 750 /opt/ldap-selfservice
chmod 640 /opt/ldap-selfservice/*.php

touch /var/log/ldap-selfservice.log
chown apache:apache /var/log/ldap-selfservice.log
chmod 640 /var/log/ldap-selfservice.log
```

## 6. Apache 配置

创建 `/opt/rh/httpd24/root/etc/httpd/conf.d/selfservice.conf`：

```apache
# LDAP 自助密码修改平台（SSL 由前置 nginx 处理）
Alias /passwd /opt/ldap-selfservice
<Directory /opt/ldap-selfservice>
    Require all granted
    Options -Indexes
    DirectoryIndex index.php
</Directory>
```

## 7. 部署 phpLDAPadmin（可选）

> 详细配置（多 server 选择、IP 限制、故障排查）见 [PHPLDAPADMIN-DEPLOY.md](./PHPLDAPADMIN-DEPLOY.md)

```bash
yum install -y phpldapadmin
```

### Apache 配置（最小版）

```apache
Alias /phpldapadmin /usr/share/phpldapadmin/htdocs
Alias /ldapadmin /usr/share/phpldapadmin/htdocs
<Directory /usr/share/phpldapadmin/htdocs>
    Require all granted
    Options -Indexes
</Directory>
```

### 关键：多 Server 选择

编辑 `/etc/phpldapadmin/config.php`，确保至少配置两台 LDAP server（参见 [PHPLDAPADMIN-DEPLOY.md](./PHPLDAPADMIN-DEPLOY.md) 第 2 节），否则登录页面不会出现 Server Select 下拉框。

## 8. 验证

```bash
source /opt/rh/httpd24/enable
/opt/rh/httpd24/root/usr/sbin/apachectl configtest
/opt/rh/httpd24/root/usr/sbin/apachectl restart

# 测试
curl -s -o /dev/null -w "%{http_code}" http://localhost/passwd/   # 应返回 200
```

## 9. Nginx 反向代理（统一入口）

```nginx
upstream ldap_passwd {
    server ldap01.example.com:80 weight=1 max_fails=2 fail_timeout=30s;
    server ldap02.example.com:80 weight=1 max_fails=2 fail_timeout=30s;
}

server {
    listen 443 ssl;
    server_name passwd.example.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    location /passwd/ {
        proxy_pass http://ldap_passwd;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80;
    server_name passwd.example.com;
    return 301 https://$host$request_uri;
}
```

## 10. 故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| 500 错误 | PHP 语法错误 | `php -l /opt/ldap-selfservice/*.php` 检查 |
| "Cannot connect" | apache 无法连 LDAPS | `usermod -a -G ldap apache` + `setsebool` |
| "Invalid form submission" | Session cookie 问题 | 非 HTTPS 时禁用 `cookie_secure` |
| PROOTPW=EMPTY | 密码文件读不到 | 检查 `/etc/openldap/certs/.ro_token_file` 权限 |
