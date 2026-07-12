# phpLDAPadmin 部署文档

## 概述

phpLDAPadmin 是基于 Web 的 LDAP 管理工具。在两台 LDAP 服务器上均部署，支持多 server 切换。

## 1. 安装

```bash
yum install -y phpldapadmin
```

## 2. 配置 LDAP Server（多 server 选择）

编辑 `/etc/phpldapadmin/config.php`，在 `$servers = new Datastore();` 下方配置两台 server（使用 ldaps:// URI，端口包含在 URI 中）：

```php
$servers = new Datastore();

/* ===== Server 1: ldap01 ===== */
$servers->newServer('ldap_pla');
$servers->setValue('server','name','ldap01.example.com');
$servers->setValue('server','host','ldaps://ldap01.example.com:636/');
// $servers->setValue('server','port',389); // 端口已在 host URI 中指定
$servers->setValue('server','base',array('dc=example,dc=com'));
$servers->setValue('login','auth_type','cookie');
$servers->setValue('login','bind_id','cn=Manager,dc=example,dc=com');
//$servers->setValue('login','bind_pass','');
$servers->setValue('server','tls',false);

/* ===== Server 2: ldap02 ===== */
$servers->newServer('ldap_pla');
$servers->setValue('server','name','ldap02.example.com');
$servers->setValue('server','host','ldaps://ldap02.example.com:636/');
$servers->setValue('server','base',array('dc=example,dc=com'));
$servers->setValue('login','auth_type','cookie');
$servers->setValue('login','bind_id','cn=Manager,dc=example,dc=com');
//$servers->setValue('login','bind_pass','');
$servers->setValue('server','tls',false);
```

> **说明**：`host` 使用 `ldaps://` URI 时端口已包含在内，`port` 设置不再生效，应注释掉。

### 关键配置项说明

| 配置项 | 值 | 说明 |
|--------|-----|------|
| `server','name'` | `ldap01.example.com` | 登录页面下拉框显示名称 |
| `server','host'` | `ldaps://ldap01.example.com:636/` | LDAPS URI（端口包含在 URI 中，无需单独设置 port） |
| `server','port'` | （注释掉） | URI 中已指定端口，此行无效 |
| `server','base'` | `array('dc=example,dc=com')` | Base DN |
| `login','auth_type'` | `cookie` | 通过 Web 表单登录 |
| `login','bind_id'` | `cn=Manager,...` | 默认绑定 DN（密码页面留空，用户自行输入） |
| `server','tls'` | `false` | 使用 ldaps:// 无需 StartTLS |

### 其他推荐配置

```php
// 登录属性：使用 uid 而非 dn
$servers->setValue('login','attr','uid');

// 自动编号（新建用户时自动分配 uidNumber/gidNumber）
$servers->setValue('auto_number','enable',true);
$servers->setValue('auto_number','min',array('uidNumber'=>5000,'gidNumber'=>5000));

// 唯一性检查
$servers->setValue('unique','attrs',array('mail','uid','uidNumber'));

// 密码哈希（留空使用 LDAP 默认，即 SSHA）
$servers->setValue('appearance','pla_password_hash','');
```

## 3. Apache httpd24 配置

创建 `/opt/rh/httpd24/root/etc/httpd/conf.d/phpldapadmin.conf`：

### 内网开放版（推荐用于内网环境）

```apache
#
# phpLDAPadmin — Web-based LDAP administration
#

Alias /phpldapadmin /usr/share/phpldapadmin/htdocs
Alias /ldapadmin /usr/share/phpldapadmin/htdocs

<Directory /usr/share/phpldapadmin/htdocs>
    Require all granted
    Options -Indexes
</Directory>
```

### IP 限制版（仅允许特定网段）

```apache
Alias /phpldapadmin /usr/share/phpldapadmin/htdocs
Alias /ldapadmin /usr/share/phpldapadmin/htdocs

<Directory /usr/share/phpldapadmin/htdocs>
  <IfModule mod_authz_core.c>
    # Apache 2.4
    Require ip 127.0.0.1 ::1 10.1.10.0/24
  </IfModule>
  <IfModule !mod_authz_core.c>
    # Apache 2.2
    Order Deny,Allow
    Deny from all
    Allow from 127.0.0.1 ::1 10.1.10.0/24
  </IfModule>
</Directory>
```

## 4. SELinux 和权限

```bash
# 允许 Apache 连接 LDAP
setsebool -P httpd_can_network_connect on

# 如果使用 ldaps://，还需要允许连接 LDAPS 端口
setsebool -P httpd_can_connect_ldap on
```

## 5. 重启 httpd24

```bash
# SCL 方式
source /opt/rh/httpd24/enable
/opt/rh/httpd24/root/usr/sbin/apachectl configtest
/opt/rh/httpd24/root/usr/sbin/apachectl restart

# 或 systemd 方式（若已配置 httpd24.service）
systemctl restart httpd24
```

## 6. 访问验证

```bash
# 检查 http 状态码
curl -s -o /dev/null -w "%{http_code}" http://localhost/phpldapadmin/   # 应返回 200
curl -s -o /dev/null -w "%{http_code}" http://localhost/ldapadmin/       # 应返回 200
```

浏览器访问：
- ldap01: `http://ldap01.example.com/phpldapadmin/`
- ldap02: `http://ldap02.example.com/phpldapadmin/`

登录页面会显示 **Server Select** 下拉框，可选择：
- `ldap01.example.com`
- `ldap02.example.com`

输入 `cn=Manager,dc=example,dc=com` 和密码即可登录管理。

## 7. 配置备份与恢复

```bash
# 备份
cp /etc/phpldapadmin/config.php /etc/phpldapadmin/config.php.bak.$(date +%Y%m%d)

# 恢复
cp /etc/phpldapadmin/config.php.bak.YYYYMMDD /etc/phpldapadmin/config.php
systemctl restart httpd24   # 或 apachectl restart
```

## 8. 故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| 页面 404 | Apache Alias 未配置 | 检查 `/opt/rh/httpd24/root/etc/httpd/conf.d/phpldapadmin.conf` |
| 页面 403 | IP 限制 | 检查 Require ip 配置，确认客户端 IP 在白名单内 |
| 无 Server Select 下拉框 | config.php 只配了一个 server | 确保有两个 `$servers->newServer('ldap_pla')` 块 |
| "Can't contact LDAP server" | 网络不通或端口错误 | `ldapsearch -H ldap://192.168.1.12 -x -b "" -s base` 测试 |
| 登录失败 "Invalid credentials" | 密码错误或 bind_id 不对 | 确认 Manager DN 和密码 |
| 登录后无法搜索 | 匿名搜索被 ACL 禁止 | config.php 中设置 `login','bind_id'` 或 `anon_bind` |
