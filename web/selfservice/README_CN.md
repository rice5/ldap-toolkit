# LDAP 自助密码修改平台

## 访问地址

- ldap01: `https://ldap01.example.com/passwd/`
- ldap02: `https://ldap02.example.com/passwd/`

## 使用说明

1. 打开上述网址，输入**用户名**和**当前密码**，点击 Sign In
2. 输入**新密码**和**确认密码**，点击 Change Password
3. 看到 "Password changed successfully" 即修改成功

## 密码要求

| 要求 | 说明 |
|------|------|
| 最少 8 个字符 | `PASSWORD_MIN_LENGTH=8` |
| 大写字母 | 至少 1 个 A-Z |
| 小写字母 | 至少 1 个 a-z |
| 数字 | 至少 1 个 0-9 |
| 特殊字符 | 至少 1 个 !@#$% 等 |
| 不含用户名 | 密码中不能出现用户名 |
| 不与旧密码相同 | 新旧密码必须不同 |

## 密码过期策略

- 密码有效期 90 天（`shadowMax`）
- 到期前 7 天警告（`shadowWarning`）
- 到期后 30 天宽限期（`shadowInactive`）
- 超宽限期账号锁定，需管理员解锁

## 常见问题

**Q: 提示 "Invalid username or password"？**
A: 确认用户名和当前密码正确。连续 5 次失败将被锁定 15 分钟。

**Q: 提示 "Cannot connect to authentication server"？**
A: 服务器暂时不可用，稍后重试。

**Q: 忘记当前密码怎么办？**
A: 联系 IT 管理员通过 `ldapadmin.py user passwd <用户名>` 重置。

## 管理员信息

- 环境：CentOS 7 + httpd24 + PHP 7.0 (SCL)
- 路径：`/opt/ldap-selfservice/`
- 部署文档：`docs/SELFSERVICE-DEPLOY.md`
- 日志：`/var/log/ldap-selfservice.log`
- 密码策略配置：`config.inc.php`（`PASSWORD_REQUIRE_*` 常量）
