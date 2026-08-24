# LDAP 审计日志（auditlog overlay）部署方案

## 目的

追踪 LDAP 所有写操作（尤其 `userPassword` 修改），配合
`admin/pwd_change_audit_sync.py` 自动对齐 `shadowLastChange`，解决
phpldapadmin / SSH passwd 改密不回写 `shadowLastChange` 导致密码过期日算错的问题。

## 为什么选 auditlog 而非 accesslog

| 方案 | 机制 | 空间 | 复杂度 |
|------|------|------|--------|
| **auditlog**（选用） | 所有写操作以 LDIF 追加到文件 | 小（估算见下） | 低：加载模块 + 一个 overlay |
| accesslog | 写操作存到独立 logdb 数据库，可结构化查询 | 中 | 高：需建 logdb + syncprov + logpurge |

审计诉求只需"追踪谁改了密码"，auditlog 文件方式足够，解析简单。

## 空间评估

- 每条写操作记录约 300~800 字节（LDIF 文本）。
- 按每天 100 条写操作估算：约 80 KB/天 ≈ 29 MB/年。
- logrotate 保留 90 天（压缩后）≈ 几 MB，对现有 36 GB 可用空间可忽略。

## 配置（LDIF）

### 第 1 步：加载 auditlog 模块

```ldif
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: {2}auditlog
```

### 第 2 步：添加 auditlog overlay

```ldif
dn: olcOverlay={2}auditlog,olcDatabase={2}hdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcAuditlogConfig
olcOverlay: {2}auditlog
olcAuditlogFile: /var/log/ldap/audit.log
```

> 说明：`{2}` 是 overlay 索引号，需与本库现有 overlay（`{0}syncprov`、
> `{1}ppolicy`）不冲突。若生产库的 overlay 索引不同，按实际调整。

### 第 3 步：logrotate（防止日志无限增长）

```
/var/log/ldap/audit.log {
    daily
    rotate 90
    compress
    copytruncate
    missingok
    notifempty
}
```

> 用 `copytruncate` 而非默认 rename，避免 slapd 持有文件句柄导致轮转后
> 仍写旧 inode。

## 执行步骤（多主镜像，两节点错开，禁止同时操作）

1. 在 ldap01：`ldapmodify` 应用第 1 步（加载模块）。
2. **重启 ldap01 的 slapd**（模块在启动时加载）：
   `systemctl restart slapd`，确认起来后 `systemctl status slapd` 无报错。
3. 在 ldap01：`ldapmodify` 应用第 2 步（加 overlay，模块已加载，动态生效，无需再重启）。
4. 验证：执行一次任意写操作（如改某测试条目描述），确认 `/var/log/ldap/audit.log` 有 LDIF 记录。
5. 配置第 3 步 logrotate（两节点）。
6. 在 ldap02 重复 1~4 步（ldap01 全程保持在线）。

## 回滚

- 删 overlay：`ldapmodify` 删除 `olcOverlay={2}auditlog,...` 条目。
- 移除模块：`ldapmodify` 从 `cn=module{0}` 删除 `olcModuleLoad: {2}auditlog`。
- 重启 slapd 生效。审计日志文件可保留或删除。

## 风险提示

- 重启 slapd 期间该节点 LDAP 短暂不可用（秒级），认证会由另一节点接管；
  必须**错开**重启，绝不两台同时停。
- 若模块加载失败，slapd 可能启动异常——因此采用"先加载模块并重启验证、
  再动态加 overlay"的顺序，把风险拆开。
- auditlog 记录的 `userPassword` 是哈希值（非明文），不会额外泄露明文密码；
  但审计日志含用户 DN 等目录信息，文件权限应设为 `root:ldap 640`。

## 配合脚本

- `admin/pwd_change_audit_sync.py`：解析 audit.log，找「改过 userPassword 但
  shadowLastChange 未同步」的用户，`--dry-run` 报告 / `--apply` 自动对齐。
- 已部署到 ldap01 + ldap02 的 `/opt/ldap-toolkit/admin/pwd_change_audit_sync.py`。
- 通过 hermes cron `ldap-pwd-audit-sync` 每天跑两次（08:00 + 16:00，no_agent）：
  wrapper `~/.hermes/scripts/ldap-pwd-audit-sync.sh` SSH 到两节点各自执行。
- **Python 3.6 兼容**（CentOS 7）：脚本的 subprocess 调用必须用
  `stdout=PIPE, stderr=PIPE, universal_newlines=True`，不能用 `capture_output=True` / `text=True`（3.7+）。
- Manager 凭据从本地密码文件（600 权限）读取，经环境变量 `LDAP_MANAGER_PW` 注入。

## 运维查看审计日志

```bash
# 实时跟踪
tail -f /var/log/ldap/audit.log
# 查某用户的写操作
grep -n "cn=<uid>" /var/log/ldap/audit.log
# 只看密码修改（replace/add/delete userPassword）
grep -E "^(replace|add|delete): userPassword" /var/log/ldap/audit.log
# 轮转后的压缩文件
zcat /var/log/ldap/audit.log-*.gz | grep userPassword
```

记录头 `# modify <unix秒> ...` 的时间戳可用 `date -d @<秒> +%F\ %T` 换算。
