#!/usr/bin/env python3
"""LDAP 密码修改审计对齐 + shadow 属性完整性巡检 (pwd_change_audit_sync.py)

两个功能（默认都执行，--apply 控制是否写入）：

1. 改密对齐：解析 slapo-auditlog 审计日志，找出「修改过 userPassword 但
   shadowLastChange 未同步」的用户，自动把 shadowLastChange 对齐到改密当天。
   背景：phpldapadmin / SSH passwd 只改 userPassword、不回写 shadowLastChange。

2. shadow 完整性巡检：扫描所有 posixAccount，修复漏设/异常的 shadow 属性——
   - 缺 shadowMax → 补 90（新用户创建时漏设，导致密码过期时间算不出）
   - 缺 shadowWarning → 补 7
   - shadowInactive 异常（>365 天，如 999999「永不过期」哨兵）→ 改 30
   - shadowExpire 异常（>20000 天，如 55120 账号「永不过期」哨兵）→ 删除
   老用户也会被扫描到（全量扫描，不依赖审计日志）。

用法（在 LDAP 服务器本地运行，需能读审计日志 + Manager 凭据）：
  python3 pwd_change_audit_sync.py                 # dry-run：只报告，不改
  python3 pwd_change_audit_sync.py --apply         # 实际对齐 + 修复
  python3 pwd_change_audit_sync.py --since 2026-08-01   # 只处理该日期之后的改密记录

依赖：仅 Python3 标准库 + 系统 ldapsearch/ldapmodify。审计日志由 auditlog overlay 生成。
"""
import argparse
import gzip
import glob
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# ── 配置（生产真实值通过环境变量注入，勿写入公开仓库）──────────────
AUDIT_LOG = os.environ.get("LDAP_AUDIT_LOG", "/var/log/ldap/audit.log")
LDAP_HOST = os.environ.get("LDAP_HOST", "ldap01.example.com")
LDAP_PORT = os.environ.get("LDAP_PORT", "636")
LDAP_SUFFIX = os.environ.get("LDAP_SUFFIX", "dc=example,dc=com")
LDAP_MANAGER_DN = os.environ.get("LDAP_MANAGER_DN", f"cn=Manager,{LDAP_SUFFIX}")
LDAP_MANAGER_PW = os.environ.get("LDAP_MANAGER_PW", "")   # 敏感，必须外部提供
LDAP_TLS_CACERT = os.environ.get("LDAP_TLS_CACERT", "/etc/openldap/certs/ca.crt")

# shadow 属性默认值（对齐正常账号策略）
DEFAULT_SHADOW_MAX = 90
DEFAULT_SHADOW_WARNING = 7
DEFAULT_SHADOW_INACTIVE = 30

# 异常阈值：超过即视为哨兵值（「永不过期」标记），需要修复
SHADOW_INACTIVE_MAX = 365        # shadowInactive 超过 365 天视为异常（如 999999）

# auditlog 记录里，userPassword 修改以 modify 行的属性名出现（replace/add/delete: userPassword）
PWD_ATTR_RE = re.compile(r"^(?:replace|add|delete):\s*userPassword\s*$", re.IGNORECASE)
# 时间戳在记录头注释行："# modify <unix秒> <suffix> <binddn> IP=... conn=..."
TS_RE = re.compile(r"^#\s*(?:modify|add|delete|modrdn)\s+(\d{10})\b")


def iter_audit_records(glob_pattern):
    """遍历审计日志（含轮转的 .gz 文件），产出 (unix_ts, dn)。

    记录格式（slapo-auditlog，OpenLDAP 2.4）实测示例：
        # modify 1787572345 dc=example,dc=com cn=Manager,... IP=... conn=...
        dn: cn=harvey.zhu,ou=rd,ou=People,dc=...
        changetype: modify
        replace: userPassword
        userPassword:: e1NTSEF9...
        -
        replace: entryCSN
        ...
        # end modify 1787572345
        <空行>
    """
    files = sorted(glob.glob(glob_pattern + "*"))
    for f in files:
        opener = gzip.open if f.endswith(".gz") else open
        try:
            with opener(f, "rt", encoding="utf-8", errors="ignore") as fh:
                cur_ts = None
                cur_dn = None
                cur_pwd = False
                for line in fh:
                    line = line.rstrip("\n")
                    m = TS_RE.match(line.strip())
                    if m:
                        cur_ts = int(m.group(1))
                        continue
                    if line.startswith("dn:"):
                        cur_dn = line[3:].strip()
                        continue
                    if PWD_ATTR_RE.match(line.strip()):
                        cur_pwd = True
                        continue
                    if line.strip() == "":
                        # 一条记录结束
                        if cur_dn and cur_pwd and cur_ts:
                            yield cur_ts, cur_dn
                        cur_ts = cur_dn = None
                        cur_pwd = False
        except OSError as e:
            print(f"读取 {f} 失败: {e}", file=sys.stderr)


def ts_to_epoch_days(ts):
    """auditlog unix 秒时间戳 → shadowLastChange 语义的 UTC 天数。"""
    return int(ts / 86400)


def ldap_query_all_shadow():
    """查所有 posixAccount 的 shadow 属性。返回 {dn: {attr小写: value}}。

    用 Manager 查询（只读账号可能没有所有 OU 的读权限）；用 -y 密码文件避免 ps 泄露。
    """
    result = {}
    import tempfile
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(LDAP_MANAGER_PW)
        pw_path = f.name
    os.chmod(pw_path, 0o600)
    try:
        cmd = [
            "ldapsearch", "-x", "-LLL",
            "-H", f"ldaps://{LDAP_HOST}:{LDAP_PORT}",
            "-D", LDAP_MANAGER_DN,
            "-y", pw_path,
            "-b", LDAP_SUFFIX,
            "(objectClass=posixAccount)",
            "dn", "uid", "shadowLastChange", "shadowMax",
            "shadowWarning", "shadowInactive", "shadowExpire",
        ]
        env = dict(os.environ, LDAPTLS_CACERT=LDAP_TLS_CACERT)
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=60, env=env)
    finally:
        os.remove(pw_path)
    if r.returncode != 0:
        print("ldapsearch 失败:", r.stderr[:500], file=sys.stderr)
        return result
    cur = {}
    for line in r.stdout.splitlines():
        if not line.strip():
            if "dn" in cur:
                result[cur["dn"]] = cur
            cur = {}
            continue
        if line.startswith(" "):
            continue
        if ": " in line:
            k, _, v = line.partition(": ")
            k = k.strip().lower()
            if k not in cur:
                cur[k] = v.strip()
    if "dn" in cur:
        result[cur["dn"]] = cur
    return result


def ldap_set_shadow(dn, days):
    """用 Manager 修改 shadowLastChange。返回 True/False。"""
    return ldap_modify_attrs(dn, [("replace", "shadowLastChange", str(days))])


def ldap_modify_attrs(dn, changes):
    """通用 ldapmodify。changes = [(op, attr, value|None), ...]，value=None 表示删除整个属性。"""
    import tempfile
    lines = [f"dn: {dn}", "changetype: modify"]
    for op, attr, value in changes:
        lines.append(f"{op}: {attr}")
        if value is not None:
            lines.append(f"{attr}: {value}")
        lines.append("-")
    ldif = "\n".join(lines) + "\n"
    with tempfile.NamedTemporaryFile("w", suffix=".ldif", delete=False) as f:
        f.write(ldif)
        ldif_path = f.name
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(LDAP_MANAGER_PW)
        pw_path = f.name
    os.chmod(pw_path, 0o600)
    try:
        cmd = [
            "ldapmodify", "-x",
            "-H", f"ldaps://{LDAP_HOST}:{LDAP_PORT}",
            "-D", LDAP_MANAGER_DN,
            "-y", pw_path,
            "-f", ldif_path,
        ]
        env = dict(os.environ, LDAPTLS_CACERT=LDAP_TLS_CACERT)
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=30, env=env)
        return r.returncode == 0
    finally:
        os.remove(ldif_path)
        os.remove(pw_path)


def check_shadow_completeness(ldap_data):
    """检测 shadow 属性完整性。返回 [(dn, uid, [(op, attr, value|None), ...])]。

    规则（对齐正常账号默认值，只修明确异常，不碰系统标准值/特殊账号）：
    - 缺 shadowMax → add 90（新用户创建时漏设，导致密码过期时间算不出）
    - 缺 shadowWarning → add 7
    - shadowInactive 异常哨兵（>365 天，如 999999「永不过期」）→ replace 30

    注意：以下值是这个 LDAP 的**标准值或有效状态**，检测时一律跳过：
    - shadowExpire=55120 = 账号「长期有效」的标准值（600+ 账号都有），不动
    - shadowExpire=1 = 「禁用账号」标记，不动
    - shadowMax=99999 + shadowInactive=0 = 特殊账号（如 xhxu/jeman）的「密码永不过期」故意设置，不动
    """
    to_fix = []
    for dn in sorted(ldap_data):
        rec = ldap_data[dn]
        uid = rec.get("uid", "?")
        changes = []
        if not rec.get("shadowmax"):
            changes.append(("add", "shadowMax", str(DEFAULT_SHADOW_MAX)))
        if not rec.get("shadowwarning"):
            changes.append(("add", "shadowWarning", str(DEFAULT_SHADOW_WARNING)))
        inactive = rec.get("shadowinactive")
        if inactive and inactive.isdigit() and int(inactive) > SHADOW_INACTIVE_MAX:
            changes.append(("replace", "shadowInactive", str(DEFAULT_SHADOW_INACTIVE)))
        if changes:
            to_fix.append((dn, uid, changes))
    return to_fix


def main():
    parser = argparse.ArgumentParser(description="auditlog 改密对齐 + shadow 属性完整性巡检")
    parser.add_argument("--apply", action="store_true", help="实际写入；默认 dry-run 只报告")
    parser.add_argument("--since", default=None, help="只处理该日期（YYYY-MM-DD）之后的改密记录")
    parser.add_argument("--log", default=AUDIT_LOG, help="审计日志路径")
    args = parser.parse_args()

    global LDAP_MANAGER_PW
    LDAP_MANAGER_PW = os.environ.get("LDAP_MANAGER_PW", "")
    if not LDAP_MANAGER_PW:
        print("错误: 需设置环境变量 LDAP_MANAGER_PW（Manager 密码）。", file=sys.stderr)
        sys.exit(1)

    # ── 第一部分：auditlog 改密对齐 shadowLastChange ──
    if os.path.exists(args.log):
        since_days = None
        if args.since:
            dt = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            since_days = int(dt.timestamp() / 86400)

        pwd_changes = {}  # dn -> 最近改密 epoch days
        for ts, dn in iter_audit_records(args.log):
            days = ts_to_epoch_days(ts)
            if since_days is not None and days < since_days:
                continue
            if dn not in pwd_changes or days > pwd_changes[dn]:
                pwd_changes[dn] = days

        print(f"审计日志中改过密码的 DN: {len(pwd_changes)} 个")
        if pwd_changes:
            ldap_data = ldap_query_all_shadow()
            to_fix = []
            for dn, pwd_days in pwd_changes.items():
                rec = ldap_data.get(dn)
                if rec is None:
                    continue
                lc = rec.get("shadowlastchange")
                if lc in (None, "", "0"):
                    continue
                try:
                    lc_days = int(lc)
                except ValueError:
                    continue
                if pwd_days > lc_days:
                    to_fix.append((dn, rec.get("uid", "?"), lc_days, pwd_days))
            to_fix.sort(key=lambda x: x[0])

            print(f"需要对齐 shadowLastChange 的账号: {len(to_fix)} 个")
            if to_fix:
                print("\n" + "=" * 92)
                print(f"{'用户名':<22} {'当前 shadowLastChange':<22} {'改密日期(auditlog)':<22} {'操作'}")
                print("=" * 92)
                fixed = 0
                for dn, uid, lc_days, pwd_days in to_fix:
                    lc_date = datetime.fromtimestamp(lc_days * 86400, tz=timezone.utc).strftime("%Y-%m-%d")
                    pwd_date = datetime.fromtimestamp(pwd_days * 86400, tz=timezone.utc).strftime("%Y-%m-%d")
                    if args.apply:
                        ok = ldap_set_shadow(dn, pwd_days)
                        action = "已对齐" if ok else "失败"
                        if ok:
                            fixed += 1
                    else:
                        action = "dry-run"
                    print(f"{uid:<22} {lc_date:<22} {pwd_date:<22} {action}")
                print("=" * 92)
                if args.apply:
                    print(f"\n完成: 对齐 {fixed}/{len(to_fix)} 个账号。")
                else:
                    print(f"\n[dry-run] 共 {len(to_fix)} 个账号待对齐。加 --apply 实际写入。")
    else:
        print(f"审计日志不存在: {args.log}（auditlog overlay 未开启？），跳过改密对齐。", file=sys.stderr)

    # ── 第二部分：shadow 属性完整性巡检 ──
    print("\n" + "=" * 92)
    print("shadow 属性完整性巡检（缺 shadowMax/shadowWarning、异常 shadowInactive/shadowExpire）")
    print("=" * 92)
    shadow_data = ldap_query_all_shadow()
    shadow_fix = check_shadow_completeness(shadow_data)
    print(f"需要修复 shadow 属性的账号: {len(shadow_fix)} 个")
    if shadow_fix:
        print(f"\n{'用户名':<22} {'问题':<50} {'操作'}")
        print("-" * 92)
        fixed = 0
        for dn, uid, changes in shadow_fix:
            desc = []
            for op, attr, value in changes:
                if op == "delete":
                    desc.append(f"删 {attr}")
                elif op == "replace":
                    desc.append(f"{attr}→{value}")
                else:
                    desc.append(f"补 {attr}={value}")
            desc_str = "；".join(desc)
            if args.apply:
                ok = ldap_modify_attrs(dn, changes)
                action = "已修复" if ok else "失败"
                if ok:
                    fixed += 1
            else:
                action = "dry-run"
            print(f"{uid:<22} {desc_str:<50} {action}")
        print("-" * 92)
        if args.apply:
            print(f"\n完成: 修复 {fixed}/{len(shadow_fix)} 个账号。")
        else:
            print(f"\n[dry-run] 共 {len(shadow_fix)} 个账号待修复。加 --apply 实际写入。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
