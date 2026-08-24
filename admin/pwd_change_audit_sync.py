#!/usr/bin/env python3
"""LDAP 密码修改审计对齐脚本 (pwd_change_audit_sync.py)

功能：解析 slapo-auditlog 产出的审计日志，找出「修改过 userPassword 但
shadowLastChange 未同步」的用户，自动把 shadowLastChange 对齐到改密当天。

背景：phpldapadmin / SSH passwd 两条改密路径只改 userPassword、不回写
shadowLastChange，导致密码过期日（shadowLastChange + shadowMax）算错。
本脚本配合 auditlog overlay 使用，实现自动巡检对齐。

用法（在 LDAP 服务器本地运行，需能读审计日志 + Manager 凭据）：
  python3 pwd_change_audit_sync.py                 # dry-run：只报告，不改
  python3 pwd_change_audit_sync.py --apply         # 实际对齐 shadowLastChange
  python3 pwd_change_audit_sync.py --since 2026-08-01   # 只处理该日期之后的记录

依赖：仅 Python3 标准库 + 系统 ldapsearch。审计日志由 auditlog overlay 生成。
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


def ldap_query(dn_attr_map):
    """查多个 DN 的 shadowLastChange。返回 {dn: shadowLastChange_days 或 None}。"""
    # 用 Manager 查询（只读账号可能没有所有 OU 的读权限）
    result = {}
    cmd = [
        "ldapsearch", "-x", "-LLL",
        "-H", f"ldaps://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_MANAGER_DN,
        "-w", LDAP_MANAGER_PW,
        "-b", LDAP_SUFFIX,
        "(objectClass=posixAccount)",
        "dn", "uid", "shadowLastChange", "shadowMax",
    ]
    env = dict(os.environ, LDAPTLS_CACERT=LDAP_TLS_CACERT)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    if r.returncode != 0:
        print("ldapsearch 失败:", r.stderr[:500], file=sys.stderr)
        return result
    # 解析 LDIF
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
    # 写临时 LDIF + 密码文件，密码不出现在命令行
    import tempfile
    ldif = f"""dn: {dn}
changetype: modify
replace: shadowLastChange
shadowLastChange: {days}
"""
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=env)
        return r.returncode == 0
    finally:
        os.remove(ldif_path)
        os.remove(pw_path)


def main():
    parser = argparse.ArgumentParser(description="auditlog 密码修改对齐 shadowLastChange")
    parser.add_argument("--apply", action="store_true", help="实际写入；默认 dry-run 只报告")
    parser.add_argument("--since", default=None, help="只处理该日期（YYYY-MM-DD）之后的改密记录")
    parser.add_argument("--log", default=AUDIT_LOG, help="审计日志路径")
    args = parser.parse_args()

    global LDAP_MANAGER_PW
    LDAP_MANAGER_PW = os.environ.get("LDAP_MANAGER_PW", "")
    if not LDAP_MANAGER_PW:
        print("错误: 需设置环境变量 LDAP_MANAGER_PW（Manager 密码）。", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.log):
        print(f"审计日志不存在: {args.log}（auditlog overlay 是否已开启？）", file=sys.stderr)
        sys.exit(1)

    since_days = None
    if args.since:
        dt = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        since_days = int(dt.timestamp() / 86400)

    # 1) 收集所有「改过密码」的 DN + 改密时间
    pwd_changes = {}  # dn -> 最近改密 epoch days
    for ts, dn in iter_audit_records(args.log):
        days = ts_to_epoch_days(ts)
        if since_days is not None and days < since_days:
            continue
        if dn not in pwd_changes or days > pwd_changes[dn]:
            pwd_changes[dn] = days

    print(f"审计日志中改过密码的 DN: {len(pwd_changes)} 个")

    # 2) 查这些 DN 当前 shadowLastChange
    ldap_data = ldap_query(set(pwd_changes.keys()))

    # 3) 比对，找出 shadowLastChange 落后于改密时间的
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
            uid = rec.get("uid", "?")
            to_fix.append((dn, uid, lc_days, pwd_days))

    to_fix.sort(key=lambda x: x[0])

    print(f"需要对齐 shadowLastChange 的账号: {len(to_fix)} 个")
    if not to_fix:
        return 0

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
