#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETX 离职/禁用员工残留进程精准扫描与双阶段清理脚本
功能：
1. 联动 OpenLDAP (ou=People,dc=jaguarmicro,dc=hpc) 获取 shadowExpire=1 的禁用账号（或指定单个用户）。
2. 通过 Ansible (10.1.254.14) 在 ETX 交互桌面节点 (etx:etxt) 并发执行进程检索。
3. 执行双阶段安全回收：先发送 SIGTERM (优雅终止释放 License/文件锁)，等待 15s 后对残留进程发送 SIGKILL。
4. 白名单保护：内置系统级服务账号白名单，严禁误伤基础组件。
5. 告警通知：通过 @alert 机器人将清理明细推送到企业微信 IT 告警群。
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_DIR = os.path.dirname(SCRIPT_DIR)

ANSIBLE_HOST = os.environ.get("ANSIBLE_HOST", "10.1.254.14")
ANSIBLE_TARGET = os.environ.get("ANSIBLE_TARGET", "etx:etxt")
LDAP_CA = os.environ.get("LDAP_CA", os.path.join(TOOLKIT_DIR, "ldap_certs", "ca.crt"))
LDAP_URI = os.environ.get("LDAP_URI", "ldaps://ldap01.jaguarmicro.hpc:636")
LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "cn=readonly,dc=jaguarmicro,dc=hpc")
LDAP_BIND_PW = os.environ.get("LDAP_RO_PW", "JgMcro@2021")
LDAP_BASE = os.environ.get("LDAP_BASE", "ou=People,dc=jaguarmicro,dc=hpc")

# 节点端执行的双阶段清理与上报脚本
NODE_WORKER_SH = r'''#!/bin/bash
export LC_ALL=C
HOSTNAME=$(hostname -s)
DRY_RUN="$1"

# 系统保留账号白名单
SYSTEM_USERS="^(root|zabbix|telegraf|chrony|postfix|polkitd|dbus|rpc|daemon|bin|node_exporter|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd.*|messagebus|avahi|colord|gluster|geoclue|pulse|rtkit|saned|usbmux|etx|etxsvr|etxdb)$"

declare -A DISABLED_MAP
while read -r u; do
    [ -n "$u" ] && DISABLED_MAP["$u"]=1
done < /tmp/disabled_uids.txt

TARGET_PIDS=()
REPORT_ITEMS=()

while read -r pid ppid user cpu mem etime comm args; do
    [ -z "$pid" ] && continue
    [[ "$user" =~ $SYSTEM_USERS ]] && continue
    
    if [ "${DISABLED_MAP[$user]}" = "1" ]; then
        TARGET_PIDS+=("$pid")
        REPORT_ITEMS+=("{\"host\":\"$HOSTNAME\",\"pid\":$pid,\"user\":\"$user\",\"cpu\":\"$cpu%\",\"mem\":\"$mem%\",\"runtime\":\"$etime\",\"comm\":\"$comm\",\"args\":\"$args\"}")
    fi
done < <(ps -eo pid,ppid,user:32,%cpu,%mem,etime,comm,args --sort=-%cpu | grep -v "PID")

# 执行清理逻辑
if [ "$DRY_RUN" != "--dry-run" ] && [ ${#TARGET_PIDS[@]} -gt 0 ]; then
    # 第一阶段：SIGTERM 优雅退出
    for p in "${TARGET_PIDS[@]}"; do
        kill -15 "$p" 2>/dev/null
    done
    
    sleep 15
    
    # 第二阶段：SIGKILL 强制回收
    for p in "${TARGET_PIDS[@]}"; do
        kill -9 "$p" 2>/dev/null
    done
fi

if [ ${#REPORT_ITEMS[@]} -gt 0 ]; then
    echo "CLEANUP_JSON_START"
    printf '%s\n' "${REPORT_ITEMS[@]}"
    echo "CLEANUP_JSON_END"
fi
'''

def get_disabled_uids_from_ldap(single_user=None):
    if single_user:
        return [single_user]
    
    cmd = [
        "ldapsearch", "-x", "-LLL",
        "-H", LDAP_URI,
        "-D", LDAP_BIND_DN,
        "-w", LDAP_BIND_PW,
        "-b", LDAP_BASE,
        "(shadowExpire=1)", "uid"
    ]
    env = os.environ.copy()
    env["LDAPTLS_CACERT"] = LDAP_CA
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error querying LDAP: {res.stderr}", file=sys.stderr)
        return []
    
    uids = []
    for line in res.stdout.splitlines():
        if line.startswith("uid:"):
            uids.append(line.split(":", 1)[1].strip())
    return sorted(list(set(uids)))

def run_cleanup(uids, dry_run=False):
    if not uids:
        print("No disabled uids to process.")
        return []
    
    # 写入 uid 列表并推送到 Ansible 控制机
    with open("/tmp/disabled_uids.txt", "w", encoding="utf-8") as f:
        for u in uids:
            f.write(u + "\n")
    subprocess.run(f"scp /tmp/disabled_uids.txt root@{ANSIBLE_HOST}:/tmp/disabled_uids.txt", shell=True, check=True)
    
    with open("/tmp/node_disabled_cleaner.sh", "w", encoding="utf-8") as f:
        f.write(NODE_WORKER_SH)
    subprocess.run(f"scp /tmp/node_disabled_cleaner.sh root@{ANSIBLE_HOST}:/tmp/node_disabled_cleaner.sh", shell=True, check=True)

    # 同步 uid 文件到各节点
    subprocess.run(f"ssh root@{ANSIBLE_HOST} 'ansible {ANSIBLE_TARGET} -m copy -a \"src=/tmp/disabled_uids.txt dest=/tmp/disabled_uids.txt\" -f 15'", shell=True, check=True)
    
    # 节点执行
    flag = "--dry-run" if dry_run else "--clean"
    ansible_cmd = f"ssh root@{ANSIBLE_HOST} 'ansible {ANSIBLE_TARGET} -m script -a \"/tmp/node_disabled_cleaner.sh {flag}\" -f 15'"
    proc = subprocess.run(ansible_cmd, shell=True, capture_output=True, text=True)
    
    items = []
    in_json = False
    for line in proc.stdout.splitlines():
        line_clean = line.replace('\r', '').strip()
        if "CLEANUP_JSON_START" in line_clean:
            in_json = True
            continue
        if "CLEANUP_JSON_END" in line_clean:
            in_json = False
            continue
        if in_json and line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                items.append(json.loads(line_clean))
            except Exception:
                pass
    return items

def notify_alert(items, dry_run=False):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts_dict = {}
    users_dict = {}
    for it in items:
        h = it.get("host", "unknown")
        u = it.get("user", "unknown")
        hosts_dict.setdefault(h, []).append(it)
        users_dict[u] = users_dict.get(u, 0) + 1
    
    status_tag = "[预检/Dry-Run 模式]" if dry_run else "[自动清理完毕]"
    msg_lines = [
        f"### 🔔 ETX 集群离职/禁用账号进程治理报告 {status_tag}",
        f"> **⏰ 执行时间**: {now_str}",
        f"> **🎯 扫描范围**: ETX 交互桌面集群 (etx02~28, etxt01)",
        f"> **📊 影响统计**: 在 **{len(hosts_dict)}** 台主机上命中 **{len(users_dict)}** 个离职用户的 **{len(items)}** 个残留进程",
        "",
        "**Top 5 节点分布**:"
    ]
    
    for h, p_list in sorted(hosts_dict.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
        msg_lines.append(f"- 节点 `{h}`: {len(p_list)} 个进程")
        
    msg_lines.append("\n**Top 5 用户残留**:")
    for u, cnt in sorted(users_dict.items(), key=lambda x: x[1], reverse=True)[:5]:
        msg_lines.append(f"- 用户 `{u}`: {cnt} 个进程")
        
    if not dry_run:
        msg_lines.append("\n✅ 已通过两阶段 (SIGTERM -> SIGKILL) 彻底回收进程资源与 License。")
        
    full_msg = "\n".join(msg_lines)
    
    # 经由 hermes alert 发送 (统一使用 Agent 间协同交互协议)
    hermes_bin = "/home/root1/.hermes/hermes-agent/venv/bin/hermes"
    alert_cmd = [
        hermes_bin, "-p", "alert", "chat",
        "--in", "/home/root1",
        "-c", "Bot Chat",
        "--create-if-missing",
        "-Q", "-q",
        f"Message from 🤖 operator (@operator): 请将以下离职账号进程清理报告统一推送给管理员：\n\n{full_msg}"
    ]
    subprocess.run(alert_cmd, capture_output=True, text=True)

def main():
    parser = argparse.ArgumentParser(description="ETX 离职/禁用账号残留进程清理工具")
    parser.add_argument("--dry-run", action="store_true", help="仅扫描上报，不实际杀进程")
    parser.add_argument("--user", type=str, help="指定清理单个已禁用账号")
    parser.add_argument("--notify", action="store_true", help="向企业微信告警群推送报告")
    args = parser.parse_args()

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching disabled uids...")
    uids = get_disabled_uids_from_ldap(args.user)
    print(f"Total target uids: {len(uids)}")
    
    print(f"Running scan & clean (dry_run={args.dry_run}) across {ANSIBLE_TARGET}...")
    items = run_cleanup(uids, dry_run=args.dry_run)
    print(f"Total processes matched: {len(items)}")
    
    if items and args.notify:
        print("Sending alert to WeCom...")
        notify_alert(items, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
