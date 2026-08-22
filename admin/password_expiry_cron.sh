#!/bin/bash
#===============================================================================
# LDAP 密码过期通知 — 定时任务入口
# 供 hermes cronjob（no_agent=True）或系统 crontab 调用。
#
# 行为：
#   - 正常执行：脚本输出全部写入日志文件，stdout 为空 → hermes 静默（不发消息）
#   - 执行失败：stdout 输出错误摘要 + 返回非零退出码 → hermes 触发错误告警
#===============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/../logs/password_expiry_notify.log"

# 确保日志目录存在
mkdir -p "$(dirname "${LOG_FILE}")"

/usr/bin/python3.12 "${SCRIPT_DIR}/password_expiry_notify.py" >> "${LOG_FILE}" 2>&1
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "LDAP密码过期通知脚本执行失败（退出码 ${rc}）。"
    echo "日志文件: ${LOG_FILE}"
    echo "--- 最近日志 ---"
    tail -20 "${LOG_FILE}" 2>/dev/null
fi

exit "$rc"
