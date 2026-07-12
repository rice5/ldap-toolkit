#!/bin/bash
#===============================================================================
# 查找所有 Shell 为 /sbin/nologin 的用户并批量禁用
#
# 用法：
#   ./batch/disable-nologin.sh              # 交互确认后执行
#   ./batch/disable-nologin.sh --dry-run    # 仅列出，不执行
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLKIT_DIR="${SCRIPT_DIR}/.."
ADMIN_TOOL="${TOOLKIT_DIR}/admin/ldapadmin.py"
QUERY_TOOL="${TOOLKIT_DIR}/client/ldapquery.sh"

DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY_RUN=true ;;
        -h|--help)
            echo "用法: $0 [--dry-run|-n]"
            echo ""
            echo "查找 Shell 为 /sbin/nologin 的用户，批量执行 disable 操作。"
            echo "  --dry-run/-n   仅列出，不实际执行"
            exit 0
            ;;
        *) echo "未知参数: $arg" >&2; exit 1 ;;
    esac
done

# 获取只读密码（复用 ldapquery.sh 的自动检测逻辑）
if [ -n "${LDAP_RO_PW:-}" ]; then
    RO_PW="$LDAP_RO_PW"
elif [ -r /etc/sssd/sssd.conf ] 2>/dev/null; then
    RO_PW=$(sed -n 's/^[[:space:]]*ldap_default_authtok[[:space:]]*=[[:space:]]*//p' /etc/sssd/sssd.conf 2>/dev/null | head -1)
elif [ -r /etc/nslcd.conf ] 2>/dev/null; then
    RO_PW=$(sed -n 's/^[[:space:]]*bindpw[[:space:]]\+//p' /etc/nslcd.conf 2>/dev/null | head -1)
fi

if [ -z "${RO_PW:-}" ]; then
    echo -n "请输入 LDAP 只读账号密码: "
    read -rs RO_PW
    echo ""
fi

export LDAP_RO_PW="$RO_PW"

# 查找 nologin 用户
echo "正在查找 Shell 为 /sbin/nologin 的用户..."
set +e
QUERY_OUTPUT=$("$QUERY_TOOL" user-list 2>/dev/null)
QUERY_RC=$?
set -e
if [ $QUERY_RC -ne 0 ] || [ -z "$QUERY_OUTPUT" ]; then
    echo "错误: 查询用户列表失败。请检查只读账号密码。" >&2
    exit 1
fi
NOLOGIN_USERS=$(echo "$QUERY_OUTPUT" | grep nologin | awk '{print $1}' || true)

if [ -z "$NOLOGIN_USERS" ]; then
    echo "未找到 nologin 用户。"
    exit 0
fi

# 统计
USER_ARRAY=()
while IFS= read -r uid; do
    [ -n "$uid" ] && USER_ARRAY+=("$uid")
done <<< "$NOLOGIN_USERS"

TOTAL=${#USER_ARRAY[@]}
echo ""
echo "找到 ${TOTAL} 个 nologin 用户:"
echo ""
printf "  %-4s %s\n" "序号" "用户名"
echo "  ---- ----"
for i in "${!USER_ARRAY[@]}"; do
    printf "  %-4d %s\n" $((i+1)) "${USER_ARRAY[$i]}"
done
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] 以上用户将被禁用。去掉 --dry-run 参数以实际执行。"
    exit 0
fi

# 确认
echo -n "确认禁用以上 ${TOTAL} 个用户？[y/N]: "
read -r CONFIRM
if [ "${CONFIRM,,}" != "y" ]; then
    echo "已取消。"
    exit 0
fi

echo ""
echo "开始批量禁用..."
SUCCESS=0
FAILED=0

for uid in "${USER_ARRAY[@]}"; do
    echo -n "  ${uid} ... "
    set +e
    MOD_OUTPUT=$("$ADMIN_TOOL" user mod "$uid" disable 2>&1)
    MOD_RC=$?
    set -e
    if [ $MOD_RC -eq 0 ] && echo "$MOD_OUTPUT" | grep -q "已禁用"; then
        echo "OK"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "FAILED"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "完成: 成功 ${SUCCESS}, 失败 ${FAILED}"
