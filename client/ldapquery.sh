#!/bin/bash
#===============================================================================
# LDAP 客户端查询工具 (ldapquery.sh)
# 独立脚本，适用于客户端节点。普通用户即可运行，无需 python-ldap。
#
# 依赖：openldap-clients (ldapsearch) + CA 证书
# 认证：优先从环境变量 $LDAP_RO_PW 读取，否则交互提示。
#
# 用法：
#   ./ldapquery.sh user <uid>      查询用户详细信息
#   ./ldapquery.sh group <name>    查询组详细信息
#   ./ldapquery.sh user-list       列出所有用户（含状态/改密/过期）
#   ./ldapquery.sh group-list      列出所有组
#   ./ldapquery.sh self            查询当前登录用户
#===============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# 配置
#------------------------------------------------------------------------------
LDAP_MASTER1="${LDAP_MASTER1:-ldap01.example.com}"
LDAP_MASTER2="${LDAP_MASTER2:-ldap02.example.com}"
LDAPS_PORT="${LDAPS_PORT:-636}"
LDAP_SUFFIX="${LDAP_SUFFIX:-dc=example,dc=com}"
LDAP_RO_DN="${LDAP_RO_DN:-cn=readonly,${LDAP_SUFFIX}}"
LDAP_RO_PW="${LDAP_RO_PW:-}"

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() { echo -e "${RED}错误: $*${NC}" >&2; exit 1; }

#------------------------------------------------------------------------------
# 获取只读密码
#------------------------------------------------------------------------------
get_ro_password() {
    [ -n "${LDAP_RO_PW:-}" ] && return
    local found=false

    if [ -r /etc/sssd/sssd.conf ] 2>/dev/null; then
        LDAP_RO_PW=$(sed -n 's/^[[:space:]]*ldap_default_authtok[[:space:]]*=[[:space:]]*//p' /etc/sssd/sssd.conf 2>/dev/null | head -1)
        [ -n "${LDAP_RO_PW:-}" ] && found=true
    fi

    if [ "$found" = false ] && [ -r /etc/nslcd.conf ] 2>/dev/null; then
        LDAP_RO_PW=$(sed -n 's/^[[:space:]]*bindpw[[:space:]]\+//p' /etc/nslcd.conf 2>/dev/null | head -1)
        [ -n "${LDAP_RO_PW:-}" ] && found=true
    fi

    [ "$found" = true ] && return

    echo -n "请输入 LDAP 只读账号密码 (cn=readonly): " >&2
    read -rs LDAP_RO_PW
    echo "" >&2
    if [ -z "${LDAP_RO_PW}" ]; then
        die "需要只读账号密码才能查询。"
    fi
}

#------------------------------------------------------------------------------
# 执行 ldapsearch（失败时自动重试 ldap02）
#------------------------------------------------------------------------------
ldap_search() {
    local filter="$1" attrs="$2" base="${3:-$LDAP_SUFFIX}"
    local result stderr_file pw_file rc
    stderr_file=$(mktemp)
    # 密码临时文件: mktemp 默认 600，用完立即删除，不会泄露
    pw_file=$(mktemp)
    printf '%s' "${LDAP_RO_PW}" > "$pw_file"
    # 确保只有当前用户可读
    chmod 600 "$pw_file" 2>/dev/null || true

    for host in "${LDAP_MASTER1}" "${LDAP_MASTER2}"; do
        set +e
        result=$(ldapsearch -x -LLL \
            -H "ldaps://${host}:${LDAPS_PORT}" \
            -D "${LDAP_RO_DN}" -y "$pw_file" \
            -b "$base" "$filter" $attrs 2>"$stderr_file")
        rc=$?
        set -e
        if [ $rc -eq 0 ]; then
            rm -f "$stderr_file" "$pw_file"
            echo "$result"
            return 0
        fi
        if grep -qi "invalid credentials\|authentication" "$stderr_file" 2>/dev/null; then
            cat "$stderr_file" >&2 || true
            rm -f "$stderr_file" "$pw_file"
            die "只读账号认证失败，请检查密码（注意：只读密码 ≠ 管理员密码）。"
        fi
    done

    echo "--- ldapsearch stderr ---" >&2
    cat "$stderr_file" >&2 || true
    rm -f "$stderr_file" "$pw_file"
    die "LDAP 查询失败。请检查: 1) 网络通否 2) CA证书 ${TLS_CACERT} 是否存在"
}

epoch_to_date() {
    local days="$1"
    [ -z "$days" ] || [ "$days" = "0" ] && { echo "-"; return; }
    date -d "@$((days * 86400))" '+%Y-%m-%d' 2>/dev/null || echo "-"
}

#------------------------------------------------------------------------------
# user — 查询单个用户详情
#------------------------------------------------------------------------------
cmd_user() {
    local uid="$1"
    get_ro_password

    local data
    data=$(ldap_search "(&(objectClass=posixAccount)(uid=${uid}))" \
        "dn uidNumber gidNumber homeDirectory loginShell mail shadowLastChange shadowExpire shadowMax shadowInactive cn")

    [ -z "$data" ] && die "用户 '${uid}' 未找到。"

    # 用 awk 解析 LDIF
    echo "$data" | awk -v uid="$uid" -v today="$(date +%s)" '
    function epoch2date(days) {
        if (days == "" || days == "0") return "-"
        cmd = "date -d @\"" (days * 86400) "\" +%Y-%m-%d 2>/dev/null"
        cmd | getline d; close(cmd)
        return (d != "" ? d : "-")
    }
    /^dn: /              { dn=substr($0,5) }
    /^uidNumber: /       { uidnum=$2 }
    /^gidNumber: /       { gidnum=$2 }
    /^homeDirectory: /   { home=$2 }
    /^loginShell: /      { shell=$2 }
    /^mail: /            { mail=$2 }
    /^shadowLastChange: /{ lastch=$2 }
    /^shadowExpire: /    { expire=$2 }
    /^shadowMax: /       { maxdays=$2 }
    /^shadowInactive: /  { inactive=$2 }
    END {
        # 账号状态
        status="启用"
        if (expire == "1") status="禁用"
        else if (expire != "" && expire > 1) {
            now_days = int(today / 86400)
            if (expire <= now_days) status="已过期"
            else status="启用（过期: " epoch2date(expire) "）"
        }
        # 密码过期
        pwd_expire="-"
        if (lastch != "" && maxdays != "" && maxdays != "0")
            pwd_expire = epoch2date(lastch + maxdays)

        print "========================================"
        print "  用户: " uid
        print "========================================"
        print "  DN:                    " dn
        print "  UID:                   " uidnum
        print "  GID:                   " gidnum
        print "  家目录:                " (home ? home : "?")
        print "  Shell:                 " (shell ? shell : "?")
        print "  邮箱:                  " (mail ? mail : "(无)")
        print "  账号状态:              " status
        print "  上次改密:              " epoch2date(lastch)
        print "  密码过期日:            " pwd_expire
        print "  过期宽限期:            " (inactive ? inactive " 天" : "?")
        print "========================================"
    }'
}

#------------------------------------------------------------------------------
# group — 查询组详情
#------------------------------------------------------------------------------
cmd_group() {
    local name="$1"
    get_ro_password

    local data
    data=$(ldap_search "(&(objectClass=posixGroup)(cn=${name}))" \
        "dn gidNumber memberUid description cn")

    [ -z "$data" ] && die "组 '${name}' 未找到。"

    echo "$data" | awk -v grp="$name" '
    /^dn: /          { dn=substr($0,5) }
    /^gidNumber: /   { gid=$2 }
    /^description: / { desc=substr($0, index($0,$2)) }
    /^memberUid: /   { members[++n]=$2 }
    END {
        print "========================================"
        print "  组: " grp
        print "========================================"
        print "  DN:                    " dn
        print "  GID:                   " gid
        print "  描述:                  " (desc ? desc : "(无)")
        print "  成员数:                " n
        if (n > 0) {
            print "  成员列表:"
            for (i=1; i<=n; i++) print "    - " members[i]
        }
        print "========================================"
    }'
}

#------------------------------------------------------------------------------
# user-list — 列出所有用户（含状态/改密/密码过期）
#------------------------------------------------------------------------------
cmd_user_list() {
    get_ro_password

    local now_epoch; now_epoch=$(date +%s)

    printf "%-16s %-8s %-8s %-8s %-12s %-28s %-12s %-12s\n" \
        "用户名" "UID" "GID" "状态" "Shell" "家目录" "上次改密" "密码过期"
    echo "------------------------------------------------------------------------------------------------------------------"

    ldap_search "(objectClass=posixAccount)" \
        "uid uidNumber gidNumber homeDirectory loginShell shadowLastChange shadowExpire shadowMax" | \
    awk -v today="$now_epoch" '
    function epoch2date(days) {
        if (days == "" || days == "0") return "-"
        cmd = "date -d @\"" (days * 86400) "\" +%Y-%m-%d 2>/dev/null"
        cmd | getline d; close(cmd)
        return (d != "" ? d : "-")
    }
    /^dn:/ {
        if (uid != "") {
            status = "启用"
            if (expire == "1") status = "禁用"
            else if (expire != "" && expire > 1) {
                now_days = int(today / 86400)
                if (expire <= now_days) status = "过期"
            }
            pwd_exp = "-"
            if (lastch != "" && maxd != "" && maxd != "0")
                pwd_exp = epoch2date(lastch + maxd)
            printf "%-16s %-8s %-8s %-8s %-12s %-28s %-12s %-12s\n", uid, uidnum, gidnum, status, shell, home, epoch2date(lastch), pwd_exp
        }
        uid=""; uidnum=""; gidnum=""; home=""; shell=""; lastch=""; expire=""; maxd=""
    }
    /^uid: /             { uid=$2 }
    /^uidNumber: /       { uidnum=$2 }
    /^gidNumber: /       { gidnum=$2 }
    /^homeDirectory: /   { home=$2 }
    /^loginShell: /      { shell=$2 }
    /^shadowLastChange: /{ lastch=$2 }
    /^shadowExpire: /    { expire=$2 }
    /^shadowMax: /       { maxd=$2 }
    END {
        if (uid != "") {
            status = "启用"
            if (expire == "1") status = "禁用"
            else if (expire != "" && expire > 1) {
                now_days = int(today / 86400)
                if (expire <= now_days) status = "过期"
            }
            pwd_exp = "-"
            if (lastch != "" && maxd != "" && maxd != "0")
                pwd_exp = epoch2date(lastch + maxd)
            printf "%-16s %-8s %-8s %-8s %-12s %-28s %-12s %-12s\n", uid, uidnum, gidnum, status, shell, home, epoch2date(lastch), pwd_exp
        }
    }'
}

#------------------------------------------------------------------------------
# group-list — 列出所有组
#------------------------------------------------------------------------------
cmd_group_list() {
    get_ro_password

    printf "%-30s %-8s %s\n" "组名" "GID" "成员"
    echo "----------------------------------------------------------------------"

    ldap_search "(objectClass=posixGroup)" \
        "cn gidNumber memberUid" | \
    awk '
    /^dn:/ {
        if (cn != "") printf "%-30s %-8s %s\n", cn, gid, members
        cn=""; gid=""; members=""
    }
    /^cn: /        { cn=$2 }
    /^gidNumber: / { gid=$2 }
    /^memberUid: / {
        if (members == "") members=$2; else members=members "," $2
    }
    END {
        if (cn != "") printf "%-30s %-8s %s\n", cn, gid, members
    }'
}

#------------------------------------------------------------------------------
# self — 查自己
#------------------------------------------------------------------------------
cmd_self() {
    local uid="${1:-$USER}"
    [ -z "$uid" ] && die "无法确定当前用户名，请手动指定: $0 self <uid>"
    cmd_user "$uid"
}

#------------------------------------------------------------------------------
# 入口
#------------------------------------------------------------------------------
usage() {
    echo "用法: $0 <命令> [参数]"
    echo ""
    echo "命令:"
    echo "  user  <uid>      查询用户详细信息"
    echo "  group <name>     查询组详细信息（含成员列表）"
    echo "  user-list        列出所有用户（含状态/改密/过期）"
    echo "  group-list       列出所有组"
    echo "  self  [uid]      查询当前用户（默认 \$USER）"
    echo ""
    echo "认证:"
    echo "  优先读取 \$LDAP_RO_PW，其次尝试 /etc/sssd/sssd.conf"
    echo "  或 /etc/nslcd.conf（需 root），最后交互提示。"
    echo ""
    echo "示例:"
    echo "  export LDAP_RO_PW='密码'      # 一次设置，后续免输"
    echo "  $0 self"
    echo "  $0 user zhangsan"
    echo "  $0 group devteam"
    echo "  $0 user-list"
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        user)       [ $# -lt 2 ] && { usage; exit 1; }; cmd_user "$2" ;;
        group)      [ $# -lt 2 ] && { usage; exit 1; }; cmd_group "$2" ;;
        user-list)  cmd_user_list ;;
        group-list) cmd_group_list ;;
        self)       cmd_self "${2:-}" ;;
        -h|--help|"") usage ;;
        *)          echo "未知命令: $cmd" >&2; usage; exit 1 ;;
    esac
}

main "$@"
