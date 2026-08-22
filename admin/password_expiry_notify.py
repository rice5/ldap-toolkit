#!/usr/bin/env python3
#===============================================================================
# LDAP 密码过期统计与通知脚本 (password_expiry_notify.py)
#
# 功能：
#   1) 统计未来 N 天（默认 15 天）内密码过期的用户，发送汇总邮件
#      到 IT 邮箱（ADMIN_TO，抄送 ADMIN_CC）；
#   2) 分别向这些用户发送密码过期通知邮件，告知两种改密方式。
#
# 依赖：仅系统 ldapsearch（openldap-clients）+ Python3 标准库，无第三方模块。
#
# 用法：
#   python3 password_expiry_notify.py                 # 正常发送
#   python3 password_expiry_notify.py --dry-run       # 仅打印，不发邮件
#   python3 password_expiry_notify.py --send-summary-only   # 只发汇总，不发通知
#   python3 password_expiry_notify.py --test-email x@x.com  # 通知邮件改发到指定邮箱
#   python3 password_expiry_notify.py --config /path/to/.env
#
# 配置优先级：环境变量 > 配置文件(--config 或默认) > 脚本内置默认值
#===============================================================================

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
import logging
from datetime import datetime, timedelta
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from smtplib import SMTP, SMTPException

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLKIT_DIR = os.path.dirname(SCRIPT_DIR)  # ldap 项目根目录

#------------------------------------------------------------------------------
# 内置默认配置（非敏感项直接给出生产默认值；密码必须从环境变量/配置文件提供）
#------------------------------------------------------------------------------
DEFAULTS = {
    # LDAP（生产真实值在 config/password_expiry_notify.env 中，勿写入公开仓库）
    'LDAP_MASTER1': 'ldap01.example.com',
    'LDAP_MASTER2': 'ldap02.example.com',
    'LDAPS_PORT': '636',
    'LDAP_SUFFIX': 'dc=example,dc=com',
    'LDAP_RO_DN': 'cn=readonly,dc=example,dc=com',
    'LDAP_RO_PW': '',                       # 只读账号密码，敏感，必须外部提供
    'LDAP_TLS_CACERT': os.path.join(TOOLKIT_DIR, 'ldap_certs', 'ca.crt'),
    'LDAP_USER_BASE': 'ou=People,dc=example,dc=com',

    # 通知阈值（未来多少天内过期）
    'NOTIFY_DAYS': '15',

    # SMTP
    'SMTP_HOST': 'mail.example.com',
    'SMTP_PORT': '25',
    'SMTP_USER': 'donotreply@example.com',
    'SMTP_PASS': '',                        # SMTP 密码，敏感，必须外部提供
    'SMTP_FROM': 'donotreply@example.com',
    'SMTP_FROM_NAME': 'LDAP密码过期通知',

    # 汇总邮件收件人
    'ADMIN_TO': 'it@example.com',
    'ADMIN_CC': 'admin@example.com',

    # 自助改密网站
    'SELF_SERVICE_URL': 'https://self.example.com/',
}

# 配置文件默认路径
DEFAULT_CONFIG = os.path.join(TOOLKIT_DIR, 'config', 'password_expiry_notify.env')

# LDAP 查询需要获取的属性
LDAP_ATTRS = 'uid cn mail shadowLastChange shadowMax shadowExpire shadowInactive loginShell'

LOG = logging.getLogger('ldap-password-expiry')


#------------------------------------------------------------------------------
# 配置加载
#------------------------------------------------------------------------------
def load_config(config_path=None):
    """合并配置：内置默认值 < 配置文件 < 环境变量（最高优先级）。"""
    cfg = dict(DEFAULTS)

    # 1) 配置文件
    path = config_path or DEFAULT_CONFIG
    if path and os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    cfg[key] = value

    # 2) 环境变量覆盖（仅覆盖脚本关心的键）
    for key in cfg:
        if key in os.environ and os.environ[key] != '':
            cfg[key] = os.environ[key]

    return cfg


#------------------------------------------------------------------------------
# LDAP 查询（调用系统 ldapsearch）
#------------------------------------------------------------------------------
def ldap_search(cfg, base, filter_str, attrs):
    """执行 ldapsearch，返回 stdout 文本；失败重试 ldap02，仍失败抛异常。"""
    masters = [cfg['LDAP_MASTER1'], cfg['LDAP_MASTER2']]
    port = cfg['LDAPS_PORT']
    cacert = cfg['LDAP_TLS_CACERT']
    ro_dn = cfg['LDAP_RO_DN']
    ro_pw = cfg['LDAP_RO_PW']

    last_err = None
    for host in masters:
        # 密码写入临时文件（600），避免出现在 ps/命令行中
        pw_file = None
        try:
            with tempfile.NamedTemporaryFile('w', delete=False) as pf:
                pf.write(ro_pw)
                pw_file = pf.name
            os.chmod(pw_file, 0o600)

            cmd = [
                'ldapsearch', '-x', '-LLL',
                '-H', f'ldaps://{host}:{port}',
                '-D', ro_dn,
                '-y', pw_file,
                '-b', base,
                filter_str,
            ] + attrs.split()

            env = dict(os.environ)
            if cacert and os.path.isfile(cacert):
                env['LDAPTLS_CACERT'] = cacert

            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, env=env)
            if proc.returncode == 0:
                return proc.stdout
            last_err = proc.stderr.strip() or f'ldapsearch 退出码 {proc.returncode}'
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
        finally:
            if pw_file and os.path.exists(pw_file):
                os.remove(pw_file)

    raise RuntimeError(f'LDAP 查询失败（已重试 {len(masters)} 台服务器）: {last_err}')


def parse_ldif(text):
    """解析 ldapsearch -LLL 输出为记录列表 [{attr: value}, ...]。"""
    records = []
    cur = {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                records.append(cur)
                cur = {}
            continue
        if line.startswith(' '):  # 续行（本查询属性均单行，保留兼容）
            continue
        if ': ' in line:
            key, _, value = line.partition(': ')
            key = key.strip().lower()
            # 多值属性仅取第一个
            if key not in cur:
                cur[key] = value.strip()
    if cur:
        records.append(cur)
    return records


#------------------------------------------------------------------------------
# 密码过期计算
#------------------------------------------------------------------------------
def epoch_days_to_date(days):
    """将 shadow 的 epoch 天数转换为本地日期字符串 YYYY-MM-DD。"""
    if days in (None, '', '0', 0):
        return None
    try:
        return datetime.fromtimestamp(int(days) * 86400).strftime('%Y-%m-%d')
    except (ValueError, OSError):
        return None


def today_epoch_days():
    """今天对应的 epoch 天数（UTC 语义，与 shadowLastChange 一致）。"""
    return int(time.time() / 86400)


def compute_expiry(rec):
    """根据一条 LDAP 记录计算密码过期信息。

    返回 dict 或 None（无法计算/密码永不过期）。
    """
    last_change = rec.get('shadowlastchange')
    max_days = rec.get('shadowmax')

    # 无法计算：缺少属性
    if last_change in (None, '') or max_days in (None, ''):
        return None
    try:
        last_change = int(last_change)
        max_days = int(max_days)
    except ValueError:
        return None

    # shadowMax=0 表示密码永不过期（lock 状态）
    if max_days == 0:
        return None

    expire_days = last_change + max_days
    days_left = expire_days - today_epoch_days()

    return {
        'last_change_date': epoch_days_to_date(last_change),
        'expire_date': epoch_days_to_date(expire_days),
        'days_left': days_left,
    }


#------------------------------------------------------------------------------
# 邮件正文
#------------------------------------------------------------------------------
SELF_SERVICE_URL_PLACEHOLDER = '{SELF_SERVICE_URL}'

SUMMARY_TEMPLATE = """\
您好，

以下为未来 {notify_days} 天内密码将过期的 LDAP 用户统计，请及时关注并协助处理。

共 {count} 个用户：

{rows}

说明：
  - 距离密码过期天数 = 密码过期日 - 今天（0 表示今天过期，负数表示已过期）。
  - 用户需在过期前完成密码修改，否则登录将受到限制。

此邮件由 LDAP 密码过期监控任务自动发送（发件人：{smtp_from}）。
"""

NOTIFY_TEMPLATE = """\
您好，{uid}：

您的 LDAP 账号密码将于 {expire_date} 过期（距今还有 {days_left} 天），为避免影响正常登录与作业，请尽快修改密码。

账号信息：
  用户名：          {uid}
  最后一次改密时间：{last_change_date}
  密码过期时间：    {expire_date}
  距离密码过期天数：{days_left} 天

修改密码的方式（任选其一）：

方式一：通过 Exceed TurboX（ETX）登录 Linux 服务器后，在终端执行 passwd 命令修改密码。

方式二：通过自助密码修改网站 {self_service_url}
        选择目录服务 "LDAP Account"，输入当前密码登录后修改密码。

如已修改密码，请忽略本邮件。

此邮件由系统自动发送，请勿直接回复。如有疑问，请联系 IT 部门（{admin_to}）。
"""


def render_summary(users, cfg):
    if not users:
        return None
    notify_days = cfg['NOTIFY_DAYS']
    header = f"{'用户名':<20} {'邮箱':<32} {'最后改密':<12} {'密码过期':<12} {'剩余天数':>6}"
    sep = '-' * len(header)
    lines = [header, sep]
    for u in users:
        mail = u.get('mail') or '(无)'
        lines.append(
            f"{u['uid']:<20} {mail:<32} {u['last_change_date'] or '-':<12} "
            f"{u['expire_date'] or '-':<12} {u['days_left']:>6}"
        )
    body = SUMMARY_TEMPLATE.format(
        notify_days=notify_days,
        count=len(users),
        rows='\n'.join(lines),
        smtp_from=cfg['SMTP_FROM'],
    )
    return body


def render_notify(u, cfg):
    return NOTIFY_TEMPLATE.format(
        uid=u['uid'],
        expire_date=u['expire_date'] or '-',
        days_left=u['days_left'],
        last_change_date=u['last_change_date'] or '-',
        self_service_url=cfg['SELF_SERVICE_URL'],
        admin_to=cfg['ADMIN_TO'],
    )


#------------------------------------------------------------------------------
# SMTP 发送
#------------------------------------------------------------------------------
def send_mail(cfg, to_addrs, subject, body, cc_addrs=None):
    """通过 SMTP 发送一封纯文本邮件。返回 (成功数, 失败信息列表)。"""
    from_addr = formataddr((Header(cfg['SMTP_FROM_NAME'], 'utf-8').encode(),
                            cfg['SMTP_FROM']))

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8').encode()
    msg['From'] = from_addr
    msg['To'] = ', '.join(to_addrs)
    if cc_addrs:
        msg['Cc'] = ', '.join(cc_addrs)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=cfg['SMTP_FROM'].split('@')[-1])

    all_rcpts = list(to_addrs) + list(cc_addrs or [])

    failures = []
    try:
        smtp = SMTP(cfg['SMTP_HOST'], int(cfg['SMTP_PORT']), timeout=30)
        smtp.ehlo()
        smtp.login(cfg['SMTP_USER'], cfg['SMTP_PASS'])
        smtp.sendmail(cfg['SMTP_FROM'], all_rcpts, msg.as_string())
        smtp.quit()
        return len(all_rcpts), failures
    except (SMTPException, OSError) as e:
        failures.append(f'{cfg["SMTP_HOST"]}:{cfg["SMTP_PORT"]} -> {type(e).__name__}: {e}')
        return 0, failures


#------------------------------------------------------------------------------
# 主逻辑
#------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='LDAP 密码过期统计与通知（未来 N 天内过期用户）')
    parser.add_argument('--config', default=None,
                        help=f'配置文件路径（默认 {DEFAULT_CONFIG}）')
    parser.add_argument('--days', type=int, default=None,
                        help='通知阈值天数（覆盖 NOTIFY_DAYS）')
    parser.add_argument('--dry-run', '-n', action='store_true',
                        help='仅打印结果，不发送任何邮件')
    parser.add_argument('--send-summary-only', action='store_true',
                        help='只发汇总邮件，不发用户通知邮件')
    parser.add_argument('--test-email', default=None,
                        help='将通知邮件改发到指定邮箱（测试用，替代真实用户邮箱）')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='输出详细日志到 stderr')
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr, level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s')

    cfg = load_config(args.config)
    if args.days is not None:
        cfg['NOTIFY_DAYS'] = str(args.days)
    notify_days = int(cfg['NOTIFY_DAYS'])

    # 校验必需配置
    missing = []
    if not cfg['LDAP_RO_PW']:
        missing.append('LDAP_RO_PW')
    if not cfg['SMTP_PASS']:
        missing.append('SMTP_PASS')
    if missing:
        LOG.error(f'缺少必需配置: {", ".join(missing)}。'
                  f'请在配置文件或环境变量中提供。')
        sys.exit(1)
    if not os.path.isfile(cfg['LDAP_TLS_CACERT']):
        LOG.error(f'CA 证书不存在: {cfg["LDAP_TLS_CACERT"]}')
        sys.exit(1)

    # 查询所有用户
    LOG.info('正在查询 LDAP 用户 ...')
    try:
        output = ldap_search(cfg, cfg['LDAP_USER_BASE'],
                             '(objectClass=posixAccount)', LDAP_ATTRS)
    except RuntimeError as e:
        LOG.error(str(e))
        sys.exit(1)
    records = parse_ldif(output)
    LOG.info(f'查询到 {len(records)} 个用户')

    # 计算过期，筛选未来 notify_days 天内过期的用户
    expiring = []
    for rec in records:
        uid = rec.get('uid')
        if not uid:
            continue
        info = compute_expiry(rec)
        if info is None:
            continue
        if 0 <= info['days_left'] <= notify_days:
            expiring.append({
                'uid': uid,
                'mail': rec.get('mail', ''),
                'last_change_date': info['last_change_date'],
                'expire_date': info['expire_date'],
                'days_left': info['days_left'],
            })

    # 按剩余天数升序（最紧急在前）
    expiring.sort(key=lambda x: x['days_left'])

    LOG.info(f'未来 {notify_days} 天内密码过期用户数: {len(expiring)}')
    for u in expiring:
        LOG.info(f"  {u['uid']}  mail={u['mail'] or '-'}  "
                 f"改密={u['last_change_date']} 过期={u['expire_date']} "
                 f"剩余={u['days_left']}天")

    if not expiring:
        LOG.info('无即将过期用户，不发送邮件。')
        return 0

    if args.dry_run:
        print(f'\n[DRY-RUN] 共 {len(expiring)} 个用户未来 {notify_days} 天内密码过期，'
              f'未发送任何邮件。')
        print(render_summary(expiring, cfg))
        return 0

    # 功能1：汇总邮件给 IT（ADMIN_TO / ADMIN_CC 均支持逗号分隔多个收件人）
    admin_to = [x.strip() for x in cfg['ADMIN_TO'].split(',') if x.strip()]
    admin_cc = [x.strip() for x in cfg['ADMIN_CC'].split(',') if x.strip()]
    subject_summary = f'[LDAP密码过期统计] 未来{notify_days}天内 {len(expiring)} 个用户密码将过期'
    body_summary = render_summary(expiring, cfg)
    LOG.info(f'发送汇总邮件 -> {", ".join(admin_to)} (cc {", ".join(admin_cc)})')
    if not args.dry_run:
        ok, errs = send_mail(cfg, admin_to, subject_summary,
                             body_summary, cc_addrs=admin_cc or None)
        if errs:
            LOG.error(f'汇总邮件发送失败: {errs}')
        else:
            LOG.info(f'汇总邮件发送成功（{ok} 收件人）')

    # 功能2：逐个通知用户
    if args.send_summary_only:
        LOG.info('--send-summary-only，跳过用户通知邮件。')
        return 0

    sent = 0
    for u in expiring:
        if not u['mail']:
            LOG.warning(f"用户 {u['uid']} 无邮箱，跳过通知。")
            continue
        to_addr = args.test_email or u['mail']
        subject_notify = f'【密码过期提醒】您的LDAP账号密码将于{u["expire_date"] or "近期"}过期'
        body_notify = render_notify(u, cfg)
        ok, errs = send_mail(cfg, [to_addr], subject_notify, body_notify)
        if errs:
            LOG.error(f"通知邮件发送失败 [{u['uid']} -> {to_addr}]: {errs}")
        else:
            LOG.info(f"通知邮件已发送 [{u['uid']} -> {to_addr}]")
            sent += 1

    LOG.info(f'完成：汇总 1 封，通知 {sent}/{len(expiring)} 封。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
