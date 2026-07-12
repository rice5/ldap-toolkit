#!/usr/bin/env python3
#===============================================================================
# LDAP 统一管理工具 (ldapadmin.py)
# 合并所有管理员操作：用户、组、批量导入、密码管理
#
# 依赖：python3-ldap (python3-ldap / pyldap)
# 安装：yum install python3-ldap 或 pip3 install python-ldap
#
# 用法：
#   python3 ldapadmin.py user add <uid> [options]
#   python3 ldapadmin.py user mod <uid> <action>
#   python3 ldapadmin.py user del <uid> [options]
#   python3 ldapadmin.py user search <uid>
#   python3 ldapadmin.py user passwd <uid>
#   python3 ldapadmin.py group add <name> [options]
#   python3 ldapadmin.py group del <name> [options]
#   python3 ldapadmin.py batch add <file>
#   python3 ldapadmin.py batch del <file>
#===============================================================================

import argparse
import os
import re
import sys
import random
import string
import hashlib
import base64
import logging
from datetime import datetime, timedelta

# Try to import ldap
try:
    import ldap
    from ldap import modlist
    from ldap.ldapobject import LDAPObject
except ImportError:
    print("错误: 缺少 python-ldap 模块。请安装: yum install python3-ldap 或 pip3 install python-ldap", file=sys.stderr)
    sys.exit(1)


#------------------------------------------------------------------------------
# 配置（可通过环境变量覆盖）
#------------------------------------------------------------------------------

class Config:
    """LDAP 配置管理

    所有值均可通过环境变量覆盖，默认值为示例占位符。
    生产部署前需设置以下核心变量（或通过 config/ldap.conf 统一覆盖）：

        export LDAP_DC1=your_domain      # ★ 替换 example
        export LDAP_DC2=your_tld         # ★ 替换 com
        export LDAP_MASTER1=ldap01.your.domain  # ★ 替换服务器地址
        export LDAP_MASTER2=ldap02.your.domain
        export LDAP_ROOTPW='your_manager_password'
        export LDAP_RO_PW='your_readonly_password'
    """

    def __init__(self):
        # ── ★ 部署前必须修改的变量 ──
        # LDAP 域
        self.dc1 = os.environ.get('LDAP_DC1', 'example')       # ★ 改为你的 dc1
        self.dc2 = os.environ.get('LDAP_DC2', 'com')           # ★ 改为你的 dc2
        self.suffix = os.environ.get('LDAP_SUFFIX', f'dc={self.dc1},dc={self.dc2}')
        self.root_dn = os.environ.get('LDAP_ROOTDN', f'cn=Manager,{self.suffix}')
        self.root_pw = os.environ.get('LDAP_ROOTPW', '')       # ★ 设置管理员密码

        # 只读账号
        self.ro_user = os.environ.get('LDAP_RO', 'readonly')
        self.ro_dn = os.environ.get('LDAP_RO_DN', f'cn={self.ro_user},{self.suffix}')
        self.ro_pw = os.environ.get('LDAP_RO_PW', '')          # ★ 设置只读密码

        # 服务器
        self.master1 = os.environ.get('LDAP_MASTER1', 'ldap01.example.com')  # ★ 改为实际地址
        self.master2 = os.environ.get('LDAP_MASTER2', 'ldap02.example.com')  # ★ 改为实际地址
        self.ldaps_port = int(os.environ.get('LDAPS_PORT', '636'))

        # ── 通常无需修改 ──
        # TLS
        self.tls_enabled = os.environ.get('LDAP_TLS_ENABLED', 'yes') == 'yes'
        self.tls_cacert = os.environ.get('LDAP_TLS_CACERT', '/etc/openldap/certs/ca.crt')
        self.tls_reqcert = os.environ.get('LDAP_TLS_REQCERT', 'demand')

        # DIT
        self.user_base = os.environ.get('LDAP_USER_BASE', f'ou=People,{self.suffix}')
        self.group_base = os.environ.get('LDAP_GROUP_BASE', f'ou=Group,{self.suffix}')
        self.search_base = self.suffix

        # 默认值（★ 可按需修改）
        self.default_shell = os.environ.get('DEFAULT_LOGIN_SHELL', '/bin/csh')     # ★ 默认 Shell
        self.default_home_base = os.environ.get('DEFAULT_HOME_BASE', '/share/home') # ★ 家目录前缀
        self.uid_min = int(os.environ.get('DEFAULT_UID_MIN', '5000'))               # ★ UID/GID 起点
        self.gid_min = int(os.environ.get('DEFAULT_GID_MIN', '5000'))

        # 密码策略
        self.password_min_length = int(os.environ.get('PASSWORD_MIN_LENGTH', '8'))
        self.shadow_max_days = int(os.environ.get('SHADOW_MAX_DAYS', '90'))          # 密码有效期（天）
        self.shadow_warn_days = int(os.environ.get('SHADOW_WARN_DAYS', '7'))         # 过期前警告（天）
        self.shadow_inactive = int(os.environ.get('SHADOW_INACTIVE', '30'))           # 宽限期（天）


config = Config()


#------------------------------------------------------------------------------
# LDAP 连接管理
#------------------------------------------------------------------------------

class LDAPConnection:
    """TLS-enabled LDAP 连接管理"""

    def __init__(self):
        self.conn = None

    def connect(self, bind_dn=None, bind_pw=None):
        """建立 LDAP 连接"""
        uri = f'ldaps://{config.master1}:{config.ldaps_port}'
        self.conn = ldap.initialize(uri)
        self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        self.conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)

        if config.tls_enabled:
            self.conn.set_option(ldap.OPT_X_TLS_CACERTFILE, config.tls_cacert)
            reqcert = {
                'demand': ldap.OPT_X_TLS_DEMAND,
                'allow': ldap.OPT_X_TLS_ALLOW,
                'never': ldap.OPT_X_TLS_NEVER,
            }.get(config.tls_reqcert, ldap.OPT_X_TLS_DEMAND)
            self.conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, reqcert)
            # 注意：ldaps:// 已加密，不需要 start_tls_s()（否则会报 TLS already started）
            if uri.startswith('ldap://'):
                self.conn.start_tls_s()

        dn = bind_dn or config.root_dn
        pw = bind_pw or config.root_pw
        self.conn.simple_bind_s(dn, pw)
        return self.conn

    def close(self):
        """关闭连接"""
        if self.conn:
            self.conn.unbind_s()

    def search(self, base, filter_str, attrs=None):
        """搜索 LDAP 条目"""
        try:
            result = self.conn.search_s(base, ldap.SCOPE_SUBTREE, filter_str, attrs)
            return result
        except ldap.NO_SUCH_OBJECT:
            return []

    def add(self, dn, attrs):
        """添加 LDAP 条目"""
        ldif = modlist.addModlist(attrs)
        self.conn.add_s(dn, ldif)

    def modify(self, dn, changes):
        """修改 LDAP 条目"""
        self.conn.modify_s(dn, changes)

    def delete(self, dn):
        """删除 LDAP 条目"""
        self.conn.delete_s(dn)

    def passwd(self, dn, new_pw):
        """修改用户密码"""
        if hasattr(self.conn, 'passwd_s'):
            self.conn.passwd_s(dn, None, new_pw)
        else:
            hashed = self._ssha_hash(new_pw)
            self.modify(dn, [(ldap.MOD_REPLACE, 'userPassword', hashed.encode())])

    def get_next_uid(self):
        """获取下一个可用 ID（同时扫描 posixAccount 的 uidNumber 和 posixGroup 的 gidNumber，确保不被占用）"""
        max_id = config.uid_min - 1

        # 从 posixAccount 中找最大 uidNumber
        result = self.search(config.search_base, '(objectClass=posixAccount)', ['uidNumber'])
        for dn, attrs in result:
            try:
                val = int(attrs.get('uidNumber', [b'0'])[0])
                if val > max_id:
                    max_id = val
            except (ValueError, IndexError):
                pass

        # 从 posixGroup 中找最大 gidNumber（防止组 GID 与用户 UID 冲突）
        result = self.search(config.search_base, '(objectClass=posixGroup)', ['gidNumber'])
        for dn, attrs in result:
            try:
                val = int(attrs.get('gidNumber', [b'0'])[0])
                if val > max_id:
                    max_id = val
            except (ValueError, IndexError):
                pass

        return max(max_id + 1, config.uid_min)

    def get_next_gid(self):
        """获取下一个可用 GID（仅从 posixGroup 取值）"""
        max_id = config.uid_min - 1
        result = self.search(config.search_base, '(objectClass=posixGroup)', ['gidNumber'])
        for dn, attrs in result:
            try:
                val = int(attrs.get('gidNumber', [b'0'])[0])
                if val > max_id:
                    max_id = val
            except (ValueError, IndexError):
                pass
        return max(max_id + 1, config.uid_min)

    def user_exists(self, uid):
        """检查用户是否存在"""
        result = self.search(config.search_base, f'(uid={ldap_filter_escape(uid)})', ['dn'])
        return len(result) > 0

    def group_exists(self, name):
        """检查组是否存在"""
        result = self.search(config.search_base, f'(cn={ldap_filter_escape(name)})', ['dn'])
        return len(result) > 0

    @staticmethod
    def _ssha_hash(password):
        """生成 SSHA 密码哈希"""
        salt = os.urandom(4)
        sha = hashlib.sha1(password.encode() + salt).digest()
        return '{SSHA}' + base64.b64encode(sha + salt).decode()


#------------------------------------------------------------------------------
# 工具函数
#------------------------------------------------------------------------------

def ldap_filter_escape(value):
    """转义 LDAP 过滤器中的特殊字符"""
    return value.replace('\\', '\\5c').replace('*', '\\2a') \
                .replace('(', '\\28').replace(')', '\\29') \
                .replace('\x00', '\\00')

def generate_password(length=10):
    """生成随机密码（默认10位，含大小写字母+数字+特殊字符）"""
    chars = string.ascii_letters + string.digits + '!@#$%'
    password = ''.join(random.choice(chars) for _ in range(length))
    # 确保至少包含大写、小写、数字、特殊字符各一个
    if not (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in '!@#$%' for c in password)):
        return generate_password(length)
    return password

def validate_username(username):
    """校验用户名格式"""
    import re
    if not re.match(r'^[a-z][a-z0-9._-]{0,31}$', username):
        raise ValueError(f"无效的用户名: '{username}'。必须以小写字母开头，最多 32 个字符（字母、数字、点、下划线、连字符）。")
    return username.lower()

def validate_group_name(name):
    """校验组名格式"""
    import re
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9._-]{0,31}$', name):
        raise ValueError(f"无效的组名: '{name}'。必须以字母开头，最多 32 个字符。")
    return name

def validate_password_strength(password, username=''):
    """校验密码强度，返回错误列表（空列表 = 通过）

    要求：
      - 至少 8 个字符
      - 包含大写字母
      - 包含小写字母
      - 包含数字
      - 包含特殊字符（!@#$%^&*等）
      - 不能包含用户名
    """
    errors = []
    if len(password) < 8:
        errors.append(f"密码长度至少 8 个字符（当前 {len(password)} 个）")
    if not re.search(r'[A-Z]', password):
        errors.append("密码必须包含至少一个大写字母")
    if not re.search(r'[a-z]', password):
        errors.append("密码必须包含至少一个小写字母")
    if not re.search(r'[0-9]', password):
        errors.append("密码必须包含至少一个数字")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]', password):
        errors.append("密码必须包含至少一个特殊字符")
    if username and username.lower() in password.lower():
        errors.append("密码不能包含用户名")
    return errors

def prompt_password(prompt_text="请输入密码: "):
    """安全地提示输入密码"""
    import getpass
    return getpass.getpass(prompt_text)

def confirm_action(message):
    """交互式确认"""
    answer = input(f"{message} [y/N]: ").strip().lower()
    return answer == 'y'


#------------------------------------------------------------------------------
# 用户管理
#------------------------------------------------------------------------------

class UserManager:
    """用户管理操作"""

    def __init__(self, conn):
        self.conn = conn

    def add(self, username, **kwargs):
        """创建用户"""
        username = validate_username(username)

        if self.conn.user_exists(username):
            print(f"错误: 用户 '{username}' 已存在。", file=sys.stderr)
            return 3

        # 参数默认值
        group_name = kwargs.get('group', username)
        shell = kwargs.get('shell', config.default_shell)
        password = kwargs.get('password') or ''
        home = kwargs.get('home') or f'{config.default_home_base}/{username}'
        uid = kwargs.get('uid', 0)
        gid = kwargs.get('gid', 0)
        mail = kwargs.get('mail')
        if mail is None:
            mail = f'{username}@example.com'
        phone = kwargs.get('phone', '')
        disabled = kwargs.get('disabled', False)
        must_change = kwargs.get('must_change', False)
        expire_date = kwargs.get('expire', '')
        max_days = kwargs.get('max_days', config.shadow_max_days)
        extra_groups = kwargs.get('groups', '')
        ou = kwargs.get('ou', '')

        # 自动分配 UID/GID（统一值）
        if not uid:
            uid = self.conn.get_next_uid()
        if not gid:
            gid = uid  # UID 和 GID 统一
        else:
            gid = uid

        # 生成密码（不指定则自动生成10位并打印）
        gen_pw = ''
        if not password:
            password = generate_password()
            gen_pw = password

        # ── dry-run 模式：打印摘要后退出，不实际创建 ──
        dry_run = kwargs.get('dry_run', False)
        if dry_run:
            user_base = f'ou={ou},{config.user_base}' if ou else config.user_base
            user_dn = f'cn={username},{user_base}'
            group_dn = f'cn={group_name},{config.group_base}'
            expire_display = '禁用（shadowExpire=1）' if disabled else (expire_date if expire_date else '正常')
            pwd_display = '***（已指定）' if not gen_pw else f'[自动生成] {password}'

            print()
            print("┌──────────────────────────────────────────┐")
            print("│  DRY-RUN 预演 — 以下是将要执行的操作        │")
            print("├──────────────────────────────────────────┤")
            print(f"│  用户名:         {username}")
            print(f"│  用户 DN:        {user_dn}")
            print(f"│  主组:           {group_name} → {group_dn}")
            if extra_groups:
                print(f"│  附加组:         {extra_groups}")
            print(f"│  UID:            {uid}")
            print(f"│  GID:            {gid}（= UID）")
            print(f"│  家目录:         {home}")
            print(f"│  Shell:          {shell}")
            print(f"│  邮箱:           {mail}")
            if phone:
                print(f"│  电话:           {phone}")
            print(f"│  密码:           {pwd_display}")
            print(f"│  密码有效期:     {max_days} 天")
            print(f"│  过期前警告:     {config.shadow_warn_days} 天")
            print(f"│  过期宽限期:     {config.shadow_inactive} 天")
            print(f"│  过期日期:       {expire_display}")
            print(f"│  首次改密:       {'是' if must_change else '否'}")
            print(f"│  账号状态:       {'禁用' if disabled else '启用'}")
            print(f"│ 所属 OU:         {user_base}")
            if not self.conn.group_exists(group_name):
                print(f"│  ★ 将自动创建主组: {group_name}")
            if ou:
                ou_dn = f'ou={ou},{config.user_base}'
                result_check = self.conn.search(ou_dn, '(objectClass=*)', ['dn'])
                if not result_check:
                    print(f"│  ★ 将自动创建 OU: ou={ou}")
            print("└──────────────────────────────────────────┘")
            print()
            print("提示: 去掉 --dry-run / -n 参数以实际创建。")
            return 0

        # 创建主组（如果组不存在）
        if not self.conn.group_exists(group_name):
            print(f"创建主组: {group_name}")
            gm = GroupManager(self.conn)
            gm.add(group_name, gid=gid, dry_run=dry_run)

        # 计算 ShadowAccount 属性
        today = int(datetime.now().timestamp() / 86400)
        last_change = 0 if must_change else today
        expire_days = 1 if disabled else None

        if expire_date:
            try:
                dt = datetime.strptime(expire_date, '%Y-%m-%d')
                expire_days = int(dt.timestamp() / 86400)
            except ValueError:
                print(f"错误: 无效的日期格式 '{expire_date}'，请使用 YYYY-MM-DD。", file=sys.stderr)
                return 1

        # 自动创建父 OU（如果指定了 --ou 且 OU 不存在）
        if ou:
            ou_dn = f'ou={ou},{config.user_base}'
            result = self.conn.search(ou_dn, '(objectClass=*)', ['dn'])
            if not result:
                print(f"创建 OU: ou={ou}")
                ou_attrs = {
                    'objectClass': [b'top', b'organizationalUnit'],
                    'ou': [ou.encode()],
                }
                try:
                    self.conn.add(ou_dn, ou_attrs)
                    print(f"OU 'ou={ou}' 创建成功。")
                except ldap.LDAPError as e:
                    print(f"错误: 创建 OU 'ou={ou}' 失败: {e}", file=sys.stderr)
                    return 2

        # 确定用户所属 OU
        user_base = f'ou={ou},{config.user_base}' if ou else config.user_base
        user_dn = f'cn={username},{user_base}'
        user_attrs = {
            'objectClass': [b'top', b'inetOrgPerson', b'posixAccount', b'shadowAccount'],
            'uid': [username.encode()],
            'cn': [username.encode()],
            'sn': [username.encode()],
            'uidNumber': [str(uid).encode()],
            'gidNumber': [str(gid).encode()],
            'homeDirectory': [home.encode()],
            'loginShell': [shell.encode()],
            'shadowLastChange': [str(last_change).encode()],
            'shadowMax': [str(max_days).encode()],
            'shadowWarning': [str(config.shadow_warn_days).encode()],
            'shadowInactive': [str(config.shadow_inactive).encode()],
        }

        if mail:
            user_attrs['mail'] = [mail.encode()]
        if phone:
            user_attrs['mobile'] = [phone.encode()]
        if expire_days is not None:
            user_attrs['shadowExpire'] = [str(expire_days).encode()]

        try:
            self.conn.add(user_dn, user_attrs)
            self.conn.passwd(user_dn, password)
            print(f"用户 '{username}' 创建成功 (UID: {uid}, GID: {gid})。")
            if gen_pw:
                print(f"★ 自动生成密码: {password}（请立即保存，此后不会再次显示）")
            else:
                print(f"密码已设置。")
        except ldap.LDAPError as e:
            print(f"错误: 创建用户失败: {e}", file=sys.stderr)
            return 2

        # 加入附加组
        if extra_groups:
            for g in extra_groups.split(','):
                g = g.strip()
                if g:
                    g_result = self.conn.search(config.search_base, f'(cn={ldap_filter_escape(g)})', ['dn'])
                    if g_result:
                        group_dn = g_result[0][0]
                        try:
                            self.conn.modify(group_dn, [(ldap.MOD_ADD, 'memberUid', username.encode())])
                            print(f"  已加入组: {g}")
                        except ldap.LDAPError:
                            print(f"  警告: 加入组 '{g}' 失败")

        if disabled:
            print("账号已创建为禁用状态。")
        if must_change:
            print("用户首次登录时必须修改密码。")

        logging.info(f"User created: {username} (uid={uid}, gid={gid})")
        return 0

    def delete(self, username, force=False, remove_groups=False, backup_home=False):
        """删除用户"""
        username = validate_username(username)

        if not self.conn.user_exists(username):
            print(f"用户 '{username}' 未找到。", file=sys.stderr)
            return 1

        if not force and not confirm_action(f"确认删除用户 '{username}'？此操作不可撤销。"):
            print("已取消。")
            return 0

        # 获取家目录
        result = self.conn.search(config.search_base, f'(uid={ldap_filter_escape(username)})', ['homeDirectory'])
        home = None
        if result:
            home = result[0][1].get('homeDirectory', [b''])[0].decode()

        # 备份家目录
        if backup_home and home and os.path.isdir(home):
            backup = f"{home}.deleted.{datetime.now().strftime('%F_%H-%M-%S')}"
            try:
                import shutil
                shutil.move(home, backup)
                print(f"家目录已备份: {backup}")
            except OSError as e:
                print(f"警告: 备份家目录失败: {e}")

        # 从组中移除
        if remove_groups:
            result = self.conn.search(config.group_base, f'(memberUid={ldap_filter_escape(username)})', ['dn'])
            for dn, _ in result:
                try:
                    self.conn.modify(dn, [(ldap.MOD_DELETE, 'memberUid', username.encode())])
                    print(f"  已从组移除: {dn}")
                except ldap.LDAPError:
                    pass

        # 查找用户真实 DN
        result = self.conn.search(config.search_base, f'(uid={ldap_filter_escape(username)})', ['dn'])
        if not result:
            print(f"错误: 用户 '{username}' 未找到。", file=sys.stderr)
            return 2
        user_dn = result[0][0]

        # 删除用户
        try:
            self.conn.delete(user_dn)
            print(f"用户 '{username}' 已删除。")
            logging.info(f"User deleted: {username}")
            return 0
        except ldap.LDAPError as e:
            print(f"错误: 删除用户失败: {e}", file=sys.stderr)
            return 2

    def modify(self, username, action, value=None, dry_run=False):
        """修改用户属性"""
        username = validate_username(username)

        # 查找用户真实 DN
        result = self.conn.search(config.search_base, f'(uid={ldap_filter_escape(username)})', ['dn', 'loginShell', 'shadowExpire', 'shadowMax'])
        if not result:
            print(f"错误: 用户 '{username}' 未找到。", file=sys.stderr)
            return 2
        user_dn = result[0][0]
        attrs = result[0][1]

        # dry-run: 打印将要执行的操作
        if dry_run:
            self._dry_run_mod(username, user_dn, attrs, action, value)
            return 0

        actions = {
            'enable': lambda: self._set_expire(user_dn, None),
            'disable': lambda: self._set_expire(user_dn, 1),
            'expire': lambda: self._set_expire_date(user_dn, value),
            'lock': lambda: self._set_shadow_max(user_dn, 0),
            'unlock': lambda: self._set_shadow_max(user_dn, config.shadow_max_days),
            'pwd-expire': lambda: self._force_pwd_change(user_dn),
            'shell': lambda: self._change_attr(user_dn, 'loginShell', value),
            'home': lambda: self._change_attr(user_dn, 'homeDirectory', value),
            'status': lambda: self._show_status(username),
        }

        if action not in actions:
            print(f"错误: 未知操作 '{action}'。有效操作: {', '.join(actions.keys())}", file=sys.stderr)
            return 1

        return actions[action]()

    def _dry_run_mod(self, username, user_dn, attrs, action, value):
        """dry-run: 显示将要执行的修改操作"""
        def get_attr(name):
            val = attrs.get(name, [b''])[0]
            return val.decode() if val else '-'

        current_expire = get_attr('shadowExpire')
        current_shell = get_attr('loginShell')
        current_max = get_attr('shadowMax')

        desc_map = {
            'enable':     ('启用账号', f'删除 shadowExpire (当前={current_expire}) + 恢复 Shell={config.default_shell}'),
            'disable':    ('禁用账号', f'shadowExpire=1 + Shell=/sbin/nologin (当前 Shell={current_shell})'),
            'expire':     ('设置过期', f'shadowExpire={value}'),
            'lock':       ('锁定密码', f'shadowMax=0 (当前={current_max})'),
            'unlock':     ('解锁密码', f'shadowMax={config.shadow_max_days} (当前={current_max})'),
            'pwd-expire': ('强制改密', 'shadowLastChange=0'),
            'shell':      ('修改 Shell', f'loginShell={value} (当前={current_shell})'),
            'home':       ('修改家目录', f'homeDirectory={value}'),
            'status':     ('查看状态', '(只读，不修改)'),
        }

        desc, detail = desc_map.get(action, (action, str(value)))
        print()
        print("┌──────────────────────────────────────────┐")
        print("│  DRY-RUN 预演 — 将执行以下修改              │")
        print("├──────────────────────────────────────────┤")
        print(f"│  用户:           {username}")
        print(f"│  DN:             {user_dn}")
        print(f"│  操作:           {desc}")
        print(f"│  详情:           {detail}")
        print("└──────────────────────────────────────────┘")
        print()
        print("提示: 去掉 --dry-run / -n 参数以实际执行。")
        """设置/移除 shadowExpire，同时修改 loginShell"""
        if days is None:
            self.conn.modify(dn, [
                (ldap.MOD_DELETE, 'shadowExpire', None),
                (ldap.MOD_REPLACE, 'loginShell', config.default_shell.encode()),
            ])
            print("账号已启用（Shell 已恢复为默认）。")
        else:
            self.conn.modify(dn, [
                (ldap.MOD_REPLACE, 'shadowExpire', str(days).encode()),
                (ldap.MOD_REPLACE, 'loginShell', b'/sbin/nologin'),
            ])
            print("账号已禁用（Shell 已设为 /sbin/nologin）。")
        logging.info(f"Account expire: {dn} shadowExpire={days}")
        return 0

    def _set_expire_date(self, dn, date_str):
        """设置账号过期日期"""
        if not date_str:
            print("错误: 需要日期参数 (YYYY-MM-DD)。", file=sys.stderr)
            return 1
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            days = int(dt.timestamp() / 86400)
            return self._set_expire(dn, days)
        except ValueError:
            print(f"错误: 无效的日期格式 '{date_str}'。请使用 YYYY-MM-DD。", file=sys.stderr)
            return 1

    def _set_shadow_max(self, dn, days):
        """设置 shadowMax"""
        self.conn.modify(dn, [(ldap.MOD_REPLACE, 'shadowMax', str(days).encode())])
        action_word = "锁定" if days == 0 else "解锁"
        print(f"账号已{action_word}。")
        return 0

    def _force_pwd_change(self, dn):
        """强制下次登录修改密码"""
        self.conn.modify(dn, [
            (ldap.MOD_REPLACE, 'shadowLastChange', b'0'),
            (ldap.MOD_REPLACE, 'shadowMax', str(config.shadow_max_days).encode()),
        ])
        print("用户下次登录时必须修改密码。")
        return 0

    def _change_attr(self, dn, attr, value):
        """修改单个属性"""
        if not value:
            print(f"错误: 需要提供 {attr} 的值。", file=sys.stderr)
            return 1
        self.conn.modify(dn, [(ldap.MOD_REPLACE, attr, value.encode())])
        print(f"{attr} 已修改为: {value}")
        return 0

    def _show_status(self, username):
        """显示用户状态"""
        result = self.conn.search(config.search_base, f'(uid={ldap_filter_escape(username)})',
                                  ['uidNumber', 'gidNumber', 'homeDirectory', 'loginShell',
                                   'shadowLastChange', 'shadowExpire', 'shadowMax',
                                   'shadowInactive', 'mail'])

        if not result:
            print(f"用户 '{username}' 未找到。", file=sys.stderr)
            return 1

        dn, attrs = result[0]

        def get_attr(name):
            val = attrs.get(name, [b''])[0]
            return val.decode() if val else ''

        uidnum = get_attr('uidNumber')
        gidnum = get_attr('gidNumber')
        home = get_attr('homeDirectory')
        shell = get_attr('loginShell')
        last_change = get_attr('shadowLastChange')
        expire = get_attr('shadowExpire')
        shadow_max = get_attr('shadowMax')
        inactive = get_attr('shadowInactive')
        mail = get_attr('mail')

        # 确定状态
        now = datetime.now()
        status = "启用"
        if expire == '1':
            status = "禁用"
        elif expire and int(expire) > 1:
            expire_dt = datetime.fromtimestamp(int(expire) * 86400)
            if expire_dt < now:
                status = "已过期"
            else:
                status = f"启用（过期日期: {expire_dt.strftime('%Y-%m-%d')}）"

        # 格式化日期
        lc_str = "未知"
        if last_change:
            lc_dt = datetime.fromtimestamp(int(last_change) * 86400) if last_change != '0' else None
            lc_str = lc_dt.strftime('%Y-%m-%d') if lc_dt else "首次登录时需修改"

        pwd_expire_str = "无"
        if last_change and shadow_max and int(shadow_max) > 0:
            pwd_expire_dt = datetime.fromtimestamp((int(last_change) + int(shadow_max)) * 86400)
            pwd_expire_str = pwd_expire_dt.strftime('%Y-%m-%d')

        # 查询组成员
        group_result = self.conn.search(config.search_base, f'(memberUid={ldap_filter_escape(username)})', ['cn'])
        groups = [attrs['cn'][0].decode() for _, attrs in group_result if 'cn' in attrs]

        print("========================================")
        print(f"  账号状态: {username}")
        print("========================================")
        print(f"  DN:                    {dn}")
        print(f"  UID 号:                 {uidnum}")
        print(f"  GID 号:                 {gidnum}")
        print(f"  家目录:                 {home}")
        print(f"  Shell:                  {shell}")
        print(f"  邮箱:                   {mail}")
        print(f"  账号过期 (shadowExpire):     {status}")
        print(f"  上次改密 (shadowLastChange):  {lc_str}")
        print(f"  密码过期 (shadowMax+LastChange): {pwd_expire_str}")
        print(f"  过期宽限天数 (shadowInactive):   {inactive}")
        print(f"  组成员:                 {', '.join(groups) if groups else '(无)'}")
        print("========================================")
        return 0

    def search(self, username):
        """搜索用户并显示信息"""
        return self._show_status(username)

    def change_password(self, username, new_password=None):
        """修改用户密码"""
        username = validate_username(username)

        if not self.conn.user_exists(username):
            print(f"错误: 用户 '{username}' 未找到。", file=sys.stderr)
            return 2

        if not new_password:
            new_password = prompt_password(f"为用户 '{username}' 输入新密码: ")
            confirm = prompt_password("确认新密码: ")
            if new_password != confirm:
                print("错误: 密码不匹配。", file=sys.stderr)
                return 1

        # 密码强度校验
        errors = validate_password_strength(new_password, username)
        if errors:
            for e in errors:
                print(f"错误: {e}", file=sys.stderr)
            return 1

        # 查找用户真实 DN
        result = self.conn.search(config.search_base, f'(uid={ldap_filter_escape(username)})', ['dn'])
        if not result:
            print(f"错误: 用户 '{username}' 未找到。", file=sys.stderr)
            return 1
        user_dn = result[0][0]
        try:
            self.conn.passwd(user_dn, new_password)
            # 更新 shadowLastChange
            today = int(datetime.now().timestamp() / 86400)
            self.conn.modify(user_dn, [(ldap.MOD_REPLACE, 'shadowLastChange', str(today).encode())])
            print(f"用户 '{username}' 密码修改成功。")
            logging.info(f"Password changed: {username}")
            return 0
        except ldap.LDAPError as e:
            print(f"错误: 密码修改失败: {e}", file=sys.stderr)
            return 2


#------------------------------------------------------------------------------
# 组管理
#------------------------------------------------------------------------------

class GroupManager:
    """组管理操作"""

    def __init__(self, conn):
        self.conn = conn

    def add(self, name, gid=0, description='', dry_run=False):
        """创建组"""
        name = validate_group_name(name)

        if self.conn.group_exists(name):
            print(f"错误: 组 '{name}' 已存在。", file=sys.stderr)
            return 3

        if not gid:
            gid = self.conn.get_next_gid()

        group_dn = f'cn={name},{config.group_base}'

        # ── dry-run 模式 ──
        if dry_run:
            print(f"  [DRY-RUN] 将创建主组: {name} (GID: {gid}, DN: {group_dn})")
            return 0

        group_attrs = {
            'objectClass': [b'top', b'posixGroup'],
            'cn': [name.encode()],
            'gidNumber': [str(gid).encode()],
        }
        if description:
            group_attrs['description'] = [description.encode()]

        try:
            self.conn.add(group_dn, group_attrs)
            print(f"组 '{name}' 创建成功 (GID: {gid})。")
            logging.info(f"Group created: {name} (gid={gid})")
            return 0
        except ldap.LDAPError as e:
            print(f"错误: 创建组失败: {e}", file=sys.stderr)
            return 2

    def delete(self, name, force=False):
        """删除组"""
        name = validate_group_name(name)

        if not self.conn.group_exists(name):
            print(f"组 '{name}' 未找到。", file=sys.stderr)
            return 1

        # 检查成员
        result = self.conn.search(config.group_base, f'(cn={ldap_filter_escape(name)})', ['memberUid'])
        if result:
            members = result[0][1].get('memberUid', [])
            if members:
                print("警告: 该组包含以下成员:")
                for m in members:
                    print(f"  - {m.decode()}")

        if not force and not confirm_action(f"确认删除组 '{name}'？"):
            print("已取消。")
            return 0

        group_dn = f'cn={name},{config.group_base}'
        try:
            self.conn.delete(group_dn)
            print(f"组 '{name}' 已删除。")
            logging.info(f"Group deleted: {name}")
            return 0
        except ldap.LDAPError as e:
            print(f"错误: 删除组失败: {e}", file=sys.stderr)
            return 2

    def search(self, name):
        """搜索组并显示信息"""
        name = validate_group_name(name)

        result = self.conn.search(config.search_base, f'(cn={ldap_filter_escape(name)})',
                                  ['cn', 'gidNumber', 'memberUid', 'description', 'dn'])
        if not result:
            print(f"组 '{name}' 未找到。", file=sys.stderr)
            return 1

        dn, attrs = result[0]

        def get_attr(attr):
            val = attrs.get(attr, [b''])
            if attr == 'memberUid':
                return [v.decode() for v in val if v]
            return val[0].decode() if val and val[0] else ''

        gid = get_attr('gidNumber')
        desc = get_attr('description')
        members = get_attr('memberUid')

        print("========================================")
        print(f"  组信息: {name}")
        print("========================================")
        print(f"  DN:                    {dn}")
        print(f"  GID:                   {gid}")
        print(f"  描述:                  {desc if desc else '(无)'}")
        print(f"  成员数:                {len(members)}")
        if members:
            print(f"  成员列表:")
            for m in members:
                print(f"    - {m}")
        print("========================================")
        return 0


#------------------------------------------------------------------------------
# 批量操作
#------------------------------------------------------------------------------

class BatchManager:
    """批量用户操作"""

    def __init__(self, conn):
        self.conn = conn
        self.um = UserManager(conn)

    def add_users(self, filepath):
        """批量导入用户
        文件格式: uid,group[,shell[,password[,home[,groups]]]]
        """
        if not os.path.isfile(filepath):
            print(f"错误: 文件未找到: {filepath}", file=sys.stderr)
            return 1

        success = 0
        failed = 0

        with open(filepath, 'r') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 2:
                    print(f"警告: 第 {line_no} 行格式无效（至少需要 uid,group）: {line}")
                    failed += 1
                    continue

                uid = parts[0]
                group = parts[1]
                kwargs = {'group': group}

                field_map = {2: 'shell', 3: 'password', 4: 'home', 5: 'groups'}
                for i, key in field_map.items():
                    if len(parts) > i and parts[i]:
                        kwargs[key] = parts[i]

                try:
                    ret = self.um.add(uid, **kwargs)
                    if ret == 0:
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    print(f"错误: 第 {line_no} 行导入失败: {e}")
                    failed += 1

        print(f"\n批量导入完成: 成功 {success}, 失败 {failed}")
        return 0 if failed == 0 else 1

    def del_users(self, filepath):
        """批量删除用户
        文件格式: 每行一个 uid
        """
        if not os.path.isfile(filepath):
            print(f"错误: 文件未找到: {filepath}", file=sys.stderr)
            return 1

        success = 0
        failed = 0

        with open(filepath, 'r') as f:
            for line in f:
                uid = line.split(',')[0].strip()
                if not uid or uid.startswith('#'):
                    continue

                try:
                    ret = self.um.delete(uid, force=True, remove_groups=True, backup_home=True)
                    if ret == 0:
                        success += 1
                    else:
                        failed += 1
                except Exception as e:
                    print(f"错误: 删除 '{uid}' 失败: {e}")
                    failed += 1

        print(f"\n批量删除完成: 成功 {success}, 失败 {failed}")
        return 0 if failed == 0 else 1


#------------------------------------------------------------------------------
# automount 管理（NFS 自动挂载条目）
#------------------------------------------------------------------------------

class AutomountManager:
    """autofs/NFS 挂载条目管理"""

    def __init__(self, conn):
        self.conn = conn
        self.base = f'nisMapName=auto.nfs,ou=automapper,{config.suffix}'

    def add(self, mount_path, target, opts='vers=3,rw', dry_run=False):
        """添加挂载条目"""
        if not mount_path.startswith('/'):
            print("错误: 挂载路径必须以 / 开头。", file=sys.stderr)
            return 1

        dn = f'cn={mount_path},{self.base}'
        nis_map_entry = f'-fstype=nfs,{opts} {target}'

        if dry_run:
            print()
            print("┌──────────────────────────────────────────┐")
            print("│  DRY-RUN 预演 — 将添加以下挂载条目         │")
            print("├──────────────────────────────────────────┤")
            print(f"│  挂载路径:       {mount_path}")
            print(f"│  DN:             {dn}")
            print(f"│  NFS 目标:       {target}")
            print(f"│  挂载选项:       {opts}")
            print(f"│  nisMapEntry:    {nis_map_entry}")
            print("└──────────────────────────────────────────┘")
            print()
            print("提示: 去掉 --dry-run / -n 参数以实际添加。")
            return 0

        attrs = {
            'objectClass': [b'top', b'nisObject'],
            'cn': [mount_path.encode()],
            'nisMapEntry': [nis_map_entry.encode()],
            'nisMapName': [b'auto.nfs'],
        }

        try:
            self.conn.add(dn, attrs)
            print(f"挂载条目已添加: {mount_path} → {target}")
            print(f"  DN: {dn}")
            logging.info(f"Automount entry added: {mount_path} -> {target}")
            return 0
        except ldap.ALREADY_EXISTS:
            print(f"错误: 挂载条目 '{mount_path}' 已存在。", file=sys.stderr)
            return 3
        except ldap.LDAPError as e:
            print(f"错误: 添加失败: {e}", file=sys.stderr)
            return 2

    def delete(self, mount_path, dry_run=False):
        """删除挂载条目"""
        dn = f'cn={mount_path},{self.base}'

        result = self.conn.search(self.base, f'(cn={ldap_filter_escape(mount_path)})', ['dn', 'nisMapEntry'])
        if not result:
            print(f"错误: 挂载条目 '{mount_path}' 未找到。", file=sys.stderr)
            return 1

        if dry_run:
            dn = result[0][0]
            entry = result[0][1].get('nisMapEntry', [b''])[0].decode()
            print()
            print("┌──────────────────────────────────────────┐")
            print("│  DRY-RUN 预演 — 将删除以下挂载条目         │")
            print("├──────────────────────────────────────────┤")
            print(f"│  挂载路径:       {mount_path}")
            print(f"│  DN:             {dn}")
            print(f"│  nisMapEntry:    {entry}")
            print("└──────────────────────────────────────────┘")
            print()
            print("提示: 去掉 --dry-run / -n 参数以实际删除。")
            return 0

        try:
            self.conn.delete(dn)
            print(f"挂载条目已删除: {mount_path}")
            logging.info(f"Automount entry deleted: {mount_path}")
            return 0
        except ldap.LDAPError as e:
            print(f"错误: 删除失败: {e}", file=sys.stderr)
            return 2

    def list(self):
        """列出所有挂载条目"""
        result = self.conn.search(self.base, '(objectClass=nisObject)', ['cn', 'nisMapEntry'])
        if not result:
            print("(无挂载条目)")
            return 0

        print(f"{'挂载路径':<45} {'目标/选项'}")
        print("-" * 100)
        for dn, attrs in result:
            cn = attrs.get('cn', [b''])[0].decode()
            entry = attrs.get('nisMapEntry', [b''])[0].decode()
            print(f"{cn:<45} {entry}")
        print(f"\n共 {len(result)} 个条目。")
        return 0


#------------------------------------------------------------------------------
# CLI 入口
#------------------------------------------------------------------------------

def build_parser():
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description='LDAP 统一管理工具 — 用户、组、批量操作',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', help='子命令')

    # ── user add ──
    ua = sub.add_parser('user', help='用户管理').add_subparsers(dest='subcommand')
    ua_add = ua.add_parser('add', help='创建用户')
    ua_add.add_argument('username', help='用户名')
    ua_add.add_argument('--group', '-g', help='主组名（默认与用户名相同）')
    ua_add.add_argument('--groups', '-G', help='附加组，逗号分隔')
    ua_add.add_argument('--shell', '-s', default=config.default_shell, help=f'登录 Shell（默认: {config.default_shell}）')
    ua_add.add_argument('--password', '--passwd', '-p', help='密码（不指定则随机生成，含特殊字符请加引号）')
    ua_add.add_argument('--home', '-d', help='家目录')
    ua_add.add_argument('--uid', '-u', type=int, default=0, help='指定 UID（0=自动分配）')
    ua_add.add_argument('--gid', type=int, default=0, help='指定 GID（0=自动分配）')
    ua_add.add_argument('--ou', help='所属 OU（如 rd, dv, sw，默认: People）')
    ua_add.add_argument('--mail', '-m', help='邮箱（默认: <uid>@example.com，传空字符串则不设置）')
    ua_add.add_argument('--phone', '-t', help='电话号码')
    ua_add.add_argument('--disabled', action='store_true', help='创建为禁用状态')
    ua_add.add_argument('--must-change', action='store_true', help='首次登录强制修改密码')
    ua_add.add_argument('--expire', '-e', help='过期日期 (YYYY-MM-DD)')
    ua_add.add_argument('--max-days', type=int, default=config.shadow_max_days, help=f'密码有效天数（默认: {config.shadow_max_days}）')
    ua_add.add_argument('--dry-run', '-n', action='store_true', help='预演模式：仅显示将要创建的信息，不实际写入 LDAP')

    # ── user mod ──
    ua_mod = ua.add_parser('mod', help='修改用户')
    ua_mod.add_argument('username', help='用户名')
    ua_mod.add_argument('action', choices=['enable', 'disable', 'expire', 'expire-date', 'max-days', 'lock', 'unlock', 'pwd-expire', 'shell', 'home', 'status'],
                        help='操作: enable/disable/expire/lock/unlock/pwd-expire/shell/home/status')
    ua_mod.add_argument('value', nargs='?', help='操作参数（如 shell 路径、家目录、过期日期 YYYY-MM-DD）')
    ua_mod.add_argument('--dry-run', '-n', action='store_true', help='预演模式：仅显示将要修改的信息，不实际写入 LDAP')

    # ── user del ──
    ua_del = ua.add_parser('del', help='删除用户')
    ua_del.add_argument('username', help='用户名')
    ua_del.add_argument('--force', '-f', action='store_true', help='跳过确认')
    ua_del.add_argument('--remove-groups', '-r', action='store_true', help='从所有组中移除')
    ua_del.add_argument('--backup-home', '-b', action='store_true', help='备份家目录')

    # ── user search ──
    ua_search = ua.add_parser('search', help='搜索用户')
    ua_search.add_argument('username', help='用户名')

    # ── user passwd ──
    ua_passwd = ua.add_parser('passwd', help='修改用户密码')
    ua_passwd.add_argument('username', help='用户名')
    ua_passwd.add_argument('--password', '--passwd', '-p', help='新密码（不指定则交互式输入，含特殊字符请加引号）')

    # ── group ──
    gp = sub.add_parser('group', help='组管理').add_subparsers(dest='subcommand')
    gp_add = gp.add_parser('add', help='创建组')
    gp_add.add_argument('name', help='组名')
    gp_add.add_argument('--gid', '-g', type=int, default=0, help='指定 GID（0=自动分配）')
    gp_add.add_argument('--description', '-d', help='组描述')
    gp_add.add_argument('--dry-run', '-n', action='store_true', help='预演模式：仅显示将要创建的信息，不实际写入 LDAP')

    gp_del = gp.add_parser('del', help='删除组')
    gp_del.add_argument('name', help='组名')
    gp_del.add_argument('--force', '-f', action='store_true', help='跳过确认')

    gp_search = gp.add_parser('search', help='搜索组')
    gp_search.add_argument('name', help='组名')

    # ── batch ──
    ba = sub.add_parser('batch', help='批量操作').add_subparsers(dest='subcommand')
    ba_add = ba.add_parser('add', help='批量导入用户')
    ba_add.add_argument('file', help='CSV 文件路径（格式: uid,group[,shell[,password[,home[,groups]]]]）')

    ba_del = ba.add_parser('del', help='批量删除用户')
    ba_del.add_argument('file', help='文件路径（每行一个 uid）')

    # ── automount ──
    am = sub.add_parser('automount', help='autofs 挂载管理').add_subparsers(dest='subcommand')
    am_add = am.add_parser('add', help='添加 NFS 挂载条目')
    am_add.add_argument('mount_path', help='挂载路径（如 /share/reg_scratch/gtl）')
    am_add.add_argument('--target', '-t', required=True, help='NFS 目标（如 nfs01.example.com:/gtl）')
    am_add.add_argument('--opts', '-o', default='vers=3,rw', help='挂载选项（默认: vers=3,rw）')
    am_add.add_argument('--dry-run', '-n', action='store_true', help='预演模式：仅显示将要添加的信息，不实际写入 LDAP')

    am_del = am.add_parser('del', help='删除 NFS 挂载条目')
    am_del.add_argument('mount_path', help='挂载路径')
    am_del.add_argument('--dry-run', '-n', action='store_true', help='预演模式：仅显示将要删除的信息')

    am_list = am.add_parser('list', help='列出所有 NFS 挂载条目')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # 提示输入管理员密码
    if not config.root_pw:
        config.root_pw = prompt_password("请输入 LDAP 管理员密码 (cn=Manager): ")

    # 连接 LDAP
    conn = LDAPConnection()
    try:
        conn.connect()
    except ldap.LDAPError as e:
        print(f"错误: 无法连接 LDAP 服务器: {e}", file=sys.stderr)
        return 2

    try:
        # 路由到对应的管理器
        if args.command == 'user':
            um = UserManager(conn)
            if args.subcommand == 'add':
                return um.add(args.username,
                              group=args.group or args.username,
                              groups=args.groups or '',
                              shell=args.shell,
                              password=args.password,
                              home=args.home,
                              uid=args.uid,
                              gid=args.gid,
                              mail=args.mail,
                              phone=args.phone or '',
                              disabled=args.disabled,
                              must_change=args.must_change,
                              expire=args.expire or '',
                              max_days=args.max_days,
                              ou=args.ou or '',
                              dry_run=args.dry_run)
            elif args.subcommand == 'mod':
                return um.modify(args.username, args.action, args.value, dry_run=args.dry_run)
            elif args.subcommand == 'del':
                return um.delete(args.username, force=args.force,
                                 remove_groups=args.remove_groups,
                                 backup_home=args.backup_home)
            elif args.subcommand == 'search':
                return um.search(args.username)
            elif args.subcommand == 'passwd':
                return um.change_password(args.username, args.password)

        elif args.command == 'group':
            gm = GroupManager(conn)
            if args.subcommand == 'add':
                return gm.add(args.name, gid=args.gid, description=args.description or '', dry_run=args.dry_run)
            elif args.subcommand == 'del':
                return gm.delete(args.name, force=args.force)
            elif args.subcommand == 'search':
                return gm.search(args.name)

        elif args.command == 'batch':
            bm = BatchManager(conn)
            if args.subcommand == 'add':
                return bm.add_users(args.file)
            elif args.subcommand == 'del':
                return bm.del_users(args.file)

        elif args.command == 'automount':
            am = AutomountManager(conn)
            if args.subcommand == 'add':
                return am.add(args.mount_path, args.target, args.opts, dry_run=args.dry_run)
            elif args.subcommand == 'del':
                return am.delete(args.mount_path, dry_run=args.dry_run)
            elif args.subcommand == 'list':
                return am.list()

        else:
            parser.print_help()
            return 1

    finally:
        conn.close()


if __name__ == '__main__':
    sys.exit(main())
