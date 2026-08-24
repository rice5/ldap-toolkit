#!/usr/bin/env python3
#===============================================================================
# LDAP 管理员 Web 管理站点 (ldap_admin_web.py)
#
# 面向管理员的 Web 站点，管理 user / group（重点）、批量操作、automount、sudo 策略。
# 参考 admin/ldapadmin.py 的功能，提供图形化界面。
#
# 技术栈：Python3 标准库 (http.server) + 系统 ldapsearch/ldapmodify 命令。
#   零第三方依赖，与 password_expiry_notify.py / pwd_change_audit_sync.py 风格一致。
#   可运行于 Python 3.6+（CentOS 7）与 Python 3.12（本机）。
#
# 架构：
#   管理员浏览器 → nginx(443) → 本服务(127.0.0.1:PORT)
#                                 ├─ 独立管理员账号登录（与 LDAP 账号分离）
#                                 ├─ Manager 凭据仅存服务端，绝不暴露给前端
#                                 └─ LDAP 操作走系统 ldapsearch/ldapmodify
#
# 用法：
#   python3 ldap_admin_web.py                     # 读取 config/ldap_admin_web.env
#   LDAP_ADMIN_WEB_ENV=/path/env python3 ldap_admin_web.py
#
# 配置（env 文件，key=value，注释 #）：
#   WEB_LISTEN / WEB_PORT          监听地址/端口（默认 127.0.0.1:8080）
#   ADMIN_USERNAME / ADMIN_PASSWORD  管理员登录账号（与 LDAP 分离）
#   SESSION_TIMEOUT                  会话超时秒数（默认 28800 = 8h）
#   LDAP_HOST / LDAP_PORT / LDAP_SUFFIX / LDAP_MANAGER_DN / LDAP_MANAGER_PW
#   LDAP_TLS_CACERT                  CA 证书路径
#   LDAP_USER_BASE / LDAP_GROUP_BASE  用户/组 DN 基址
#   DEFAULT_SHELL / DEFAULT_HOME_BASE / MAIL_DOMAIN / UID_MIN
#   SHADOW_MAX_DAYS / SHADOW_WARN_DAYS / SHADOW_INACTIVE
#===============================================================================

import base64
import hashlib
import json
import os
import re
import secrets
import string
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

try:
    from socketserver import ThreadingMixIn
    class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
except ImportError:  # pragma: no cover
    _ThreadingHTTPServer = HTTPServer  # type: ignore


#===============================================================================
# 配置
#===============================================================================

class Config(object):
    def __init__(self, env_path=None):
        # 默认值（占位符；生产真实值从 env 文件注入）
        self.web_listen = "127.0.0.1"
        self.web_port = 8080
        self.admin_username = ""
        self.admin_password = ""
        self.session_timeout = 28800

        self.ldap_host = "ldap01.example.com"
        self.ldap_port = "636"
        self.ldap_suffix = "dc=example,dc=com"
        self.ldap_manager_dn = "cn=Manager,dc=example,dc=com"
        self.ldap_manager_pw = ""
        self.ldap_manager_pw_file = ""   # 可选：从密码文件读取（优先于明文 LDAP_MANAGER_PW）
        self.ldap_tls_cacert = "/etc/openldap/certs/ca.crt"

        self.ldap_user_base = "ou=People,dc=example,dc=com"
        self.ldap_group_base = "ou=Group,dc=example,dc=com"

        self.default_shell = "/bin/csh"
        self.default_home_base = "/share/home"
        self.mail_domain = "example.com"
        self.uid_min = 5000

        self.shadow_max_days = 90
        self.shadow_warn_days = 7
        self.shadow_inactive = 30

        self._load_env(env_path)

    def _load_env(self, env_path):
        candidates = []
        if env_path:
            candidates.append(env_path)
        candidates.append(os.environ.get("LDAP_ADMIN_WEB_ENV", ""))
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # 脚本同目录（部署到 /opt/ldap-admin-web/ 时配置与脚本同目录）
        candidates.append(os.path.join(script_dir, "ldap_admin_web.env"))
        # 项目 config 目录（源码树开发时 config/ldap_admin_web.env）
        candidates.append(os.path.join(script_dir, "..", "config", "ldap_admin_web.env"))
        for p in candidates:
            if p and os.path.isfile(p):
                self._parse_env_file(p)
                break

        # 环境变量优先覆盖
        self._apply_env_overrides()

        # 若配置了密码文件路径，优先从文件读取 Manager 密码（避免明文落盘两份）
        if self.ldap_manager_pw_file and os.path.isfile(self.ldap_manager_pw_file):
            with open(self.ldap_manager_pw_file) as f:
                self.ldap_manager_pw = f.read().strip()

    def _parse_env_file(self, path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                self._set(key, val)

    def _apply_env_overrides(self):
        overrides = {
            "WEB_LISTEN": "web_listen", "WEB_PORT": "web_port",
            "ADMIN_USERNAME": "admin_username", "ADMIN_PASSWORD": "admin_password",
            "SESSION_TIMEOUT": "session_timeout",
            "LDAP_HOST": "ldap_host", "LDAP_PORT": "ldap_port",
            "LDAP_SUFFIX": "ldap_suffix", "LDAP_MANAGER_DN": "ldap_manager_dn",
            "LDAP_MANAGER_PW": "ldap_manager_pw", "LDAP_TLS_CACERT": "ldap_tls_cacert",
            "LDAP_MANAGER_PW_FILE": "ldap_manager_pw_file",
            "LDAP_USER_BASE": "ldap_user_base", "LDAP_GROUP_BASE": "ldap_group_base",
            "DEFAULT_SHELL": "default_shell", "DEFAULT_HOME_BASE": "default_home_base",
            "MAIL_DOMAIN": "mail_domain", "UID_MIN": "uid_min",
            "SHADOW_MAX_DAYS": "shadow_max_days", "SHADOW_WARN_DAYS": "shadow_warn_days",
            "SHADOW_INACTIVE": "shadow_inactive",
        }
        for env_key, attr in overrides.items():
            if env_key in os.environ:
                self._set(attr, os.environ[env_key])

    def _set(self, key, val):
        if key in ("WEB_PORT", "SESSION_TIMEOUT", "UID_MIN",
                   "SHADOW_MAX_DAYS", "SHADOW_WARN_DAYS", "SHADOW_INACTIVE"):
            try:
                setattr(self, key.lower() if key.isupper() else key, int(val))
                return
            except ValueError:
                pass
        # 大写 KEY → 小写属性名
        attr = key.lower()
        if hasattr(self, attr):
            setattr(self, attr, val)


#===============================================================================
# 工具函数（与 ldapadmin.py 保持一致）
#===============================================================================

def ldap_filter_escape(value):
    """转义 LDAP 过滤器特殊字符"""
    return value.replace("\\", "\\5c").replace("*", "\\2a") \
                .replace("(", "\\28").replace(")", "\\29") \
                .replace("\x00", "\\00")


def validate_username(username):
    if not re.match(r"^[a-z][a-z0-9._-]{0,31}$", username):
        raise ValueError("用户名必须以小写字母开头，最多 32 个字符（字母、数字、点、下划线、连字符）")
    return username.lower()


def validate_group_name(name):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9._-]{0,31}$", name):
        raise ValueError("组名必须以字母开头，最多 32 个字符")
    return name


def validate_password_strength(password, username=""):
    errors = []
    if len(password) < 8:
        errors.append("密码长度至少 8 个字符")
    if not re.search(r"[A-Z]", password):
        errors.append("密码必须包含至少一个大写字母")
    if not re.search(r"[a-z]", password):
        errors.append("密码必须包含至少一个小写字母")
    if not re.search(r"[0-9]", password):
        errors.append("密码必须包含至少一个数字")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        errors.append("密码必须包含至少一个特殊字符")
    if username and username.lower() in password.lower():
        errors.append("密码不能包含用户名")
    return errors


def generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    pw = "".join(secrets.choice(chars) for _ in range(length))
    if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw) and
            any(c.isdigit() for c in pw) and any(c in "!@#$%" for c in pw)):
        return generate_password(length)
    return pw


def ssha_hash(password):
    """生成 {SSHA} 密码哈希（与 ldapadmin.py 一致）"""
    salt = os.urandom(4)
    sha = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(sha + salt).decode()


def epoch_days_utc(date_str=None):
    """返回 shadowLastChange 语义的 UTC 天数。指定日期时按该日 UTC 午夜。"""
    if date_str:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return int(dt.timestamp() / 86400)
    return int(datetime.now(timezone.utc).timestamp() / 86400)


def days_to_date(days):
    return datetime.fromtimestamp(int(days) * 86400, tz=timezone.utc).strftime("%Y-%m-%d")


#===============================================================================
# LDAP 封装（系统 ldapsearch / ldapmodify）
#===============================================================================

class LDAPError(Exception):
    pass


class LDAPClient(object):
    def __init__(self, config):
        self.cfg = config
        self.uri = "ldaps://{}:{}".format(config.ldap_host, config.ldap_port)

    def _env(self):
        env = dict(os.environ)
        env["LDAPTLS_CACERT"] = self.cfg.ldap_tls_cacert
        return env

    def _run(self, cmd, input_text=None, timeout=60):
        """运行 LDAP 命令，返回 (returncode, stdout, stderr)。密码经 -y 文件，不落命令行。"""
        import tempfile
        pwfile = None
        try:
            # Manager 密码写临时文件（600）
            if self.cfg.ldap_manager_pw:
                with tempfile.NamedTemporaryFile("w", delete=False) as f:
                    f.write(self.cfg.ldap_manager_pw)
                    pwfile = f.name
                os.chmod(pwfile, 0o600)
            r = subprocess.run(
                cmd, input=input_text,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=timeout, env=self._env(),
            )
            return r.returncode, r.stdout, r.stderr
        finally:
            if pwfile:
                os.remove(pwfile)

    # -- 查询 --
    def search(self, base, filter_str, attrs, scope="sub"):
        """返回 [(dn, {attr: [value,...]})]，解析 base64 属性。"""
        import tempfile
        pwfile = None
        try:
            if self.cfg.ldap_manager_pw:
                with tempfile.NamedTemporaryFile("w", delete=False) as f:
                    f.write(self.cfg.ldap_manager_pw)
                    pwfile = f.name
                os.chmod(pwfile, 0o600)
            cmd = ["ldapsearch", "-x", "-LLL", "-H", self.uri,
                   "-D", self.cfg.ldap_manager_dn]
            if pwfile:
                cmd += ["-y", pwfile]
            cmd += ["-b", base, "-s", scope, filter_str] + attrs
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=60, env=self._env())
        finally:
            if pwfile:
                os.remove(pwfile)

        if r.returncode != 0 and r.returncode != 32:  # 32 = no such object
            raise LDAPError("ldapsearch 失败: " + r.stderr.strip()[:500])
        return self._parse_ldif(r.stdout)

    @staticmethod
    def _parse_ldif(text):
        """解析 ldapsearch -LLL 输出为 [(dn, {attr: [values]})]，支持 base64。"""
        results = []
        cur_dn = None
        cur_attrs = {}
        for line in text.splitlines():
            if not line.strip():
                if cur_dn is not None:
                    results.append((cur_dn, cur_attrs))
                    cur_dn = None
                    cur_attrs = {}
                continue
            if line.startswith(" "):  # 续行，忽略（我们的属性值不跨行）
                continue
            if line.startswith("dn:"):
                cur_dn = line[3:].strip()
                continue
            if ":" in line:
                key, sep, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                if sep == "::":  # base64
                    try:
                        val = base64.b64decode(val).decode("utf-8", "replace")
                    except Exception:
                        pass
                cur_attrs.setdefault(key, []).append(val)
        if cur_dn is not None:
            results.append((cur_dn, cur_attrs))
        return results

    def search_one(self, base, filter_str, attrs):
        r = self.search(base, filter_str, attrs)
        return r[0] if r else None

    # -- 修改/添加/删除 --
    def modify(self, dn, changes):
        """changes = [(op, attr, value|None)] op: add/delete/replace"""
        lines = ["dn: " + dn, "changetype: modify"]
        for op, attr, value in changes:
            lines.append("{}: {}".format(op, attr))
            if value is not None:
                lines.append("{}: {}".format(attr, value))
            lines.append("-")
        ldif = "\n".join(lines) + "\n"
        rc, out, err = self._run(
            ["ldapmodify", "-x", "-H", self.uri, "-D", self.cfg.ldap_manager_dn,
             "-y", "/dev/stdin" if False else "-"], input_text=ldif)
        # ldapmodify 不能用 -y /dev/stdin，改用 -w 通过管道读密码会有 ps 泄露。
        # 这里用更安全方式：重新实现，密码文件 + LDIF 文件。
        return self._modify_via_files(dn, changes)

    def _modify_via_files(self, dn, changes):
        import tempfile
        lines = ["dn: " + dn, "changetype: modify"]
        for op, attr, value in changes:
            lines.append("{}: {}".format(op, attr))
            if value is not None:
                lines.append("{}: {}".format(attr, value))
            lines.append("-")
        ldif = "\n".join(lines) + "\n"
        ldif_path = pw_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".ldif") as f:
                f.write(ldif)
                ldif_path = f.name
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(self.cfg.ldap_manager_pw)
                pw_path = f.name
            os.chmod(pw_path, 0o600)
            cmd = ["ldapmodify", "-x", "-H", self.uri,
                   "-D", self.cfg.ldap_manager_dn, "-y", pw_path, "-f", ldif_path]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=60, env=self._env())
            if r.returncode != 0:
                raise LDAPError("ldapmodify 失败: " + r.stderr.strip()[:500])
            return r.stdout
        finally:
            if ldif_path:
                os.remove(ldif_path)
            if pw_path:
                os.remove(pw_path)

    def add(self, dn, attrs):
        """attrs = [(attr, [values])]"""
        lines = ["dn: " + dn]
        for attr, values in attrs:
            for v in values:
                lines.append("{}: {}".format(attr, v))
        ldif = "\n".join(lines) + "\n"
        import tempfile
        ldif_path = pw_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".ldif") as f:
                f.write(ldif)
                ldif_path = f.name
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(self.cfg.ldap_manager_pw)
                pw_path = f.name
            os.chmod(pw_path, 0o600)
            cmd = ["ldapadd", "-x", "-H", self.uri,
                   "-D", self.cfg.ldap_manager_dn, "-y", pw_path, "-f", ldif_path]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=60, env=self._env())
            if r.returncode != 0:
                raise LDAPError("ldapadd 失败: " + r.stderr.strip()[:500])
            return r.stdout
        finally:
            if ldif_path:
                os.remove(ldif_path)
            if pw_path:
                os.remove(pw_path)

    def delete(self, dn):
        import tempfile
        pw_path = None
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(self.cfg.ldap_manager_pw)
                pw_path = f.name
            os.chmod(pw_path, 0o600)
            cmd = ["ldapdelete", "-x", "-H", self.uri,
                   "-D", self.cfg.ldap_manager_dn, "-y", pw_path, dn]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=60, env=self._env())
            if r.returncode != 0:
                raise LDAPError("ldapdelete 失败: " + r.stderr.strip()[:500])
            return r.stdout
        finally:
            if pw_path:
                os.remove(pw_path)


#===============================================================================
# 业务逻辑（user / group）
#===============================================================================

class BusinessLogic(object):
    def __init__(self, config):
        self.cfg = config
        self.ldap = LDAPClient(config)

    # ---- 通用 ----
    def get_next_id(self):
        """扫描 uidNumber + gidNumber，取 max+1（uid==gid 策略）"""
        max_id = self.cfg.uid_min - 1
        for base, objclass, attr in [
            (self.cfg.ldap_user_base, "posixAccount", "uidNumber"),
            (self.cfg.ldap_group_base, "posixGroup", "gidNumber"),
        ]:
            try:
                for dn, attrs in self.ldap.search(base, "(objectClass={})".format(objclass), [attr]):
                    vals = attrs.get(attr, [])
                    for v in vals:
                        try:
                            max_id = max(max_id, int(v))
                        except ValueError:
                            pass
            except LDAPError:
                pass
        return max(max_id + 1, self.cfg.uid_min)

    def get_ous(self):
        """列出 People 下的所有 OU"""
        ous = []
        try:
            for dn, attrs in self.ldap.search(self.cfg.ldap_user_base, "(objectClass=organizationalUnit)", ["ou"]):
                for v in attrs.get("ou", []):
                    ous.append(v)
        except LDAPError:
            pass
        return sorted(ous)

    def extract_ou(self, dn):
        """从 DN 提取 OU（如 cn=x,ou=rd,ou=People,dc=.. → rd）"""
        m = re.search(r"ou=([^,]+),ou=People,", dn)
        return m.group(1) if m else ""

    # ---- 用户 ----
    def list_users(self, search="", ou=""):
        attrs = ["uid", "cn", "uidNumber", "gidNumber", "loginShell", "mail",
                 "shadowLastChange", "shadowMax", "shadowExpire"]
        base = self.cfg.ldap_user_base
        if ou:
            base = "ou={},{}".format(ldap_filter_escape(ou), self.cfg.ldap_user_base)
        filter_str = "(objectClass=posixAccount)"
        if search:
            filter_str = "(&(objectClass=posixAccount)(|(uid=*{}*)(cn=*{}*)(mail=*{}*)))".format(
                ldap_filter_escape(search), ldap_filter_escape(search), ldap_filter_escape(search))
        items = []
        for dn, attrs in self.ldap.search(base, filter_str, attrs):
            items.append(self._user_to_dict(dn, attrs))
        items.sort(key=lambda x: x["uid"])
        return items

    def _user_to_dict(self, dn, attrs):
        def one(k):
            v = attrs.get(k, [""])
            return v[0] if v else ""
        uid = one("uid")
        last_change = one("shadowLastChange")
        shadow_max = one("shadowMax")
        shadow_expire = one("shadowExpire")
        pwd_expire = ""
        if last_change and shadow_max and int(shadow_max) > 0 and last_change != "0":
            pwd_expire = days_to_date(int(last_change) + int(shadow_max))
        status = "启用"
        if shadow_expire == "1":
            status = "禁用"
        elif shadow_expire and int(shadow_expire) > 1:
            exp_days = int(shadow_expire)
            if exp_days < epoch_days_utc():
                status = "已过期"
            elif exp_days > 40000:  # 超过 ~2079 年，视为长期有效标记
                status = "启用"
            else:
                status = "启用(至{})".format(days_to_date(exp_days))
        return {
            "dn": dn, "uid": uid, "cn": one("cn"),
            "uidNumber": one("uidNumber"), "gidNumber": one("gidNumber"),
            "ou": self.extract_ou(dn),
            "loginShell": one("loginShell"), "mail": one("mail"),
            "shadowLastChange": last_change,
            "shadowMax": shadow_max,
            "shadowExpire": shadow_expire,
            "lastChangeDate": days_to_date(last_change) if last_change and last_change != "0" else "",
            "pwdExpireDate": pwd_expire,
            "status": status,
        }

    def get_user(self, uid):
        r = self.ldap.search_one(self.cfg.ldap_user_base,
                                 "(uid={})".format(ldap_filter_escape(uid)),
                                 ["uid", "cn", "uidNumber", "gidNumber", "loginShell", "mail",
                                  "mobile", "homeDirectory", "shadowLastChange", "shadowMax",
                                  "shadowWarning", "shadowInactive", "shadowExpire"])
        if not r:
            return None
        dn, attrs = r
        d = self._user_to_dict(dn, attrs)
        def one(k):
            v = attrs.get(k, [""])
            return v[0] if v else ""
        d["mobile"] = one("mobile")
        d["homeDirectory"] = one("homeDirectory")
        d["shadowWarning"] = one("shadowWarning")
        d["shadowInactive"] = one("shadowInactive")
        # 组成员
        groups = []
        for gdn, gattrs in self.ldap.search(self.cfg.ldap_group_base, "(objectClass=posixGroup)", ["cn", "memberUid"]):
            members = [m for m in gattrs.get("memberUid", [])]
            if uid in members:
                groups.append(gattrs.get("cn", [""])[0])
        d["groups"] = sorted(groups)
        return d

    def user_exists(self, uid):
        return self.ldap.search_one(self.cfg.ldap_user_base,
                                    "(uid={})".format(ldap_filter_escape(uid)), ["dn"]) is not None

    def group_exists(self, name):
        return self.ldap.search_one(self.cfg.ldap_group_base,
                                    "(cn={})".format(ldap_filter_escape(name)), ["dn"]) is not None

    def create_user(self, data):
        uid = validate_username(data.get("uid", ""))
        if self.user_exists(uid):
            raise LDAPError("用户 '{}' 已存在".format(uid))
        ou = data.get("ou", "")
        group = data.get("group") or uid
        shell = data.get("shell") or self.cfg.default_shell
        home = data.get("home") or "{}/{}".format(self.cfg.default_home_base, uid)
        mail = data.get("mail")
        if mail is None or mail == "":
            mail = "{}@{}".format(uid, self.cfg.mail_domain)
        phone = data.get("phone", "")
        disabled = bool(data.get("disabled", False))
        must_change = bool(data.get("must_change", False))
        expire = data.get("expire", "")
        max_days = int(data.get("max_days") or self.cfg.shadow_max_days)
        extra_groups = data.get("groups", "")
        password = data.get("password", "")
        gen_pw = ""
        if not password:
            password = generate_password()
            gen_pw = password

        # 分配 UID/GID（uid == gid）
        uid_num = self.get_next_id()
        gid_num = uid_num

        # 创建主组（若不存在）
        if not self.group_exists(group):
            validate_group_name(group)
            self.ldap.add("cn={},{}".format(group, self.cfg.ldap_group_base),
                          [("objectClass", ["top", "posixGroup"]),
                           ("cn", [group]), ("gidNumber", [str(gid_num)])])

        # 自动创建 OU（若指定且不存在）
        if ou:
            ou_dn = "ou={},{}".format(ldap_filter_escape(ou), self.cfg.ldap_user_base)
            if self.ldap.search_one(ou_dn, "(objectClass=*)", ["dn"]) is None:
                self.ldap.add(ou_dn, [("objectClass", ["top", "organizationalUnit"]), ("ou", [ou])])

        # 计算 ShadowAccount 属性
        today = epoch_days_utc()
        last_change = 0 if must_change else today
        expire_days = 1 if disabled else None
        if expire:
            expire_days = epoch_days_utc(expire)

        user_base = "ou={},{}".format(ldap_filter_escape(ou), self.cfg.ldap_user_base) if ou else self.cfg.ldap_user_base
        user_dn = "cn={},{}".format(uid, user_base)
        attrs = [
            ("objectClass", ["top", "inetOrgPerson", "posixAccount", "shadowAccount"]),
            ("uid", [uid]), ("cn", [uid]), ("sn", [uid]),
            ("uidNumber", [str(uid_num)]), ("gidNumber", [str(gid_num)]),
            ("homeDirectory", [home]), ("loginShell", [shell]),
            ("shadowLastChange", [str(last_change)]),
            ("shadowMax", [str(max_days)]),
            ("shadowWarning", [str(self.cfg.shadow_warn_days)]),
            ("shadowInactive", [str(self.cfg.shadow_inactive)]),
        ]
        if mail:
            attrs.append(("mail", [mail]))
        if phone:
            attrs.append(("mobile", [phone]))
        if expire_days is not None:
            attrs.append(("shadowExpire", [str(expire_days)]))
        self.ldap.add(user_dn, attrs)

        # 设置密码（SSHA）
        self.ldap.modify(user_dn, [("replace", "userPassword", ssha_hash(password))])

        # 加入附加组
        for g in (extra_groups or "").split(","):
            g = g.strip()
            if g:
                try:
                    self.ldap.modify("cn={},{}".format(g, self.cfg.ldap_group_base),
                                     [("add", "memberUid", uid)])
                except LDAPError:
                    pass

        return {"uid": uid, "uidNumber": uid_num, "gidNumber": gid_num,
                "generated_password": gen_pw}

    def modify_user(self, uid, data):
        if not self.user_exists(uid):
            raise LDAPError("用户 '{}' 未找到".format(uid))
        dn = "cn={},{}".format(uid, self._user_base_of(uid))
        changes = []
        for key, attr in [("shell", "loginShell"), ("home", "homeDirectory"),
                          ("mail", "mail"), ("phone", "mobile")]:
            if key in data and data[key] not in (None, ""):
                changes.append(("replace", attr, data[key]))
        if changes:
            self.ldap.modify(dn, changes)
        return True

    def _user_base_of(self, uid):
        r = self.ldap.search_one(self.cfg.ldap_user_base,
                                 "(uid={})".format(ldap_filter_escape(uid)), ["dn"])
        if not r:
            raise LDAPError("用户 '{}' 未找到".format(uid))
        dn = r[0]
        return dn.split(",", 1)[1] if "," in dn else self.cfg.ldap_user_base

    def user_dn(self, uid):
        r = self.ldap.search_one(self.cfg.ldap_user_base,
                                 "(uid={})".format(ldap_filter_escape(uid)), ["dn"])
        return r[0] if r else None

    def set_user_status(self, uid, action, value=""):
        dn = self.user_dn(uid)
        if not dn:
            raise LDAPError("用户 '{}' 未找到".format(uid))
        if action == "enable":
            self.ldap.modify(dn, [("delete", "shadowExpire", None),
                                  ("replace", "loginShell", self.cfg.default_shell)])
        elif action == "disable":
            self.ldap.modify(dn, [("replace", "shadowExpire", "1"),
                                  ("replace", "loginShell", "/sbin/nologin")])
        elif action == "lock":
            self.ldap.modify(dn, [("replace", "shadowMax", "0")])
        elif action == "unlock":
            self.ldap.modify(dn, [("replace", "shadowMax", str(self.cfg.shadow_max_days))])
        elif action == "pwd_expire":
            self.ldap.modify(dn, [("replace", "shadowLastChange", "0"),
                                  ("replace", "shadowMax", str(self.cfg.shadow_max_days))])
        elif action == "pwd_sync":
            days = epoch_days_utc(value if value else None)
            self.ldap.modify(dn, [("replace", "shadowLastChange", str(days))])
        else:
            raise LDAPError("未知操作: " + action)
        return True

    def set_user_password(self, uid, password):
        errors = validate_password_strength(password, uid)
        if errors:
            raise LDAPError("；".join(errors))
        dn = self.user_dn(uid)
        if not dn:
            raise LDAPError("用户 '{}' 未找到".format(uid))
        self.ldap.modify(dn, [("replace", "userPassword", ssha_hash(password))])
        today = epoch_days_utc()
        self.ldap.modify(dn, [("replace", "shadowLastChange", str(today))])
        return True

    def delete_user(self, uid, remove_groups=True):
        dn = self.user_dn(uid)
        if not dn:
            raise LDAPError("用户 '{}' 未找到".format(uid))
        if remove_groups:
            for gdn, gattrs in self.ldap.search(self.cfg.ldap_group_base, "(objectClass=posixGroup)", ["cn", "memberUid"]):
                if uid in gattrs.get("memberUid", []):
                    try:
                        self.ldap.modify(gdn, [("delete", "memberUid", uid)])
                    except LDAPError:
                        pass
        self.ldap.delete(dn)
        # 删除同名空主组（user private group，如 cn=webtest01,ou=Group）。
        # 仅当组名 == uid 且已无成员时删除，避免误删共享组。
        grp = self.ldap.search_one(self.cfg.ldap_group_base,
                                   "(cn={})".format(ldap_filter_escape(uid)),
                                   ["memberUid"])
        if grp:
            gdn, gattrs = grp
            members = [m for m in gattrs.get("memberUid", []) if m]
            if not members:
                try:
                    self.ldap.delete(gdn)
                except LDAPError:
                    pass
        return True

    # ---- 组 ----
    def list_groups(self, search=""):
        attrs = ["cn", "gidNumber", "description", "memberUid"]
        filter_str = "(objectClass=posixGroup)"
        if search:
            filter_str = "(&(objectClass=posixGroup)(|(cn=*{}*)(description=*{}*)))".format(
                ldap_filter_escape(search), ldap_filter_escape(search))
        items = []
        for dn, attrs in self.ldap.search(self.cfg.ldap_group_base, filter_str, attrs):
            members = attrs.get("memberUid", [])
            items.append({
                "dn": dn,
                "cn": attrs.get("cn", [""])[0],
                "gidNumber": attrs.get("gidNumber", [""])[0],
                "description": attrs.get("description", [""])[0] if attrs.get("description") else "",
                "memberCount": len(members),
            })
        items.sort(key=lambda x: x["cn"])
        return items

    def get_group(self, name):
        r = self.ldap.search_one(self.cfg.ldap_group_base,
                                 "(cn={})".format(ldap_filter_escape(name)),
                                 ["cn", "gidNumber", "description", "memberUid"])
        if not r:
            return None
        dn, attrs = r
        return {
            "dn": dn,
            "cn": attrs.get("cn", [""])[0],
            "gidNumber": attrs.get("gidNumber", [""])[0],
            "description": attrs.get("description", [""])[0] if attrs.get("description") else "",
            "members": sorted(attrs.get("memberUid", [])),
        }

    def create_group(self, data):
        name = validate_group_name(data.get("name", ""))
        if self.group_exists(name):
            raise LDAPError("组 '{}' 已存在".format(name))
        gid = int(data.get("gid") or 0)
        if not gid:
            gid = self.get_next_id()
        attrs = [("objectClass", ["top", "posixGroup"]), ("cn", [name]),
                 ("gidNumber", [str(gid)])]
        if data.get("description"):
            attrs.append(("description", [data["description"]]))
        self.ldap.add("cn={},{}".format(name, self.cfg.ldap_group_base), attrs)
        return {"name": name, "gidNumber": gid}

    def delete_group(self, name):
        if not self.group_exists(name):
            raise LDAPError("组 '{}' 未找到".format(name))
        self.ldap.delete("cn={},{}".format(name, self.cfg.ldap_group_base))
        return True

    def modify_group_members(self, name, action, members):
        if action not in ("add", "remove"):
            raise LDAPError("未知操作: " + action)
        op = "add" if action == "add" else "delete"  # LDAP 操作类型是 add/delete，非 remove
        if not self.group_exists(name):
            raise LDAPError("组 '{}' 未找到".format(name))
        dn = "cn={},{}".format(name, self.cfg.ldap_group_base)
        for m in members:
            try:
                self.ldap.modify(dn, [(op, "memberUid", m)])
            except LDAPError as e:
                raise LDAPError("成员 '{}' 操作失败: {}".format(m, e))
        return True


#===============================================================================
# HTTP 服务
#===============================================================================

# session 存储：token -> expiry
_SESSIONS = {}


class AdminWebHandler(BaseHTTPRequestHandler):
    server_version = "LDAPAdminWeb/1.0"
    logic = None   # type: ignore  # 由 main() 注入 BusinessLogic 实例
    config = None  # type: ignore  # 由 main() 注入 Config 实例

    # ---- 工具 ----
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except IOError:
            self._send_json({"error": "文件未找到"}, 404)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except ValueError:
            return {}

    def _require_auth(self):
        token = self.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token[7:]
        if not token:
            token = self.headers.get("X-Auth-Token", "")
        if not token or token not in _SESSIONS:
            self._send_json({"error": "未登录或会话已过期"}, 401)
            return None
        if _SESSIONS[token] < time.time():
            del _SESSIONS[token]
            self._send_json({"error": "会话已过期，请重新登录"}, 401)
            return None
        return token

    # ---- 路由 ----
    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "" or path == "/":
            return self._serve_index()
        if not path.startswith("/api/"):
            return self._serve_static(path)

        # 登录检查
        if path == "/api/health":
            return self._send_json({"status": "ok"})

        token = self._require_auth()
        if token is None:
            return

        # API 路由
        try:
            if path == "/api/users":
                return self._api_list_users()
            if path == "/api/users/ous":
                return self._send_json({"ous": self.logic.get_ous()})
            if path.startswith("/api/users/"):
                uid = path[len("/api/users/"):]
                return self._api_get_user(uid)
            if path == "/api/groups":
                return self._api_list_groups()
            if path.startswith("/api/groups/"):
                name = path[len("/api/groups/"):]
                return self._api_get_group(name)
            return self._send_json({"error": "未知接口"}, 404)
        except LDAPError as e:
            return self._send_json({"error": str(e)}, 400)
        except Exception as e:
            return self._send_json({"error": "服务器错误: {}".format(e)}, 500)

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "/api/login":
            return self._api_login()
        if path == "/api/logout":
            return self._api_logout()

        token = self._require_auth()
        if token is None:
            return
        body = self._read_body()
        try:
            if path == "/api/users":
                return self._api_create_user(body)
            if path.startswith("/api/users/") and path.endswith("/password"):
                uid = path[len("/api/users/"):-len("/password")]
                return self._api_set_password(uid, body)
            if path.startswith("/api/users/") and path.endswith("/status"):
                uid = path[len("/api/users/"):-len("/status")]
                return self._api_set_status(uid, body)
            if path == "/api/groups":
                return self._api_create_group(body)
            if path.startswith("/api/groups/") and path.endswith("/members"):
                name = path[len("/api/groups/"):-len("/members")]
                return self._api_modify_members(name, body)
            return self._send_json({"error": "未知接口"}, 404)
        except LDAPError as e:
            return self._send_json({"error": str(e)}, 400)
        except Exception as e:
            return self._send_json({"error": "服务器错误: {}".format(e)}, 500)

    def do_PUT(self):
        token = self._require_auth()
        if token is None:
            return
        body = self._read_body()
        path = self.path.split("?")[0].rstrip("/")
        try:
            if path.startswith("/api/users/"):
                uid = path[len("/api/users/"):]
                return self._api_modify_user(uid, body)
            return self._send_json({"error": "未知接口"}, 404)
        except LDAPError as e:
            return self._send_json({"error": str(e)}, 400)
        except Exception as e:
            return self._send_json({"error": "服务器错误: {}".format(e)}, 500)

    def do_DELETE(self):
        token = self._require_auth()
        if token is None:
            return
        path = self.path.split("?")[0].rstrip("/")
        try:
            if path.startswith("/api/users/"):
                uid = path[len("/api/users/"):]
                return self._api_delete_user(uid)
            if path.startswith("/api/groups/"):
                name = path[len("/api/groups/"):]
                return self._api_delete_group(name)
            return self._send_json({"error": "未知接口"}, 404)
        except LDAPError as e:
            return self._send_json({"error": str(e)}, 400)
        except Exception as e:
            return self._send_json({"error": "服务器错误: {}".format(e)}, 500)

    # ---- 静态资源 ----
    def _serve_index(self):
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        self._send_file(os.path.join(web_dir, "index.html"), "text/html; charset=utf-8")

    def _serve_static(self, path):
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        safe = os.path.normpath(os.path.join(web_dir, path.lstrip("/")))
        if not safe.startswith(web_dir):
            return self._send_json({"error": "禁止访问"}, 403)
        ct = "text/html; charset=utf-8"
        if path.endswith(".css"):
            ct = "text/css"
        elif path.endswith(".js"):
            ct = "application/javascript"
        self._send_file(safe, ct)

    # ---- 认证 ----
    def _api_login(self):
        body = self._read_body()
        username = body.get("username", "")
        password = body.get("password", "")
        if not self.config.admin_username or not self.config.admin_password:
            return self._send_json({"error": "服务端未配置管理员账号"}, 500)
        if username == self.config.admin_username and password == self.config.admin_password:
            token = secrets.token_hex(32)
            _SESSIONS[token] = time.time() + self.config.session_timeout
            return self._send_json({"token": token, "username": username})
        return self._send_json({"error": "用户名或密码错误"}, 401)

    def _api_logout(self):
        token = self.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token[7:]
        _SESSIONS.pop(token, None)
        return self._send_json({"ok": True})

    # ---- 用户 API ----
    def _api_list_users(self):
        qs = self.path.split("?")[-1] if "?" in self.path else ""
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        items = self.logic.list_users(params.get("search", ""), params.get("ou", ""))
        return self._send_json({"items": items, "total": len(items),
                                "ous": self.logic.get_ous()})

    def _api_get_user(self, uid):
        d = self.logic.get_user(uid)
        if not d:
            return self._send_json({"error": "用户未找到"}, 404)
        return self._send_json(d)

    def _api_create_user(self, body):
        r = self.logic.create_user(body)
        return self._send_json({"ok": True, **r})

    def _api_modify_user(self, uid, body):
        self.logic.modify_user(uid, body)
        return self._send_json({"ok": True})

    def _api_set_password(self, uid, body):
        self.logic.set_user_password(uid, body.get("password", ""))
        return self._send_json({"ok": True})

    def _api_set_status(self, uid, body):
        self.logic.set_user_status(uid, body.get("action", ""), body.get("value", ""))
        return self._send_json({"ok": True})

    def _api_delete_user(self, uid):
        self.logic.delete_user(uid, remove_groups=True)
        return self._send_json({"ok": True})

    # ---- 组 API ----
    def _api_list_groups(self):
        qs = self.path.split("?")[-1] if "?" in self.path else ""
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        items = self.logic.list_groups(params.get("search", ""))
        return self._send_json({"items": items, "total": len(items)})

    def _api_get_group(self, name):
        d = self.logic.get_group(name)
        if not d:
            return self._send_json({"error": "组未找到"}, 404)
        return self._send_json(d)

    def _api_create_group(self, body):
        r = self.logic.create_group(body)
        return self._send_json({"ok": True, **r})

    def _api_delete_group(self, name):
        self.logic.delete_group(name)
        return self._send_json({"ok": True})

    def _api_modify_members(self, name, body):
        self.logic.modify_group_members(name, body.get("action", ""), body.get("members", []))
        return self._send_json({"ok": True})

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))


def main():
    env_path = sys.argv[1] if len(sys.argv) > 1 else None
    config = Config(env_path)
    if not config.admin_username or not config.admin_password:
        print("警告: 未配置 ADMIN_USERNAME / ADMIN_PASSWORD，登录接口不可用。", file=sys.stderr)
    logic = BusinessLogic(config)
    AdminWebHandler.logic = logic
    AdminWebHandler.config = config

    server = _ThreadingHTTPServer((config.web_listen, config.web_port), AdminWebHandler)
    print("LDAP 管理员 Web 已启动: http://{}:{}".format(config.web_listen, config.web_port))
    print("LDAP: ldaps://{}:{}  ({})".format(config.ldap_host, config.ldap_port, config.ldap_suffix))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止服务。")


if __name__ == "__main__":
    main()
