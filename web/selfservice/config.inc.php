<?php
// LDAP 自助密码修改平台 — 配置（可被 config.local.php 覆盖）
require_once __DIR__ . "/config.local.php";

// LDAP 连接 — 优先读环境变量，其次 config.local.php，最后默认值
if (!defined("LDAP_HOST"))        define("LDAP_HOST",        getenv("LDAP_MASTER1")      ?: "ldap://localhost");
if (!defined("LDAP_PORT"))        define("LDAP_PORT",        (int)(getenv("LDAPS_PORT")  ?: 636));
if (!defined("LDAP_BASE_DN"))     define("LDAP_BASE_DN",     getenv("LDAP_SUFFIX")       ?: "dc=example,dc=com");
if (!defined("LDAP_USER_BASE"))   define("LDAP_USER_BASE",   getenv("LDAP_USER_BASE")    ?: "ou=People," . LDAP_BASE_DN);
if (!defined("LDAP_GROUP_BASE"))  define("LDAP_GROUP_BASE",  getenv("LDAP_GROUP_BASE")   ?: "ou=Group," . LDAP_BASE_DN);
if (!defined("LDAP_ROOTDN"))      define("LDAP_ROOTDN",      getenv("LDAP_ROOTDN")       ?: "cn=Manager," . LDAP_BASE_DN);
if (!defined("LDAP_ROOTPW"))      define("LDAP_ROOTPW",      getenv("LDAP_ROOTPW")       ?: "");
if (!defined("LDAP_USE_TLS"))     define("LDAP_USE_TLS",     getenv("LDAP_TLS_ENABLED")  ?: true);
if (!defined("LDAP_TLS_CACERT"))  define("LDAP_TLS_CACERT",  getenv("LDAP_TLS_CACERT")   ?: "/etc/openldap/certs/ca.crt");
if (!defined("LDAP_TLS_REQCERT")) define("LDAP_TLS_REQCERT", getenv("LDAP_TLS_REQCERT")  ?: "demand");

// 密码策略
if (!defined("PASSWORD_MIN_LENGTH")) define("PASSWORD_MIN_LENGTH", (int)(getenv("PASSWORD_MIN_LENGTH") ?: 8));
if (!defined("PASSWORD_REQUIRE_UPPER")) define("PASSWORD_REQUIRE_UPPER", true);
if (!defined("PASSWORD_REQUIRE_LOWER")) define("PASSWORD_REQUIRE_LOWER", true);
if (!defined("PASSWORD_REQUIRE_DIGIT")) define("PASSWORD_REQUIRE_DIGIT", true);
if (!defined("PASSWORD_REQUIRE_SPECIAL")) define("PASSWORD_REQUIRE_SPECIAL", true);

// 会话安全
if (!defined("SESSION_TIMEOUT"))       define("SESSION_TIMEOUT",       600);
if (!defined("MAX_LOGIN_ATTEMPTS"))    define("MAX_LOGIN_ATTEMPTS",    5);
if (!defined("LOGIN_BLOCK_TIME"))      define("LOGIN_BLOCK_TIME",      900);
if (!defined("LOGIN_THROTTLE_WINDOW")) define("LOGIN_THROTTLE_WINDOW", 300);

// 日志
if (!defined("LOG_FILE"))  define("LOG_FILE", "/var/log/ldap-selfservice.log");
if (!defined("APP_TITLE")) define("APP_TITLE", "LDAP Password Self-Service");

// 启动校验
if (LDAP_USE_TLS && !file_exists(LDAP_TLS_CACERT)) {
    error_log("LDAP Self-Service WARNING: TLS_CA_CERT not found: " . LDAP_TLS_CACERT);
}
