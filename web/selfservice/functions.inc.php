<?php
/**
 * LDAP Password Self-Service — Helper Functions
 * Compatible with PHP 5.4+ and PHP 7.0+
 */

require_once __DIR__ . '/config.inc.php';

// Polyfill: ldap_escape (PHP 5.6+)
if (!function_exists('ldap_escape')) {
    function ldap_escape($value, $ignore = '', $flags = 0) {
        $pattern = '';
        if ($flags & 1) $pattern = '\\\\00-\\\\7F';
        $pattern2 = '([\\x00-\\x1F\\x7F\\*\\\\(\\\\)])';
        if ($ignore) {
            $ign = str_split($ignore);
            foreach ($ign as $c) $pattern2 = str_replace('\\' . $c, '', $pattern2);
        }
        return preg_replace('/' . $pattern2 . '/', '\\\\$1', $value);
    }
}

// Define missing LDAP TLS constants (may not exist in older php-ldap)
if (!defined('LDAP_OPT_X_TLS_CACERTFILE')) define('LDAP_OPT_X_TLS_CACERTFILE', 0x6006);
if (!defined('LDAP_OPT_X_TLS_REQUIRE_CERT')) define('LDAP_OPT_X_TLS_REQUIRE_CERT', 0x600d);
if (!defined('LDAP_OPT_X_TLS_NEVER'))  define('LDAP_OPT_X_TLS_NEVER', 0);
if (!defined('LDAP_OPT_X_TLS_DEMAND')) define('LDAP_OPT_X_TLS_DEMAND', 2);
if (!defined('LDAP_OPT_X_TLS_ALLOW'))  define('LDAP_OPT_X_TLS_ALLOW', 3);
if (!defined('LDAP_OPT_X_TLS_TRY'))    define('LDAP_OPT_X_TLS_TRY', 4);

/**
 * Connect to LDAP with TLS support.
 */
function ldap_connect_tls()
{
    $proto = defined('LDAP_USE_TLS') && LDAP_USE_TLS ? 'ldaps' : 'ldap';
    $host = defined('LDAP_HOST') ? LDAP_HOST : 'localhost';
    $port = defined('LDAP_PORT') ? LDAP_PORT : ($proto === 'ldaps' ? 636 : 389);
    $uri = sprintf('%s://%s:%d', $proto, $host, $port);

    $conn = ldap_connect($uri);
    if (!$conn) {
        error_log('LDAP Self-Service: Failed to connect to ' . $uri);
        return false;
    }

    ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($conn, LDAP_OPT_NETWORK_TIMEOUT, 5);

    // For ldaps://, set CA cert for verification only (no StartTLS needed)
    if ($proto === 'ldaps') {
        $cacert = defined('LDAP_TLS_CACERT') ? LDAP_TLS_CACERT : '';
        if ($cacert && file_exists($cacert)) {
            ldap_set_option($conn, LDAP_OPT_X_TLS_CACERTFILE, $cacert);
            $reqcert = defined('LDAP_TLS_REQCERT') ? LDAP_TLS_REQCERT : 'demand';
            $reqval = ($reqcert === 'never') ? LDAP_OPT_X_TLS_NEVER : LDAP_OPT_X_TLS_DEMAND;
            ldap_set_option($conn, LDAP_OPT_X_TLS_REQUIRE_CERT, $reqval);
        }
    }

    return $conn;
}

/**
 * Search for a user's full DN by uid or cn.
 */
function get_user_dn($conn, $uid)
{
    // 先用 admin 绑定才能搜索（ACL 不允许匿名搜索）
    $rootdn = defined('LDAP_ROOTDN') ? LDAP_ROOTDN : '';
    $rootpw = defined('LDAP_ROOTPW') ? LDAP_ROOTPW : '';
    if ($rootdn && $rootpw) {
        @ldap_bind($conn, $rootdn, $rootpw);
    }
    $base = defined('LDAP_USER_BASE') ? LDAP_USER_BASE : '';
    $filter = sprintf('(|(uid=%s)(cn=%s))', ldap_escape($uid, '', 1), ldap_escape($uid, '', 1));
    $result = @ldap_search($conn, $base, $filter, array('dn'), 0, 0, 3);
    if (!$result) return false;
    $entries = ldap_get_entries($conn, $result);
    if ($entries['count'] !== 1) return false;
    return $entries[0]['dn'];
}

/**
 * Change a user's password using the admin bind.
 */
function change_password($user_dn, $new_password)
{
    $rootpw = defined('LDAP_ROOTPW') ? LDAP_ROOTPW : '';
    if ($rootpw === '' || $rootpw === false) {
        error_log('LDAP Self-Service: LDAP_ROOTPW is not configured');
        return false;
    }

    $conn = ldap_connect_tls();
    if (!$conn) return false;

    $rootdn = defined('LDAP_ROOTDN') ? LDAP_ROOTDN : '';
    $bind = @ldap_bind($conn, $rootdn, $rootpw);
    if (!$bind) {
        error_log('LDAP Self-Service: Admin bind failed: ' . ldap_error($conn));
        ldap_unbind($conn);
        return false;
    }

    $success = false;
    if (function_exists('ldap_exop_passwd')) {
        $result = @ldap_exop_passwd($conn, $user_dn, '', $new_password);
        $success = ($result !== false);
    }

    if (!$success) {
        $salt = '';
        for ($i = 0; $i < 4; $i++) $salt .= chr(mt_rand(0, 255));
        $hashed = '{SSHA}' . base64_encode(sha1($new_password . $salt, true) . $salt);
        $entry = array('userPassword' => $hashed);
        $success = @ldap_mod_replace($conn, $user_dn, $entry);
    }

    if (!$success) {
        error_log('LDAP Self-Service: Password change failed for ' . $user_dn . ': ' . ldap_error($conn));
    }

    ldap_unbind($conn);
    return $success;
}

/**
 * Update shadowLastChange to today's epoch day value.
 */
function update_shadow_lastchange($user_dn)
{
    $rootpw = defined('LDAP_ROOTPW') ? LDAP_ROOTPW : '';
    if ($rootpw === '' || $rootpw === false) return false;

    $conn = ldap_connect_tls();
    if (!$conn) return false;

    $rootdn = defined('LDAP_ROOTDN') ? LDAP_ROOTDN : '';
    $bind = @ldap_bind($conn, $rootdn, $rootpw);
    if (!$bind) { ldap_unbind($conn); return false; }

    $today = (int)(time() / 86400);
    $entry = array('shadowLastChange' => (string)$today);
    $result = @ldap_mod_replace($conn, $user_dn, $entry);

    ldap_unbind($conn);
    return $result;
}

/**
 * Validate password strength.
 */
function validate_password_strength($password)
{
    $errors = array();
    $min = defined('PASSWORD_MIN_LENGTH') ? PASSWORD_MIN_LENGTH : 8;

    if (strlen($password) < $min) {
        $errors[] = sprintf('Password must be at least %d characters.', $min);
    }
    if (defined('PASSWORD_REQUIRE_UPPER') && PASSWORD_REQUIRE_UPPER && !preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter.';
    }
    if (defined('PASSWORD_REQUIRE_LOWER') && PASSWORD_REQUIRE_LOWER && !preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter.';
    }
    if (defined('PASSWORD_REQUIRE_DIGIT') && PASSWORD_REQUIRE_DIGIT && !preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one digit.';
    }
    if (defined('PASSWORD_REQUIRE_SPECIAL') && PASSWORD_REQUIRE_SPECIAL && !preg_match('/[!@#$%^&*()_+\-=\[\]{};:\'",.<>\/?\\\\|`~]/', $password)) {
        $errors[] = 'Password must contain at least one special character.';
    }

    return $errors;
}

/**
 * Log an event. Passwords are NEVER logged.
 */
function log_event($uid, $action, $success, $message = '')
{
    $logfile = defined('LOG_FILE') ? LOG_FILE : '/var/log/ldap-selfservice.log';
    $timestamp = date('Y-m-d H:i:s');
    $status = $success ? 'SUCCESS' : 'FAILURE';
    $ip = get_client_ip();
    $line = sprintf("[%s] [%s] user:%s action:%s ip:%s %s\n",
        $timestamp, $status, $uid, $action, $ip,
        $message ? "message:{$message}" : '');
    @file_put_contents($logfile, $line, FILE_APPEND | LOCK_EX);
}

/**
 * Get the client's real IP address.
 */
function get_client_ip()
{
    $headers = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return '0.0.0.0';
}

/**
 * Check if the current session is valid.
 */
function is_session_valid()
{
    if (!isset($_SESSION['uid']) || !isset($_SESSION['user_dn'])) return false;
    if (!isset($_SESSION['last_activity'])) return false;

    $timeout = defined('SESSION_TIMEOUT') ? SESSION_TIMEOUT : 600;
    $elapsed = time() - $_SESSION['last_activity'];
    if ($elapsed > $timeout) {
        $_SESSION = array();
        session_destroy();
        return false;
    }
    $_SESSION['last_activity'] = time();
    return true;
}

/**
 * Generate a CSRF token.
 */
function generate_csrf_token()
{
    if (!isset($_SESSION['csrf_token'])) {
        $bytes = '';
        for ($i = 0; $i < 32; $i++) $bytes .= chr(mt_rand(0, 255));
        $_SESSION['csrf_token'] = bin2hex($bytes);
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token (timing-safe).
 */
function validate_csrf_token($token)
{
    if (!isset($_SESSION['csrf_token'])) return false;
    $a = $_SESSION['csrf_token'];
    $b = $token;
    if (strlen($a) !== strlen($b)) return false;
    $ret = 0;
    for ($i = 0; $i < strlen($a); $i++) $ret |= ord($a[$i]) ^ ord($b[$i]);
    return $ret === 0;
}
