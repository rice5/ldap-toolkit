<?php
/**
 * LDAP Password Self-Service — Logout
 */


ini_set('session.cookie_httponly', '1');
session_start();

// Clear all session data
$_SESSION = [];

// Destroy the session cookie
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

// Destroy the session
session_destroy();

// Redirect to login page
header('Location: index.php?msg=logged_out');
exit;
