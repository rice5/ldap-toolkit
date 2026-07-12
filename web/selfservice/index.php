<?php
/**
 * LDAP Password Self-Service — Login Page
 *
 * Users authenticate with their LDAP credentials here.
 */

require_once __DIR__ . '/config.inc.php';
require_once __DIR__ . '/functions.inc.php';

// Start session with security settings

ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', '1');
session_start();

// Redirect to change page if already logged in
if (is_session_valid()) {
    header('Location: change.php');
    exit;
}

$error = '';
$info = '';

// Show messages from redirects
if (isset($_GET['msg'])) {
    switch ($_GET['msg']) {
        case 'logged_out':
            $info = 'You have been logged out.';
            break;
        case 'password_changed':
            $info = 'Password changed successfully. Please log in with your new password.';
            break;
        case 'session_expired':
            $info = 'Your session has expired. Please log in again.';
            break;
    }
}

// Initialize login attempt tracking
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

// Check for block
$now = time();
$recent_attempts = array_filter($_SESSION['login_attempts'], function ($t) use ($now) {
    return ($now - $t) < LOGIN_THROTTLE_WINDOW;
});
$_SESSION['login_attempts'] = array_values($recent_attempts);

$is_blocked = false;
$block_remaining = 0;

if (count($_SESSION['login_attempts']) >= MAX_LOGIN_ATTEMPTS) {
    $oldest_recent = min($_SESSION['login_attempts']);
    $block_until = $oldest_recent + LOGIN_BLOCK_TIME;
    if ($now < $block_until) {
        $is_blocked = true;
        $block_remaining = ceil(($block_until - $now) / 60);
    } else {
        // Block expired, reset
        $_SESSION['login_attempts'] = [];
    }
}

// Handle login POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($is_blocked) {
        $error = sprintf('Too many failed attempts. Please wait %d minute(s).', $block_remaining);
    } else {
        // CSRF validation
        if (!validate_csrf_token(isset($_POST["csrf_token"]) ? $_POST["csrf_token"] : '')) {
            $error = 'Invalid form submission. Please try again.';
        } else {
            $username = trim(isset($_POST["username"]) ? $_POST["username"] : '');
            $password = isset($_POST["password"]) ? $_POST["password"] : '';

            // Validate username format
            if ($username === '' || !preg_match('/^[a-zA-Z0-9._-]+$/', $username)) {
                $error = 'Invalid username format.';
            } else {
                $conn = ldap_connect_tls();

                if (!$conn) {
                    $error = 'Cannot connect to authentication server. Please try again later.';
                    error_log('LDAP Self-Service: Connection failed for login attempt');
                } else {
                    // Search for user
                    $user_dn = get_user_dn($conn, $username);

                    if (!$user_dn) {
                        // Invalid user
                        $_SESSION['login_attempts'][] = $now;
                        $remaining = MAX_LOGIN_ATTEMPTS - count($_SESSION['login_attempts']);
                        $error = sprintf('Invalid username or password. Attempts remaining: %d.', max(0, $remaining));
                        log_event($username, 'login', false, 'User not found');
                    } else {
                        // Try to bind as the user
                        $bind = @ldap_bind($conn, $user_dn, $password);

                        if ($bind) {
                            // SUCCESS
                            ldap_unbind($conn);

                            // Regenerate session ID to prevent fixation
                            session_regenerate_id(true);

                            $_SESSION['uid'] = $username;
                            $_SESSION['user_dn'] = $user_dn;
                            $_SESSION['last_activity'] = $now;
                            $_SESSION['login_time'] = $now;
                            $_SESSION['login_attempts'] = [];

                            log_event($username, 'login', true);
                            header('Location: change.php');
                            exit;
                        } else {
                            // Wrong password
                            $_SESSION['login_attempts'][] = $now;
                            $remaining = MAX_LOGIN_ATTEMPTS - count($_SESSION['login_attempts']);
                            $error = sprintf('Invalid username or password. Attempts remaining: %d.', max(0, $remaining));
                            log_event($username, 'login', false, 'Bind failed');
                        }
                    }
                    ldap_unbind($conn);
                }
            }
        }
    }
}

$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(APP_TITLE, ENT_QUOTES, 'UTF-8'); ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h1><?php echo htmlspecialchars(APP_TITLE, ENT_QUOTES, 'UTF-8'); ?></h1>
                <p class="subtitle">Sign in to change your password</p>
            </div>

            <div class="card-body">
                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
                <?php endif; ?>

                <?php if ($info): ?>
                    <div class="alert alert-info"><?php echo htmlspecialchars($info, ENT_QUOTES, 'UTF-8'); ?></div>
                <?php endif; ?>

                <form method="post" action="index.php" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username"
                               placeholder="Enter your username"
                               required autocomplete="username"
                               pattern="[a-zA-Z0-9._-]+"
                               maxlength="64"
                               autofocus>
                    </div>

                    <div class="form-group">
                        <label for="password">Current Password</label>
                        <input type="password" id="password" name="password"
                               placeholder="Enter your current password"
                               required autocomplete="current-password">
                    </div>

                    <button type="submit" class="btn btn-primary btn-full">Sign In</button>
                </form>
            </div>
        </div>

        <div class="footer">
            <p>Contact IT support if you need assistance.</p>
        </div>
    </div>
</body>
</html>
