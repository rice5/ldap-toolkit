<?php
/**
 * LDAP Password Self-Service — Password Change Page
 */

require_once __DIR__ . '/config.inc.php';
require_once __DIR__ . '/functions.inc.php';


ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', '1');
session_start();

// Require valid session
if (!is_session_valid()) {
    header('Location: index.php?msg=session_expired');
    exit;
}

$uid = $_SESSION['uid'];
$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF validation
    if (!validate_csrf_token(isset($_POST["csrf_token"]) ? $_POST["csrf_token"] : '')) {
        $errors[] = 'Invalid form submission. Please try again.';
    } else {
        $new_password = isset($_POST["new_password"]) ? $_POST["new_password"] : '';
        $confirm_password = isset($_POST["confirm_password"]) ? $_POST["confirm_password"] : '';

        // Validate passwords match
        if ($new_password !== $confirm_password) {
            $errors[] = 'Passwords do not match.';
        }

        // Validate password strength
        $strength_errors = validate_password_strength($new_password);
        $errors = array_merge($errors, $strength_errors);

        // Check that new password is different from old
        if (empty($errors)) {
            $conn = ldap_connect_tls();
            if ($conn) {
                $old_bind = @ldap_bind($conn, $_SESSION['user_dn'], $new_password);
                if ($old_bind) {
                    $errors[] = 'New password must be different from your current password.';
                }
                ldap_unbind($conn);
            }
        }

        // Attempt password change
        if (empty($errors)) {
            $result = change_password($_SESSION['user_dn'], $new_password);

            if ($result) {
                // Update shadowLastChange
                update_shadow_lastchange($_SESSION['user_dn']);

                log_event($uid, 'password_change', true, 'Password changed successfully');
                $success = true;

                // Destroy session and show success
                $_SESSION = [];
                session_destroy();
            } else {
                $errors[] = 'Failed to change password. Please contact your administrator.';
                log_event($uid, 'password_change', false, 'ldap_exop_passwd or mod_replace failed');
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
    <title><?php echo htmlspecialchars(APP_TITLE, ENT_QUOTES, 'UTF-8'); ?> — Change Password</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <?php if ($success): ?>
                <div class="card-header">
                    <h1>Password Changed</h1>
                </div>
                <div class="card-body">
                    <div class="alert alert-success">
                        Your password has been changed successfully.
                    </div>
                    <p>Please log in with your new password.</p>
                    <a href="index.php" class="btn btn-primary btn-full">Back to Login</a>
                </div>
            <?php else: ?>
                <div class="card-header">
                    <h1>Change Password</h1>
                    <p class="subtitle">
                        Logged in as: <strong><?php echo htmlspecialchars($uid, ENT_QUOTES, 'UTF-8'); ?></strong>
                        &middot; <a href="logout.php" class="logout-link">Sign Out</a>
                    </p>
                </div>

                <div class="card-body">
                    <?php foreach ($errors as $err): ?>
                        <div class="alert alert-error"><?php echo htmlspecialchars($err, ENT_QUOTES, 'UTF-8'); ?></div>
                    <?php endforeach; ?>

                    <form method="post" action="change.php" autocomplete="off">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">

                        <div class="form-group">
                            <label for="new_password">New Password</label>
                            <input type="password" id="new_password" name="new_password"
                                   placeholder="Enter new password"
                                   required autocomplete="new-password"
                                   minlength="<?php echo (int)PASSWORD_MIN_LENGTH; ?>">
                        </div>

                        <div class="form-group">
                            <label for="confirm_password">Confirm New Password</label>
                            <input type="password" id="confirm_password" name="confirm_password"
                                   placeholder="Re-enter new password"
                                   required autocomplete="new-password">
                        </div>

                        <div class="password-requirements">
                            <p>Password requirements:</p>
                            <ul>
                                <li>At least <?php echo (int)PASSWORD_MIN_LENGTH; ?> characters</li>
                                <?php if (PASSWORD_REQUIRE_UPPER): ?><li>At least one uppercase letter (A-Z)</li><?php endif; ?>
                                <?php if (PASSWORD_REQUIRE_LOWER): ?><li>At least one lowercase letter (a-z)</li><?php endif; ?>
                                <?php if (PASSWORD_REQUIRE_DIGIT): ?><li>At least one digit (0-9)</li><?php endif; ?>
                                <?php if (PASSWORD_REQUIRE_SPECIAL): ?><li>At least one special character</li><?php endif; ?>
                                <li>Must be different from your current password</li>
                            </ul>
                        </div>

                        <button type="submit" class="btn btn-primary btn-full">Change Password</button>
                        <a href="logout.php" class="btn btn-cancel btn-full">Cancel</a>
                    </form>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
