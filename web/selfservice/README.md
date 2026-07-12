# LDAP Password Self-Service Portal

## URLs

- ldap01: `https://ldap01.example.com/passwd/`
- ldap02: `https://ldap02.example.com/passwd/`

## Usage

1. Open the URL, enter your **username** and **current password**, click Sign In
2. Enter **new password** and **confirm password**, click Change Password
3. "Password changed successfully" means the change is complete

## Password Requirements

| Requirement | Detail |
|------|------|
| Minimum 8 characters | `PASSWORD_MIN_LENGTH=8` |
| Uppercase letter | At least 1 A-Z |
| Lowercase letter | At least 1 a-z |
| Digit | At least 1 0-9 |
| Special character | At least 1 of !@#$% etc. |
| No username | Password must not contain the username |
| Not same as old | New password must differ from current |

## Password Expiry Policy

- Password valid for 90 days (`shadowMax`)
- Warning 7 days before expiry (`shadowWarning`)
- 30-day grace period after expiry (`shadowInactive`)
- Account locked after grace period, requires admin to unlock

## FAQ

**Q: "Invalid username or password"?**
A: Verify your username and current password. 5 consecutive failures lock the account for 15 minutes.

**Q: "Cannot connect to authentication server"?**
A: The server is temporarily unavailable. Try again later.

**Q: Forgot current password?**
A: Contact IT admin to reset via `ldapadmin.py user passwd <username>`.

## Admin Info

- Environment: CentOS 7 + httpd24 + PHP 7.0 (SCL)
- Path: `/opt/ldap-selfservice/`
- Deployment guide: `docs/SELFSERVICE-DEPLOY.md`
- Logs: `/var/log/ldap-selfservice.log`
- Password policy config: `config.inc.php` (`PASSWORD_REQUIRE_*` constants)
