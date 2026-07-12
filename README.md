# LDAP Deployment Toolkit

OpenLDAP multi-master mirror mode deployment toolkit for RHEL/CentOS 7 (compatible with 8/9).

## Architecture

```
                          ┌──────────────────┐
                          │   LDAP Clients   │
                          │   (SSSD)         │
                          └────────┬─────────┘
                                   │ ldaps://
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐  ┌────▼──────┐
              │  ldap01   │  │  ldap02   │
              │ (ServerID │  │ (ServerID │
              │    1)     │  │    2)     │
              └─────┬─────┘  └────┬──────┘
                    │              │
                    └── Mirror ────┘
                      Replication
```

- **Multi-master mirror mode**: Both nodes are read-write peers.
- **LDAPS/TLS**: All connections encrypted with TLS 1.2+.
- **ShadowAccount**: Full account lifecycle (password expiry, enable/disable).
- **Strict ACLs**: Anonymous auth-only, read-only account for queries.
- **Read-only account**: `cn=readonly` for query operations.

## Quick Start

### 1. Configuration

```bash
vi config/ldap.conf
```

All values are set via environment variables with safe defaults. Override for your environment:

```bash
export LDAP_DC1=example LDAP_DC2=com LDAP_MASTER1=ldap01.example.com LDAP_MASTER2=ldap02.example.com
export LDAP_ROOTPW='your-manager-password'
export LDAP_RO_PW='your-readonly-password'
```

### 2. Generate TLS Certificates

```bash
cd server/tls
chmod +x gen-certs.sh
./gen-certs.sh ldap01.example.com ldap02.example.com

# Distribute CA certificate to all client nodes
scp /etc/openldap/certs/ca.crt ldap02:/etc/openldap/certs/ca.crt
for host in client01 client02; do
    scp /etc/openldap/certs/ca.crt $host:/etc/openldap/certs/ca.crt
done
```

See [docs/TLS-SETUP.md](docs/TLS-SETUP.md).

### 3. Install LDAP Servers

```bash
# On ldap01 (primary, Server ID 1)
cd server
chmod +x ldap.master
./ldap.master

# On ldap02 (mirror, Server ID 2)
cd server
chmod +x ldap.slave
./ldap.slave
```

Both scripts load `cosine`, `nis`, `inetorgperson`, `samba`, `sudo`, and `ppolicy` schemas.
DIT includes `ou=People`, `ou=Group`, `ou=automapper`, `ou=sudoers`.

### 4. Configure LDAP Clients

**Recommended: Ansible batch deployment** (`ansible/deploy-ldap-client.yml`)
- Auto-detects existing clients (nslcd/SSSD)
- New machines default to SSSD
- Supports `--check --diff` for dry-runs, `--serial 10` for rolling deployment

```bash
# Prepare
cp ansible/group_vars/all.yml.example ansible/group_vars/all.yml
# Edit all.yml with your LDAP server addresses, domain, and passwords
cp /etc/openldap/certs/ca.crt ansible/files/ca.crt

# Dry-run
ansible-playbook -i inventory.ini deploy-ldap-client.yml -l target --check --diff

# Deploy
ansible-playbook -i inventory.ini deploy-ldap-client.yml -l target
```

See `ansible/README-ETC-ANSIBLE.md` for details.

**Alternative: Shell script** (`client/ldap.client`)
```bash
cd client
chmod +x ldap.client
./ldap.client
```

### 5. Manage Users (ldapadmin.py)

```bash
cd admin
# Dry-run first (strongly recommended)
./ldapadmin.py user add zhangsan --ou dv --dry-run
./ldapadmin.py user add zhangsan --ou dv
```

#### user add — Create User

```
./ldapadmin.py user add <uid> [options]
```

| Option | Default | Description |
|------|--------|------|
| `--ou` | `People` | OU, user DN = `cn=<uid>,ou=<ou>,ou=People,dc=...` (auto-created if missing) |
| `--password` / `--passwd` | auto 10-char | Strong random password; quote special characters on CLI |
| `--home` | `/share/home/<uid>` | Home directory |
| `--shell` | `/bin/csh` | Login shell |
| `--uid` | auto (max+1, >=5000) | Scans both posixAccount uidNumber + posixGroup gidNumber |
| `--gid` | = UID | UID/GID always equal |
| `--group` | = username | Primary group (auto-created if missing) |
| `--groups` | none | Supplementary groups, comma-separated |
| `--mail` | `<uid>@example.com` | Email; `--mail ''` to disable |
| `--expire` | none | Expiry date `YYYY-MM-DD` |
| `--max-days` | 90 | Password max age (days) |
| `--disabled` | false | Create in disabled state |
| `--must-change` | false | Force password change on first login |
| `--dry-run` / `-n` | false | Preview only, no LDAP writes |

**Defaults**: no args = auto ID + 10-char password + `/share/home/<uid>` + `/bin/csh` + `ou=People`.

```bash
# Preview then create
./ldapadmin.py user add zhangsan --ou dv --dry-run
./ldapadmin.py user add zhangsan --ou dv

# Custom attributes
./ldapadmin.py user add vendor1 --ou dv --home /opt/vendor/vendor1 \
  --shell /bin/csh --expire 2026-12-31 --groups dialout

# Disabled + must change
./ldapadmin.py user add intern --ou dv --disabled --must-change
```

#### user mod — Modify User

```
./ldapadmin.py user mod <uid> <action> [value]
```

| action | Description | Mechanism |
|--------|------|------|
| `status` | Show full status | DN, UID/GID, password state, group memberships |
| `disable` | Disable account | `shadowExpire = 1` + `loginShell = /sbin/nologin` |
| `enable` | Enable account | Remove `shadowExpire` + restore `loginShell` to default |
| `lock` | Lock password | `shadowMax = 0` |
| `unlock` | Unlock password | `shadowMax = 90` |
| `pwd-expire` | Force password change | `shadowLastChange = 0` |
| `expire YYYY-MM-DD` | Set expiry date | `shadowExpire = date` |
| `shell <path>` | Change shell | e.g. `/bin/csh` |
| `home <path>` | Change home directory | e.g. `/data/home/<uid>` |

#### user passwd — Change Password

Strong password: 8+ chars, upper + lower + digit + special, no username embedded.

```bash
./ldapadmin.py user passwd zhangsan
# Interactive prompt; rejects weak passwords
```

#### user search — Query User

| Display | LDAP Attribute | Meaning |
|------|------|------|
| Account expiry | `shadowExpire` | Absolute expiry date |
| Last changed | `shadowLastChange` | Password last modified |
| Password expires | `shadowMax + LastChange` | Password deadline |
| Grace period | `shadowInactive` | Days after password expiry |

#### user del — Delete User

```bash
./ldapadmin.py user del zhangsan
./ldapadmin.py user del zhangsan --force --remove-groups --backup-home
```

#### group — Group Management

```bash
./ldapadmin.py group add devteam
./ldapadmin.py group search devteam    # View group details (GID/members)
./ldapadmin.py group del devteam
```

#### automount — autofs Mount Management

```bash
# Add NFS mount (dry-run first)
./ldapadmin.py automount add /share/reg_scratch/gtl \
  --target nfs01.example.com:/gtl --dry-run
./ldapadmin.py automount add /share/reg_scratch/gtl \
  --target nfs01.example.com:/gtl

# Custom mount options
./ldapadmin.py automount add /share/project/new \
  --target nfs01.example.com:/new --opts "vers=4,rw,noatime"

# Delete / list
./ldapadmin.py automount del /share/reg_scratch/gtl
./ldapadmin.py automount list
```

#### Batch Import

```bash
# CSV format: uid,group[,shell[,password[,home[,groups]]]]
./ldapadmin.py batch add users.csv
./ldapadmin.py batch del users.csv
```

### 6. Client Query Tool (ldapquery.sh)

> Deploy on client nodes. Regular users can query LDAP info. Requires only `openldap-clients`.

```bash
# Distribute to clients
scp ldap01:/opt/ldap-toolkit/client/ldapquery.sh /usr/local/bin/
chmod +x /usr/local/bin/ldapquery.sh

# Usage
ldapquery.sh self                  # Query self (uses $USER)
ldapquery.sh user zhangsan         # Detailed user info
ldapquery.sh group devteam         # Group details with members
ldapquery.sh user-list             # All users (UID/GID/status/shell/home/last-changed/expiry)
ldapquery.sh group-list            # All groups
```

> Password auto-detected from `/etc/sssd/sssd.conf` (root only) or interactive prompt via `$LDAP_RO_PW`.

## Self-Service Password Portal

> See `docs/SELFSERVICE-DEPLOY.md` for detailed deployment.

Users visit `https://<server>/passwd/` to change their password. Strong password policy: 8+ chars, four character classes.

```bash
# Quick deploy
mkdir -p /opt/ldap-selfservice
cp -r web/selfservice/* /opt/ldap-selfservice/
# Apache config: see docs/SELFSERVICE-DEPLOY.md
systemctl restart httpd24-httpd
```

## Directory Structure

```
├── README.md                    # This file (English)
├── README_CN.md                 # Chinese version
├── config/
│   └── ldap.conf                # Shared configuration with env variable defaults
├── server/
│   ├── ldap.master              # Primary node install script
│   ├── ldap.slave               # Mirror node install script
│   ├── eraseldap                # LDAP cleanup/uninstall
│   └── tls/
│       └── gen-certs.sh         # TLS certificate generator
├── ansible/                     # ★ Ansible batch deployment (recommended)
│   ├── deploy-ldap-client.yml   #   Client playbook
│   ├── group_vars/all.yml.example  #   Variable template
│   ├── files/                   #   CA cert and other files
│   └── README-ETC-ANSIBLE.md    #   Deployment guide
├── client/
│   ├── ldap.client              # Single-host shell deployment (fallback)
│   └── ldapquery.sh             # Client query tool (bash + ldapsearch)
├── admin/
│   └── ldapadmin.py             # Unified management CLI (user/group/batch/automount)
├── batch/
│   ├── addjaguar.sh             # Batch user import
│   └── deljaguar.sh             # Batch user delete
├── web/
│   └── selfservice/             # Self-service password portal
│       ├── index.php
│       ├── change.php
│       ├── config.inc.php
│       ├── functions.inc.php
│       ├── style.css
│       └── logout.php
├── tools/
│   └── git-secrets-hook.sh      # pre-commit hook to block sensitive data
└── docs/
    ├── TLS-SETUP.md
    ├── SELFSERVICE-DEPLOY.md
    └── PHPLDAPADMIN-DEPLOY.md
```

## Security

- No hardcoded passwords — environment variables or interactive prompts
- All LDAP operations use TLS/SSL (LDAPS port 636)
- Clients enforce CA certificate verification
- Password strength validation (min length, character classes)
- Self-service portal: CSRF protection, rate limiting, session timeout
- No password logging — credentials excluded from logs
- ShadowAccount account lifecycle management
- Strict ACLs: read-only account + anonymous auth-only

## Secret Management

**Never commit these to the repo** (blocked by `.gitignore`):

| Path | Why |
|------|-----|
| `ldap_certs/` | Private keys (ca.key, server keys) |
| `ansible/files/ca.crt` | Internal CA certificate |
| `ansible/group_vars/all.yml` | Real LDAP server addresses + passwords |

Use template pattern:
- `ansible/group_vars/all.yml.example` → copy to `all.yml`, fill in real values
- Generate CA cert with `server/tls/gen-certs.sh`, then copy to `ansible/files/`

A pre-commit hook is available: `tools/git-secrets-hook.sh`

## RHEL/CentOS Compatibility

| Feature | RHEL/CentOS 7 | RHEL 8/9 |
|------|--------------|----------|
| Auth config | `authconfig` (deprecated) | `authselect` |
| SSSD | Supported | Supported |
| Python 3 | EPEL install | Built-in |
| OpenLDAP | 2.4.x | 2.4.x / 2.5+ |
| DB backend | hdb | mdb (recommended) |
| TLS minimum | TLS 1.2 | TLS 1.2+ |

Scripts include `detect_os()` for automatic OS adaptation.

## Troubleshooting

| Issue | Check |
|------|---------|
| LDAP connection refused | `systemctl status slapd`, firewall ports 389/636 |
| TLS handshake failure | Certificate permissions (`ldap:ldap`, key=0400), client CA cert |
| User login denied | Account disabled? `python3 ldapadmin.py user mod <uid> status` |
| Replication lag | Check `olcSyncRepl` config, network, inter-node firewall |
| Self-service unreachable | PHP LDAP module loaded? `php -m \| grep ldap` |
| Password change fails | TLS enabled? Check `ldaps://` in config |
| SSSD won't start | `sssctl domain-status LDAP`, `journalctl -u sssd` |
