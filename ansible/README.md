# Ansible LDAP Client Deployment

> Used with `/etc/ansible/deploy-ldap-client.yml`. See [README-ETC-ANSIBLE.md](README-ETC-ANSIBLE.md)

## File Structure

```
ansible/
├── deploy-ldap-client.yml       # ★ Main Playbook (auto-detects nslcd/SSSD)
├── group_vars/
│   └── all.yml                  # Variables + vault_ldap_ro_pw (chmod 600)
├── files/
│   └── ca.crt                   # LDAP CA cert (copy from ldap01)
├── README-ETC-ANSIBLE.md        # Full /etc/ansible operations guide
├── README.md                    # This file
└── inventory-ldap.ini           # LDAP inventory template
```

## Quick Start

```bash
# 1. Set passwords
vi group_vars/all.yml        # set vault_ldap_ro_pw = real password
chmod 600 group_vars/all.yml

# 2. Dry-run (no changes)
ansible-playbook -i /etc/ansible/hosts deploy-ldap-client.yml \
  -l target-node --check --diff

# 3. Deploy
ansible-playbook -i /etc/ansible/hosts deploy-ldap-client.yml \
  -l target-node
```

## Deployment Modes

| Scenario | Mode | Notes |
|------|---------|------|
| **New machine** (any OS) | SSSD | Auto-detected, installs SSSD |
| CentOS 7 with existing nslcd | nslcd | Reuses existing, upgrades TLS |
| Existing SSSD nodes | SSSD | Updates configuration |

## What Gets Deployed

| File | nslcd | SSSD | Notes |
|------|-------|------|------|
| `/etc/openldap/ldap.conf` | ✅ | ✅ | ldaps:// URI + TLS demand |
| `/etc/nslcd.conf` | ✅ | — | ssl on + readonly bind |
| `/etc/sssd/sssd.conf` | — | ✅ | Optimized config |
| `/etc/autofs_ldap_auth.conf` | ✅ | ✅ | Permissions 0600 |
| `/etc/sudo-ldap.conf` | ✅ | ✅ | ldaps:// URI |
| CA certificate | ✅ | ✅ | `/etc/openldap/certs/ca.crt` |
| autofs / nslcd / SSSD | ✅ | ✅ | Service restart + enable |

## Verification

```bash
# Post-deployment checks
ansible target-node -m shell -a \
  "ldapsearch -x -H ldaps://ldap01.example.com:636 -b '' -s base dn"

ansible target-node -m shell -a "id testuser && sudo -l && ls /share/home/"
```
