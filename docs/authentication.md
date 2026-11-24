# Authentication

This page tells how dmodem-login checks the name and password of a caller, and how a caller can change the password.

## Authentication


`[general] auth` lists the backends. dmodem-login asks them in that
sequence. If a backend does not know the user, dmodem-login asks the next
backend. If a backend knows the user and the password is wrong, the
attempt ends there. If a backend does not operate (LDAP is not
available, or there is an SQL error), dmodem-login records this in the log
and skips the backend.

- **file**: `user:password` lines. The password is one of these:
  a bcrypt hash (`dmodem-login -hash` prints one), `{SHA256}`/`{SHA512}`
  (hex or base64), `{SSHA256}`/`{SSHA512}` (salted, base64) or
  `{PLAIN}text`. dmodem-login reads the file at each login.
- **ldap**: a bind as the user. The bind goes to `bind_dn` with `{user}`
  in it, or to the entry that `search_filter` finds under `search_base`.
  dmodem-login supports ldaps://, StartTLS and a private CA. Put a group
  check in the filter (`memberOf=...`). dmodem-login escapes the values for
  DNs and filters.
- **sql**: `query` gets the user (and, as an option, the password) as
  arguments. It returns the stored password, and dmodem-login checks it in
  the same way as for the file. Alternatively, with `hash = none`, a row
  in the result means that the login is correct. Use this for a database
  that checks passwords itself (`crypt()` in PostgreSQL).
- **system** (or **pam**): the accounts of the machine, through PAM.
  Refer to the section below.

User names must agree with `user_pattern` (by default, letters, digits
and `._@-`). After a wrong login, dmodem-login waits `fail_delay` seconds.
A login with an unknown user takes the same time as a login with a known
user. dmodem-login hangs up the call after `attempts` tries or after
`login_timeout`.

## System accounts (PAM)


`auth = system` runs the auth and account stacks of the PAM service
`pam_service` (by default, `dmodem-login`). Thus local accounts operate, and
all other items that PAM has a configuration for (sssd, Kerberos, OTP
modules). PAM does its own checks for expired and locked accounts. This
backend must have a build with PAM (refer to
[Building](building.md)). To configure it, do these steps:

1. Install the PAM service. `make install` puts
   [dmodem-login.pam.sample](../samples/dmodem-login.pam.sample) in `/etc/pam.d/dmodem-login`.
   The sample uses `common-auth`, `common-account` and, for password
   changes, `common-password` of the distribution.
2. For local accounts, run Asterisk (and thus dmodem-login) as root.
   `pam_unix` checks the passwords of other users only for root.
3. Add `system` to `[general] auth`. Then set these options in
   `[system]`:

   | option | default | |
   |---|---|---|
   | `pam_service` | `dmodem-login` | the file in `/etc/pam.d` |
   | `min_uid` | `1000` | accounts below this value (system accounts) cannot log in |
   | `allow_root` | `no` | `yes` lets root log in |
   | `groups` | | only members of these groups can log in (membership or primary group) |

If these rules refuse an account, the account is "unknown" to this
backend. dmodem-login asks the next backend and records the reason in the
log. With `run_as = {user}`, a selection (for example, the shell) runs
as the account of the caller.

## Changing passwords


A `mode = passwd` item lets callers change their own password. The
item does not have a command. By default, it goes back to the menu
(`after = menu`). The caller does these steps:

1. Type the current password.
2. Type the new password two times. The new password must have a minimum
   of `min_password` characters of the item (8 by default). It must be
   different from the current password. The caller has three tries.

dmodem-login checks the current password against the backends again. This
check also finds the backend that holds the account. A login by caller
ID or by an upstream menu does not give this information. The password
changes in that backend:

| backend | how |
|---|---|
| file | dmodem-login writes the line of the user again in the same location, under the lock of the file. It keeps a note after the hash. The password is bcrypt, or text with `hash = plain` |
| sql | `[sql] update_query` with `update_args` (`user`, `password`, `old_password`, in the sequence of its placeholders). `update_hash = bcrypt` stores a bcrypt hash. `none` stores the password as the caller typed it, for a query that makes the hash itself. Without `update_query`, you cannot change SQL passwords here |
| ldap | dmodem-login binds as the user, thus the password policy and hash of the server apply. It uses the Password Modify extended operation (RFC 3062, for OpenLDAP, 389 DS and most other servers). With `[ldap] password_change = ad`, it uses the method of Active Directory: it deletes the old value of `unicodePwd` and adds the new value. AD accepts this only on `ldaps://` or `starttls` |
| system | the password stack of `pam_service` in PAM. The caller sees the messages of PAM (for example, the reasons from a quality module) |

If the policy of the server or of PAM refuses the new password, the
old password stays. After a change, the selections get the new password
in `MODEM_PASSWORD`. Guests have no password to change. The log records
which user changed the password and in which backend. It never records
the password.

When it runs as root, `pam_unix` does no quality checks. Its `minlen`
and similar options do not apply to root. For a policy, put
`pam_pwquality` before `pam_unix` with `enforce_for_root`, as
[dmodem-login.pam.sample](../samples/dmodem-login.pam.sample) shows.

## New accounts in each backend


A signup (`[signup] enabled = yes`) makes the new account in each
backend of `[general] auth` that is set up to make accounts. Thus the
caller can use the same name and password in all these backends.

| backend | it makes accounts when | how |
|---|---|---|
| file | always | dmodem-login adds `user:bcrypt:note` at the end of the users file, under the lock of the file |
| sql | `[sql] insert_query` is set | dmodem-login runs `insert_query` with `insert_args` (`user`, `password`, `pending`, `note`, in the sequence of its placeholders). `insert_hash = bcrypt` stores a bcrypt hash. `none` stores the password as the caller typed it |
| ldap | `[ldap] add_dn` is set | dmodem-login binds as `add_bind_dn` and adds the entry at `add_dn` with `add_attributes`. Then it sets the password with the Password Modify extended operation, thus the server makes the hash. With `password_change = ad`, the entry gets `unicodePwd` (only on `ldaps://` or `starttls`) |
| system | `[system] create_command` is set | dmodem-login runs `create_command` with `/bin/sh`. `{user}` and `{pending}` (`yes` or `no`) are in the command. The password and a line end go to its standard input |

To use only some of these backends, set `[signup] backends`. If a
backend in `backends` cannot make accounts, dmodem-login does not start.

Before the new account is made, dmodem-login makes sure that no backend
has the name:

- Each backend that makes the account must not have the name. If one of
  these backends cannot do the check (it does not operate), the caller
  cannot get the name.
- The other backends of `auth` also must not have the name, if they can
  do the check. If one of them does not operate, dmodem-login records
  this in the log only.
- The name service of the system must not have the name.

The checks of each backend are these:

- file: the users file, in all cases of the letters.
- sql: `exists_query` with the user. A row tells that the name is
  there. Without `exists_query`, dmodem-login uses `query` if its only
  argument is `user`. If not, only the database can refuse the name (for
  example, with a `UNIQUE` key on the column of the names).
- ldap: the entry at `add_dn`, and the entries that `search_filter`
  finds under `search_base`.
- system: the name service.

If a backend cannot make the account, dmodem-login removes the account
from the backends that made it before. It uses the reverse sequence:

- file: dmodem-login removes the line.
- sql: dmodem-login runs `delete_query` with the user.
- ldap: dmodem-login deletes the entry.
- system: dmodem-login runs `remove_command` with `{user}`.

Without `delete_query` or `remove_command`, dmodem-login cannot remove
the account. It records this in the log. The sysop must then remove the
account.

### Pending accounts

With `[signup] pending = yes`, each backend must lock the new account
until the sysop unlocks it. If a backend cannot lock the account,
dmodem-login does not start:

- file: the line is `user:!bcrypt`.
- sql: `insert_args` must have `pending` (`1` for a pending account,
  `0` for an account that can log in). `query` must refuse the locked
  rows.
- ldap: `add_pending_attributes` must lock the entry. These attributes
  replace the attributes of `add_attributes` that have the same name.
  For example, use `pwdAccountLockedTime=000001010000Z` for the ppolicy
  overlay of OpenLDAP, `nsAccountLock=TRUE` for 389 DS, or
  `userAccountControl=514` for Active Directory.
- system: `create_command` gets `{pending}` and must lock the account.

### An example script for system accounts

[dmodem-login-useradd.sample](../samples/dmodem-login-useradd.sample)
makes a system account with `useradd` and `chpasswd`. For a pending
account, it locks the account with `usermod --lock`. To use it, do these
steps:

1. Install the script:
   `install -m 755 samples/dmodem-login-useradd.sample /usr/local/sbin/dmodem-login-useradd`.
2. Set these options in `[system]`:

   ```
   create_command = /usr/local/sbin/dmodem-login-useradd {user} {pending}
   remove_command = userdel -r {user}
   ```

3. Run dmodem-login as root, because `useradd` must have root.
4. Make sure that new accounts get a uid of `min_uid` or more. If not,
   the `system` backend does not let them log in.

Do not put `{user}` or `{pending}` in quotes in a command. dmodem-login
puts each value in quotes for the shell.

## The same password elsewhere: the auth socket


Callers who log in here are already logged in when they get to the
BBS. The same persons can also log in to the BBS in a different way
(telnet, SSH, the web forum of the BBS). They can use the same password,
because the BBS asks the backends of dmodem-login through a unix socket.

```
[authd]
listen = /run/dmodem-login/auth.sock
socket_mode = 0660
socket_group = bbs
; and, closer: only these users' programs (by the peer's uid)
allow_users = bbs
```

`dmodem-login -serve` answers on this socket, and also serves its sessions.
`dmodem-login -authd` answers on this socket only
([dmodem-login-authd.service.sample](../samples/dmodem-login-authd.service.sample)).
Each connection has one request, with one JSON line in each direction:

```
{"user": "alice", "password": "..."}
{"ok": true, "auth": "ldap"}          or          {"ok": false, "error": "denied"}
```

dmodem-login asks the backends in the same way as at the login prompt, and
applies `user_pattern`. A refusal comes after `fail_delay`. dmodem-login
also refuses accounts that are locked in the users file (a signup that
the sysop did not unlock). If a caller changes a password from the menu
(`mode = passwd`), the socket immediately uses the new password. For the
configuration on the BBS side, refer to its `[dmodem-login] auth_socket`
(docs/wiki/Modem-Callers.md in the BBS repository).

Other programs can also use LDAP to check the same passwords. Refer to
[the LDAP provider](ldap-provider.md).
