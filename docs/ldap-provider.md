# The LDAP provider

dmodem-login can be an LDAP server. Other programs can then use the same
user names and passwords as the dial-up line. Examples of these programs
are the BBS, a wiki, a mail server, a PBX and a VPN.

The LDAP provider uses the backends of the login prompt (the users file,
LDAP, SQL and the system accounts) to check each password. It applies
`user_pattern` and `fail_delay` in the same way as the login prompt.

The directory is read only. You cannot add, delete or modify entries
through LDAP. No entry contains a password or a password hash.

## Configuration

Add an `[ldapd]` section to `dmodem-login.conf`. This example listens on
loopback for local programs, and on all networks with TLS (ldaps):

```
[ldapd]
listen = tcp:127.0.0.1:389
listen_tls = tcp:0.0.0.0:636
base_dn = dc=example,dc=org
tls_cert = /etc/dmodem-login/ldap.crt
tls_key = /etc/dmodem-login/ldap.key
; for programs that search before they bind
bind_dn = cn=reader,dc=example,dc=org
bind_password = $2a$10$...
```

`dmodem-login -serve` answers LDAP requests, and also serves its sessions.
`dmodem-login -ldapd` answers LDAP requests only
([dmodem-login-ldapd.service.sample](../samples/dmodem-login-ldapd.service.sample)).
Use `-ldapd` when `app_dmodem` starts one dmodem-login for each call.

To listen on port 389 or 636, dmodem-login must have the
`CAP_NET_BIND_SERVICE` capability, or it must run as root. The sample
unit gives the capability.

[The configuration reference](reference.md#ldapd) gives all the keys.

## The directory

The directory has these entries:

| DN | What it is |
| --- | --- |
| `<base_dn>` | The base entry |
| `ou=people,<base_dn>` | The container of the users |
| `uid=<user>,ou=people,<base_dn>` | One user |
| `ou=groups,<base_dn>` | The container of the groups |
| `cn=<group>,ou=groups,<base_dn>` | One group of `[groups]` |

These users are in the directory:

- Each user of the users file. A locked user (a sign-up that the sysop
  did not unlock) is not in the directory.
- Each member of a group in `[groups]`.
- Each system account (`auth = system`) that a search names with
  `(uid=<user>)`. The account must agree with `min_uid`, `allow_root`
  and `groups` of `[system]`. The LDAP provider cannot list all system
  accounts.
- The user of the bind.

A user entry has these attributes:

| Attribute | Value |
| --- | --- |
| `objectClass` | `top`, `person`, `organizationalPerson`, `inetOrgPerson`, and `posixAccount` for a system account |
| `uid` | The user name |
| `cn`, `displayName` | The full name (the GECOS field of a system account), or the user name |
| `sn` | The last word of `cn` |
| `memberOf` | The DN of each group of the user in `[groups]` |
| `uidNumber`, `gidNumber`, `homeDirectory` | For a system account only |

A group entry has these attributes:

| Attribute | Value |
| --- | --- |
| `objectClass` | `top`, `groupOfNames` |
| `cn` | The group name |
| `member` | The DN of each member |
| `memberUid` | The user name of each member |

## Bind

The LDAP provider accepts simple binds only. It does not accept SASL.
These bind names are correct for a user:

- `uid=alice,ou=people,dc=example,dc=org`
- `uid=alice,dc=example,dc=org`
- `alice`

The service account (`bind_dn`) is for programs that search for a user
before they bind as that user. `bind_password` is a hash, not the
password. To make the hash, use `dmodem-login -hash`.

An unauthenticated bind (a name with no password) is refused, as
RFC 4513 tells. An anonymous bind (no name and no password) is accepted.

## Access

| Client | What it can see |
| --- | --- |
| No bind (anonymous) | The root DSE only. With `anonymous_search = yes`, all entries |
| A user | All entries. With `user_search = no`, the entry of the user and the groups only |
| The service account | All entries |

The root DSE (the entry with the empty DN) is always available. It gives
`namingContexts` and the supported extended operations.

## TLS

A password must not go through a network as clear text. Thus, with
`require_tls = yes` (the default), a bind must use TLS. There are two
ways:

- StartTLS on the `listen` port.
- The `listen_tls` port (ldaps).

A client on a unix socket or on loopback does not have to use TLS.

`tls_cert` and `tls_key` are PEM files. dmodem-login reads them when it
starts. The private key must be readable by the user of dmodem-login only.

## Operations

| Operation | What the LDAP provider does |
| --- | --- |
| Bind (simple) | Checks the password with the backends |
| Search | Gives the entries that agree with the filter. All filter types are supported, except extensible match |
| Compare | Compares one attribute value of an entry |
| StartTLS | Starts TLS on the connection |
| Who am I? (RFC 4532) | Gives the DN of the bind |
| Password Modify (RFC 3062) | Changes the password of the user (see below) |
| Add, Delete, Modify, Modify DN | Refused: the directory is read only |

The LDAP provider also supports the control for simple paged results
(RFC 2696).

## Password changes

With `password_modify = yes` (the default), users can change their
password with Password Modify, for example with `ldappasswd`:

```
ldappasswd -H ldaps://bbs.example.org -D uid=alice,ou=people,dc=example,dc=org -W -A -S
```

The request must contain the old password, also after a bind. A user can
change only the password of that user. The password changes in the
backend that holds the account, in the same way as `mode = passwd` in
the menu. The new password must have `min_password` characters or more.

## Configuration of the clients

Use these values in the program that uses the LDAP provider:

| Value | Setting |
| --- | --- |
| Server | `ldap://<host>:389` with StartTLS, or `ldaps://<host>:636` |
| Base DN of the users | `ou=people,<base_dn>` |
| Filter of the users | `(&(objectClass=inetOrgPerson)(uid=%s))` |
| Attribute of the user name | `uid` |
| Base DN of the groups | `ou=groups,<base_dn>` |
| Filter of the groups | `(&(objectClass=groupOfNames)(member=%s))` |
| Bind DN | `bind_dn` |

## Cautions

- Do not set the `[ldap]` backend of dmodem-login to this LDAP provider.
  This makes a loop.
- The directory shows the user names to all clients that can search.
  If the user names must stay private, set `user_search = no` and do not
  set `anonymous_search`.
- Each failed bind waits for `fail_delay`. `max_clients` limits the
  number of connections. These limits make it slower to guess passwords,
  but they do not stop it. Do not open the LDAP ports to the internet
  if it is not necessary.
