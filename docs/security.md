# Security notes


- Asterisk usually runs as its own user. That user must be able to read
  the users file and dmodem-login.conf, and no other user must be able to
  read them. dmodem-login.conf can contain database and LDAP passwords.
- If dmodem-login runs as root, the Asterisk of app_dmodem also runs as root.
  Root is necessary for `auth = system` with local accounts, or for
  `run_as`.
- dmodem-login gives the password to the selection, unless
  `pass_password = no`. In the environment, the same user and root can
  read the password (`/proc/PID/environ`). If the program reads the
  session file, use `session_file` to keep the password out of the
  environment.
- Do not put `{password}` in a command line. Other users can see the
  arguments of all processes. Use `MODEM_PASSWORD` or the session file.
- On many networks, it is possible to forge the caller ID. With
  `[number] user`, any caller who presents the number logs in. Use this
  feature only for numbers that your own network can confirm.
- With the signup setting `pending = yes` (the default), new accounts
  stay locked until you unlock them. With `pending = no`, each caller gets
  an account and access to all items that have no `users` or `groups`.
  Give `guest = yes` to public items, and give the other items to groups
  only.
- A signup can make accounts in SQL, LDAP and the system (refer to
  [New accounts in each backend](authentication.md#new-accounts-in-each-backend)).
  The account of `[ldap] add_bind_dn` can add entries: give it access to
  the `add_dn` branch only. `[system] create_command` runs as the user of
  dmodem-login, which is root for `useradd`. Use `pending = yes` with these
  backends, and keep the password of `add_bind_dn` out of a configuration
  file that other users can read.
- The socket of a server is only as safe as its permissions. Each user
  who can connect to it gets a login prompt. With `trust_user`, that user
  can log in as any user that they name. Use `socket_mode` and
  `socket_group` to limit the socket to Asterisk or the front menu.
- The auth socket tells if a password is correct. Thus each user who can
  connect to it can use it to guess passwords. dmodem-login sends each
  "wrong password" answer `fail_delay` late. Limit the socket to the user
  of the BBS (`socket_mode` 0660 or 0600, `socket_group`, `allow_users`).
  dmodem-login refuses a mode that gives access to other users, and it also
  refuses TCP.
- The LDAP provider (`[ldapd]`) also tells if a password is correct, and
  it can listen on a network. Each failed bind waits for `fail_delay`.
  With `require_tls = yes` (the default), a password from a network must
  go through TLS. Do not open the LDAP ports to the internet if it is not
  necessary. `bind_password` must be a hash. Refer to
  [the LDAP provider](ldap-provider.md).
- The PAP of AutoPPP sends the password as clear text on the line, as all
  PAP does. On a SIP trunk, use SRTP or a network that you trust.
- The log (by default, the auth facility of syslog) records logins,
  failures and selections. It never records passwords. dmodem-login never
  writes the log to the line, because the caller can see the line.
