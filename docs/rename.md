# The rename from modemmenu

The old name of dmodem-login is modemmenu. The old name of the repository
is D-Modem/menu. Its new name is
[D-Modem/login](https://github.com/D-Modem/login). The Go module is now
`github.com/D-Modem/login`.

## What changed

| Old name | New name |
| --- | --- |
| `modemmenu` (the program) | `dmodem-login` |
| `/etc/asterisk/modemmenu.conf` | `/etc/asterisk/dmodem-login.conf` |
| `/etc/asterisk/modemmenu.users` | `/etc/asterisk/dmodem-login.users` |
| `/etc/pam.d/modemmenu` | `/etc/pam.d/dmodem-login` |
| `/var/lib/modemmenu` | `/var/lib/dmodem-login` |
| `/run/modemmenu/modemmenu.sock` | `/run/dmodem-login/dmodem-login.sock` |
| `/etc/modemmenu/` (FreePBX, dial-up network) | `/etc/dmodem-login/` |
| `modemmenu.so` (the pppd plugin) | `dmodem-login.so` |
| `modemmenu-socket` (the option of the plugin) | `dmodem-login-socket` |
| `modemmenu*.service` | `dmodem-login*.service` |
| `MODEMMENU_*` (environment) | `DMODEM_LOGIN_*` |
| nftables table `modemmenu_dialup` | `dmodem_login_dialup` |

## What you must change

dmodem-login does not read the old names. On an old installation, do
these steps before you start the new version.

- Rename `/etc/asterisk/modemmenu.conf` to
  `/etc/asterisk/dmodem-login.conf`, or give the old path with `-config`.
- Rename `/etc/asterisk/modemmenu.users` to
  `/etc/asterisk/dmodem-login.users`, or give the old path in
  `[file] path`.
- Rename `/var/lib/modemmenu` to `/var/lib/dmodem-login`, or give the
  old path in `state_dir`.
- Rename `/etc/pam.d/modemmenu` to `/etc/pam.d/dmodem-login`, or set
  `pam_service = modemmenu`.
- In each pppd option file, change the `modemmenu-socket` option to
  `dmodem-login-socket`.
- The program is now `/usr/local/bin/dmodem-login`. Change each
  `app_dmodem` profile that starts `/usr/local/bin/modemmenu`, and each
  pppd option file that loads `modemmenu.so`. Then delete the old
  program and the old plugin.
- The default socket of `-serve` is now
  `/run/dmodem-login/dmodem-login.sock`. If your configuration does not
  give `[server] listen`, set it to the old path, or change the
  `app_dmodem` profile to the new path.
- The systemd units have new names. Disable the old unit, then enable the
  new unit. For example:

  ```
  systemctl disable --now modemmenu.service
  systemctl enable --now dmodem-login.service
  ```

- The new units of FreePBX and of the dial-up network read their files in
  `/etc/dmodem-login/`. Move the files from `/etc/modemmenu/` to
  `/etc/dmodem-login/`, and rename `modemmenu.conf` to `dmodem-login.conf`
  and `modemmenu.users` to `dmodem-login.users`. Then change the paths in
  the files that give them.
- The dial-up network uses the new nftables table. After you install the
  new version, restart `dmodem-login-dialup.service`. Then delete the old
  tables:

  ```
  nft delete table inet modemmenu_dialup
  nft delete table ip modemmenu_dialup_nat
  ```

- A program that sets `MODEMMENU_*` environment variables must use the
  `DMODEM_LOGIN_*` names.
- A Go program that imports `github.com/D-Modem/menu/authd` must import
  `github.com/D-Modem/login/authd`.
