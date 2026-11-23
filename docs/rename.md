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

## What continues to operate

You can install the new version on an old installation. These items
continue to operate:

- `make install` and `make install-freepbx` also install `modemmenu`, a
  link to `dmodem-login`. An `app_dmodem` profile that starts
  `/usr/local/bin/modemmenu` continues to operate.
- The pppd plugin is also installed as `modemmenu.so`, a link to
  `dmodem-login.so`. The plugin also accepts the `modemmenu-socket`
  option.
- If `-config` is not given and `/etc/asterisk/dmodem-login.conf` is not
  there, dmodem-login reads `/etc/asterisk/modemmenu.conf`.
- If `[file] path` is not given and `/etc/asterisk/dmodem-login.users` is
  not there, dmodem-login reads `/etc/asterisk/modemmenu.users`. The
  sign-up uses the same file.
- If `state_dir` is not given and `/var/lib/dmodem-login` is not there,
  dmodem-login uses `/var/lib/modemmenu`.
- If `pam_service` is not given and `/etc/pam.d/dmodem-login` is not
  there, dmodem-login uses the PAM service `modemmenu`.

## What you must change

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
