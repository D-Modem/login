# Building


You must have Go 1.22 or later. Use these commands:

```
make                    # or: go build ./cmd/dmodem-login (-tags pam for PAM)
make PAM=0              # without PAM, when libpam's headers are there
make test
make install            # /usr/local/bin/dmodem-login, and the samples into
                        # /etc/asterisk (and /etc/pam.d) if there are none
```

If the headers of libpam are installed, `make` builds with PAM. The
package is `libpam0g-dev` on Debian and Ubuntu, and `pam-devel` on Fedora.
If the headers are not installed, dmodem-login builds with the other
backends only. Then `auth = system` is a configuration error.

## The source

The source has one Go module and one program:

| Where | What |
| --- | --- |
| `cmd/dmodem-login/` | the program: the login, the menu, the access rules and time limits, the selections, `-serve`, AutoPPP, drop files and the server of the auth socket |
| `internal/config/` | the sections and keys of dmodem-login.conf, and the `{name}` templates |
| `internal/term/` | the line of the caller: read and write operations, line edits, terminal detection and PETSCII |
| `internal/auth/` | the backends (users file, LDAP, SQL, system through PAM) and password changes |
| `internal/telnet/` | the telnet client of `mode = telnet` items |
| `authd/` | the protocol of the auth socket and a client, which other programs (for example, a BBS) can import |
| `pppd/` | the `dmodem-login.so` plugin for pppd, in C |
| `dialup/` | the network for PPP callers: VRF, firewall and DNS with overrides (`make install-dialup`) |
| `samples/` | samples of dmodem-login.conf, the users file, PAM and systemd |
| `freepbx/` | the FreePBX configuration |
| `tools/confref/` | makes docs/reference.md from samples/dmodem-login.conf.sample |

