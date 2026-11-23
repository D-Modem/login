# dmodem-login documentation

- [Building](building.md): Go, PAM and `make install`.
- [Running it from app_dmodem](running.md): one program for each call, one server on a unix socket, and FreePBX.
- [Configuration](configuration.md): `dmodem-login.conf`, the connect rate, terminals, the message of the day, the menu (full screen or lines) and its items, guests and sign-up, caller ID, time limits, drop files, last callers, and the transfer of callers to a different program.
- [Configuration reference](reference.md): all sections and keys, from the sample.
- [The sysop's setup](setup.md): `dmodem-login -setup`, to change the configuration on a full screen, at the console or on the line.
- [Authentication](authentication.md): users file, LDAP, SQL, system accounts (PAM), password changes and the auth socket.
- [The LDAP provider](ldap-provider.md): an LDAP server for other programs, with the same users and passwords.
- [PPP dialers](ppp.md): AutoPPP and PAP, and the pppd plugin.
- [AOL callers](aol.md): the classic AOL client when it dials in, and the emulation of its network.
- [Security notes](security.md).
- [Tests](testing.md).
- [The rename from modemmenu](rename.md): the new names, and what to change on an old installation.

The samples: [dmodem-login.conf.sample](../samples/dmodem-login.conf.sample), [dmodem-login.users.sample](../samples/dmodem-login.users.sample), [dmodem-login.pam.sample](../samples/dmodem-login.pam.sample), [dmodem-login.service.sample](../samples/dmodem-login.service.sample), [dmodem-login-authd.service.sample](../samples/dmodem-login-authd.service.sample), [dmodem-login-ldapd.service.sample](../samples/dmodem-login-ldapd.service.sample).
