// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/D-Modem/menu/internal/auth"
	"github.com/D-Modem/menu/internal/config"
	"github.com/D-Modem/menu/internal/ldapd"
)

// The LDAP provider: [ldapd].  An LDAPv3 server over the backends of the
// login prompt, so that other programs (the BBS, a wiki, mail) take the
// same users and passwords.  Read only; the users come from the users
// file, [groups] and the system's accounts (looked up by name).

// ldapdSettings: [ldapd]
type ldapdSettings struct {
	listen          string // tcp:host:port or a unix socket path; "" none
	listenTLS       string // tcp:host:port, ldaps; "" none
	socketMode      os.FileMode
	socketGroup     string
	baseDN          string
	tlsCert, tlsKey string
	tls             *tls.Config
	requireTLS      bool
	anonymous       bool
	userSearch      bool
	bindDN          string
	bindPassword    string // hashed, as CheckPassword reads it
	passwordModify  bool
	minPassword     int
	maxClients      int
	idleTimeout     time.Duration
	sizeLimit       int
}

// loadLdapd: [ldapd]; nil when it has no listen and no listen_tls
func loadLdapd(sec *config.Section) (*ldapdSettings, error) {
	l := &ldapdSettings{
		listen:      sec.Get("listen", ""),
		listenTLS:   sec.Get("listen_tls", ""),
		socketGroup: sec.Get("socket_group", ""),
		baseDN:      sec.Get("base_dn", ""),
		tlsCert:     sec.Get("tls_cert", ""),
		tlsKey:      sec.Get("tls_key", ""),
		bindDN:      sec.Get("bind_dn", ""),
		// the service account's password is a hash, never the text
		bindPassword: sec.Get("bind_password", ""),
	}
	if l.listen == "" && l.listenTLS == "" {
		return nil, nil
	}
	if l.baseDN == "" {
		return nil, fmt.Errorf("[ldapd] base_dn: not set (for example dc=example,dc=org)")
	}
	if n, err := ldapd.NormDN(l.baseDN); err != nil || n == "" {
		return nil, fmt.Errorf("[ldapd] base_dn: %q is not a DN", l.baseDN)
	}
	for _, v := range []struct{ key, val string }{{"listen", l.listen}, {"listen_tls", l.listenTLS}} {
		if v.val != "" && !strings.HasPrefix(v.val, "tcp:") && !strings.HasPrefix(v.val, "/") {
			return nil, fmt.Errorf("[ldapd] %s: %q (tcp:host:port, or a socket path)", v.key, v.val)
		}
	}
	if strings.HasPrefix(l.listenTLS, "/") {
		return nil, fmt.Errorf("[ldapd] listen_tls: %q (tcp:host:port; a unix socket needs no TLS)", l.listenTLS)
	}
	mode, err := parseMode(sec.Get("socket_mode", "0660"))
	if err != nil {
		return nil, fmt.Errorf("[ldapd] socket_mode: %v", err)
	}
	l.socketMode = mode
	if (l.tlsCert == "") != (l.tlsKey == "") {
		return nil, fmt.Errorf("[ldapd] tls_cert and tls_key: set both or neither")
	}
	if l.tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(l.tlsCert, l.tlsKey)
		if err != nil {
			return nil, fmt.Errorf("[ldapd] tls_cert, tls_key: %v", err)
		}
		l.tls = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	if l.listenTLS != "" && l.tls == nil {
		return nil, fmt.Errorf("[ldapd] listen_tls: no tls_cert and tls_key")
	}
	if l.requireTLS, err = sec.Bool("require_tls", true); err != nil {
		return nil, err
	}
	if l.anonymous, err = sec.Bool("anonymous_search", false); err != nil {
		return nil, err
	}
	if l.userSearch, err = sec.Bool("user_search", true); err != nil {
		return nil, err
	}
	if l.passwordModify, err = sec.Bool("password_modify", true); err != nil {
		return nil, err
	}
	if l.minPassword, err = sec.Int("min_password", 8); err != nil {
		return nil, err
	}
	if l.maxClients, err = sec.Int("max_clients", 64); err != nil {
		return nil, err
	}
	if l.maxClients < 1 {
		return nil, fmt.Errorf("[ldapd] max_clients: %d", l.maxClients)
	}
	if l.sizeLimit, err = sec.Int("size_limit", 1000); err != nil {
		return nil, err
	}
	if l.idleTimeout, err = sec.Duration("idle_timeout", 5*time.Minute); err != nil {
		return nil, err
	}
	if (l.bindDN == "") != (l.bindPassword == "") {
		return nil, fmt.Errorf("[ldapd] bind_dn and bind_password: set both or neither")
	}
	if l.bindDN != "" {
		if n, err := ldapd.NormDN(l.bindDN); err != nil || n == "" {
			return nil, fmt.Errorf("[ldapd] bind_dn: %q is not a DN", l.bindDN)
		}
		// a hash only: the file is readable by more than the server
		if !strings.HasPrefix(l.bindPassword, "$2") && !strings.HasPrefix(l.bindPassword, "{SSHA") &&
			!strings.HasPrefix(l.bindPassword, "{SHA") {
			return nil, fmt.Errorf("[ldapd] bind_password: a hash (modemmenu -hash), not the password")
		}
		if _, err := auth.CheckPassword(l.bindPassword, "", "auto"); err != nil {
			return nil, fmt.Errorf("[ldapd] bind_password: %v", err)
		}
	}
	return l, nil
}

// parseMode: a socket's mode, octal, that does not let everyone in
func parseMode(v string) (os.FileMode, error) {
	var mode uint64
	if _, err := fmt.Sscanf(v, "%o", &mode); err != nil || mode > 0o777 {
		return 0, fmt.Errorf("%q (octal, e.g. 0660)", v)
	}
	if mode&0o007 != 0 {
		return 0, fmt.Errorf("%04o lets anyone connect", mode)
	}
	return os.FileMode(mode), nil
}

// directory: the users and groups that [ldapd] serves
type directory struct{ s *settings }

func (d directory) Users() []ldapd.User {
	var out []ldapd.User
	seen := map[string]bool{}
	for _, b := range d.s.backends {
		l, ok := b.(auth.Lister)
		if !ok {
			continue
		}
		us, err := l.ListUsers()
		if err != nil {
			logf("ldap: %s: %v", b.Name(), err)
			continue
		}
		for _, u := range us {
			if !seen[u.Name] && d.s.userPattern.MatchString(u.Name) {
				seen[u.Name] = true
				out = append(out, toLDAPUser(u))
			}
		}
	}
	return out
}

func (d directory) Lookup(name string) (ldapd.User, bool) {
	if !d.s.userPattern.MatchString(name) {
		return ldapd.User{}, false
	}
	for _, b := range d.s.backends {
		l, ok := b.(auth.Looker)
		if !ok {
			continue
		}
		u, err := l.LookupUser(name)
		if err == nil {
			return toLDAPUser(u), true
		}
		if !errors.Is(err, auth.ErrNoUser) {
			logf("ldap: %s: %v", b.Name(), err)
		}
	}
	return ldapd.User{}, false
}

func (d directory) Groups() map[string][]string { return d.s.groups }

func toLDAPUser(u auth.DirUser) ldapd.User {
	return ldapd.User{Name: u.Name, FullName: u.FullName, Posix: u.Posix,
		UID: u.UID, GID: u.GID, Home: u.Home, Shell: u.Shell}
}

// quiet: the line of a password change that has no caller
type quiet struct{}

func (quiet) Write(string) error { return nil }

// newLdapd: the LDAP server of s
func newLdapd(s *settings) (*ldapd.Server, error) {
	l := s.ldapd
	cfg := &ldapd.Config{
		BaseDN: l.baseDN,
		Dir:    directory{s},
		Authenticate: func(ctx context.Context, user, password string) (string, error) {
			return auth.Authenticate(ctx, s.backends, user, password, logf)
		},
		ValidUser:       s.userPattern.MatchString,
		Burn:            auth.Burn,
		TLS:             l.tls,
		RequireTLS:      l.requireTLS,
		AnonymousSearch: l.anonymous,
		UserSearch:      l.userSearch,
		MinPassword:     l.minPassword,
		FailDelay:       s.failDelay,
		IdleTimeout:     l.idleTimeout,
		SizeLimit:       l.sizeLimit,
		MaxClients:      l.maxClients,
		Logf:            logf,
	}
	if l.bindDN != "" {
		cfg.ServiceDN = l.bindDN
		cfg.ServiceCheck = func(pw string) bool {
			ok, err := auth.CheckPassword(l.bindPassword, pw, "auto")
			return ok && err == nil
		}
	}
	if l.passwordModify {
		cfg.ChangePassword = func(ctx context.Context, user, old, new string) error {
			return changePassword(ctx, s, user, old, new)
		}
	}
	return ldapd.New(cfg)
}

// changePassword: the old password checked, the new one set in the
// backend that holds the account
func changePassword(ctx context.Context, s *settings, user, old, new string) error {
	name, err := auth.Authenticate(ctx, s.backends, user, old, logf)
	if err != nil {
		return ldapd.ErrBadPassword
	}
	for _, b := range s.backends {
		if b.Name() != name {
			continue
		}
		c, ok := b.(auth.PasswordChanger)
		if !ok || !c.CanChangePassword() {
			break
		}
		err := c.ChangePassword(ctx, quiet{}, user, old, new)
		if errors.Is(err, auth.ErrRefused) {
			return fmt.Errorf("%w: %v", ldapd.ErrRefused, err)
		}
		return err
	}
	return ldapd.ErrCannot
}

// startLdapd: the LDAP server on its listeners, in the background; nil
// when there is no [ldapd]
func startLdapd(s *settings) (*ldapd.Server, error) {
	if s.ldapd == nil {
		return nil, nil
	}
	srv, err := newLdapd(s)
	if err != nil {
		return nil, fmt.Errorf("[ldapd] %v", err)
	}
	l := s.ldapd
	var lns []net.Listener
	closeAll := func() {
		for _, ln := range lns {
			ln.Close()
		}
	}
	if l.listen != "" {
		ln, err := listen(&serverSettings{listen: l.listen, socketMode: l.socketMode, socketGroup: l.socketGroup})
		if err != nil {
			return nil, fmt.Errorf("[ldapd] listen: %v", err)
		}
		lns = append(lns, ln)
		logf("LDAP on %s", l.listen)
		go srv.Serve(ln, false)
	}
	if l.listenTLS != "" {
		ln, err := listen(&serverSettings{listen: l.listenTLS})
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("[ldapd] listen_tls: %v", err)
		}
		logf("LDAP over TLS on %s", l.listenTLS)
		go srv.Serve(ln, true)
	}
	return srv, nil
}

// runLdapd: modemmenu -ldapd, the LDAP provider alone, until SIGTERM
func runLdapd(s *settings) int {
	if s.ldapd == nil {
		fmt.Fprintln(os.Stderr, "modemmenu: -ldapd: no [ldapd] listen or listen_tls")
		return 2
	}
	srv, err := startLdapd(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "modemmenu:", err)
		return 1
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	sig := <-ch
	logf("%v: stopping", sig)
	srv.Close()
	return 0
}
