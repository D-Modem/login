// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestLdapd: [ldapd] over the users file and [groups]: a bind, a search,
// a locked account left out, and a password changed in the users file.
func TestLdapd(t *testing.T) {
	dir := t.TempDir()
	users := filepath.Join(dir, "users")
	os.WriteFile(users, []byte("alice:{PLAIN}secretpw\nbob:{PLAIN}bobspass\npending:!{PLAIN}secret\n"), 0o600)
	sock := filepath.Join(dir, "ldapi.sock")
	p := filepath.Join(dir, "c.conf")
	os.WriteFile(p, []byte(fmt.Sprintf("[general]\nauth = file\nfail_delay = 0\n[file]\npath = %s\n"+
		"[groups]\nsysops = alice\n"+
		"[ldapd]\nlisten = %s\nsocket_mode = 0600\nbase_dn = dc=bbs,dc=test\n"+
		"[item x]\nkey = X\ncommand = true\n", users, sock)), 0o600)
	s, err := loadSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := startLdapd(s)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	nc, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c := ldap.NewConn(nc, false)
	c.Start()
	defer c.Close()
	if err := c.Bind("uid=pending,ou=people,dc=bbs,dc=test", "secret"); err == nil {
		t.Error("a locked account could bind")
	}
	if err := c.Bind("uid=alice,ou=people,dc=bbs,dc=test", "secretpw"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	r, err := c.Search(ldap.NewSearchRequest("ou=people,dc=bbs,dc=test", ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=person)", []string{"uid", "memberOf"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range r.Entries {
		got = append(got, e.GetAttributeValue("uid")+":"+strings.Join(e.GetAttributeValues("memberOf"), ";"))
	}
	if strings.Join(got, " ") != "alice:cn=sysops,ou=groups,dc=bbs,dc=test bob:" {
		t.Errorf("people: %v", got)
	}

	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "secretpw", "anothersecret")); err != nil {
		t.Fatalf("password modify: %v", err)
	}
	b, _ := os.ReadFile(users)
	if strings.Contains(string(b), "alice:{PLAIN}secretpw") || !strings.Contains(string(b), "alice:$2") {
		t.Errorf("users file after the change:\n%s", b)
	}
	if err := c.Bind("uid=alice,ou=people,dc=bbs,dc=test", "anothersecret"); err != nil {
		t.Errorf("bind with the new password: %v", err)
	}
}

// TestLdapdSettings: what [ldapd] refuses
func TestLdapdSettings(t *testing.T) {
	for _, tc := range []struct{ conf, want string }{
		{"listen = tcp:127.0.0.1:389\n", "base_dn"},
		{"listen = tcp:127.0.0.1:389\nbase_dn = nonsense\n", "not a DN"},
		{"listen = 389\nbase_dn = dc=x\n", "tcp:host:port"},
		{"listen_tls = tcp:127.0.0.1:636\nbase_dn = dc=x\n", "no tls_cert"},
		{"listen = /run/x.sock\nsocket_mode = 0666\nbase_dn = dc=x\n", "anyone"},
		{"listen = tcp:127.0.0.1:389\nbase_dn = dc=x\nbind_dn = cn=r,dc=x\nbind_password = secret\n", "a hash"},
		{"listen = tcp:127.0.0.1:389\nbase_dn = dc=x\nbind_dn = cn=r,dc=x\n", "both or neither"},
	} {
		dir := t.TempDir()
		users := filepath.Join(dir, "users")
		os.WriteFile(users, nil, 0o600)
		p := filepath.Join(dir, "c.conf")
		os.WriteFile(p, []byte(fmt.Sprintf("[general]\nauth = file\n[file]\npath = %s\n[ldapd]\n%s[item x]\nkey = X\ncommand = true\n", users, tc.conf)), 0o600)
		_, err := loadSettings(p)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.conf, err, tc.want)
		}
	}
}
