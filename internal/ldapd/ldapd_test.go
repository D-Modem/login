// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package ldapd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeDir: alice and bob in the users file, carol a system account
type fakeDir struct{}

func (fakeDir) Users() []User { return []User{{Name: "alice"}, {Name: "bob", FullName: "Bob Smith"}} }
func (fakeDir) Lookup(name string) (User, bool) {
	if name == "carol" {
		return User{Name: "carol", FullName: "Carol Jones", Posix: true, UID: 1001, GID: 100, Home: "/home/carol"}, true
	}
	return User{}, false
}
func (fakeDir) Groups() map[string][]string {
	return map[string][]string{"sysops": {"alice"}, "ppp": {"alice", "bob"}}
}

// fake backends: password "<name>pass"
type fakeAuth struct {
	mu  sync.Mutex
	pws map[string]string
}

func (f *fakeAuth) check(_ context.Context, user, pw string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want, ok := f.pws[user]
	if !ok {
		return "", ErrNoUser
	}
	if pw != want {
		return "", ErrBadPassword
	}
	return "file", nil
}

func (f *fakeAuth) change(ctx context.Context, user, old, nw string) error {
	if _, err := f.check(ctx, user, old); err != nil {
		return err
	}
	f.mu.Lock()
	f.pws[user] = nw
	f.mu.Unlock()
	return nil
}

func testCert(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func newTest(t *testing.T, edit func(*Config)) (*Server, *fakeAuth) {
	t.Helper()
	fa := &fakeAuth{pws: map[string]string{"alice": "alicepass", "bob": "bobpass", "carol": "carolpass"}}
	cfg := &Config{
		BaseDN: "dc=example,dc=org", Dir: fakeDir{},
		Authenticate: fa.check, ChangePassword: fa.change,
		ServiceDN:    "cn=reader,dc=example,dc=org",
		ServiceCheck: func(pw string) bool { return pw == "readerpass" },
		TLS:          testCert(t), RequireTLS: true, UserSearch: true, MinPassword: 8,
		Logf: t.Logf,
	}
	if edit != nil {
		edit(cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, fa
}

// dial: a client on loopback TCP (local: no TLS needed)
func dial(t *testing.T, s *Server) *ldap.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln, false)
	t.Cleanup(s.Close)
	c, err := ldap.DialURL("ldap://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// remote: a client that is not local, on a pipe
func remote(t *testing.T, s *Server) *ldap.Conn {
	t.Helper()
	a, b := net.Pipe()
	go s.serveConn(b, false)
	c := ldap.NewConn(a, false)
	c.Start()
	t.Cleanup(func() { c.Close() })
	return c
}

func code(err error) uint16 {
	if err == nil {
		return 0
	}
	if e, ok := err.(*ldap.Error); ok {
		return e.ResultCode
	}
	return 9999
}

func search(c *ldap.Conn, base, filter string, attrs ...string) (*ldap.SearchResult, error) {
	return c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
}

func dns(r *ldap.SearchResult) []string {
	var out []string
	for _, e := range r.Entries {
		out = append(out, e.DN)
	}
	sort.Strings(out)
	return out
}

func TestRootDSEAndAnonymous(t *testing.T) {
	s, _ := newTest(t, nil)
	c := dial(t, s)
	r, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"namingContexts", "supportedExtension"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("root DSE: %v %v", r, err)
	}
	if got := r.Entries[0].GetAttributeValue("namingContexts"); got != "dc=example,dc=org" {
		t.Errorf("namingContexts %q", got)
	}
	if len(r.Entries[0].GetAttributeValues("supportedExtension")) != 3 {
		t.Errorf("supportedExtension %v", r.Entries[0].GetAttributeValues("supportedExtension"))
	}
	if _, err := search(c, "dc=example,dc=org", "(uid=alice)"); code(err) != ldap.LDAPResultInsufficientAccessRights {
		t.Errorf("anonymous search: %v", err)
	}
}

func TestBindAndSearch(t *testing.T) {
	s, _ := newTest(t, nil)
	c := dial(t, s)
	if err := c.Bind("uid=alice,ou=people,dc=example,dc=org", "wrong"); code(err) != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("wrong password: %v", err)
	}
	if err := c.Bind("uid=nobody,ou=people,dc=example,dc=org", "x"); code(err) != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := c.SimpleBind(&ldap.SimpleBindRequest{Username: "uid=alice,ou=people,dc=example,dc=org", AllowEmptyPassword: true}); code(err) != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("unauthenticated bind: %v", err)
	}
	if err := c.Bind("UID=alice, OU=People, DC=Example, DC=org", "alicepass"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	who, err := c.WhoAmI(nil)
	if err != nil || who.AuthzID != "dn:uid=alice,ou=people,dc=example,dc=org" {
		t.Errorf("whoami: %v %v", who, err)
	}

	r, err := search(c, "dc=example,dc=org", "(uid=alice)", "uid", "memberOf", "cn")
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("(uid=alice): %v %v", r, err)
	}
	if mo := r.Entries[0].GetAttributeValues("memberOf"); len(mo) != 2 {
		t.Errorf("memberOf %v", mo)
	}
	if len(r.Entries[0].GetAttributeValues("userPassword")) != 0 {
		t.Error("a password in the entry")
	}

	// a system account, found by its name only
	r, err = search(c, "ou=people,dc=example,dc=org", "(&(objectClass=posixAccount)(uid=carol))")
	if err != nil || len(r.Entries) != 1 || r.Entries[0].GetAttributeValue("uidNumber") != "1001" ||
		r.Entries[0].GetAttributeValue("cn") != "Carol Jones" {
		t.Fatalf("carol: %v %v", r, err)
	}

	r, err = search(c, "ou=people,dc=example,dc=org", "(objectClass=inetOrgPerson)")
	if got := dns(r); err != nil || len(got) != 2 {
		t.Errorf("people: %v %v", got, err)
	}
	r, err = search(c, "dc=example,dc=org", "(&(objectClass=groupOfNames)(member=uid=bob,ou=people,dc=example,dc=org))", "cn")
	if err != nil || len(r.Entries) != 1 || r.Entries[0].GetAttributeValue("cn") != "ppp" {
		t.Errorf("bob's groups: %v %v", dns(r), err)
	}
	r, err = search(c, "dc=example,dc=org", "(|(cn=*smi*)(sn=Smith))")
	if err != nil || len(r.Entries) != 1 || r.Entries[0].GetAttributeValue("uid") != "bob" {
		t.Errorf("substrings: %v %v", dns(r), err)
	}
	r, err = search(c, "dc=example,dc=org", "(!(objectClass=*))")
	if err != nil || len(r.Entries) != 0 {
		t.Errorf("not: %v %v", dns(r), err)
	}
	// one level
	r, err = c.Search(ldap.NewSearchRequest("dc=example,dc=org", ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
	if got := dns(r); err != nil || len(got) != 2 {
		t.Errorf("one level: %v %v", got, err)
	}
	// size limit
	_, err = c.Search(ldap.NewSearchRequest("dc=example,dc=org", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false, "(objectClass=*)", nil, nil))
	if code(err) != ldap.LDAPResultSizeLimitExceeded {
		t.Errorf("size limit: %v", err)
	}
	// paging
	r, err = c.SearchWithPaging(ldap.NewSearchRequest("dc=example,dc=org", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil), 2)
	if err != nil || len(r.Entries) != 7 {
		t.Errorf("paging: %d entries, %v", len(r.Entries), err)
	}
	if _, err := search(c, "dc=other,dc=org", "(objectClass=*)"); code(err) != ldap.LDAPResultNoSuchObject {
		t.Errorf("other base: %v", err)
	}

	ok, err := c.Compare("cn=sysops,ou=groups,dc=example,dc=org", "memberUid", "alice")
	if err != nil || !ok {
		t.Errorf("compare: %v %v", ok, err)
	}
	ok, err = c.Compare("cn=sysops,ou=groups,dc=example,dc=org", "memberUid", "bob")
	if err != nil || ok {
		t.Errorf("compare false: %v %v", ok, err)
	}

	// read only
	if err := c.Del(ldap.NewDelRequest("uid=bob,ou=people,dc=example,dc=org", nil)); code(err) != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("delete: %v", err)
	}
	m := ldap.NewModifyRequest("uid=alice,ou=people,dc=example,dc=org", nil)
	m.Replace("cn", []string{"x"})
	if err := c.Modify(m); code(err) != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("modify: %v", err)
	}
}

func TestUserSearchSelf(t *testing.T) {
	s, _ := newTest(t, func(c *Config) { c.UserSearch = false })
	c := dial(t, s)
	if err := c.Bind("alice", "alicepass"); err != nil {
		t.Fatalf("bind by name: %v", err)
	}
	r, err := search(c, "ou=people,dc=example,dc=org", "(objectClass=person)")
	if got := dns(r); err != nil || len(got) != 1 || got[0] != "uid=alice,ou=people,dc=example,dc=org" {
		t.Errorf("own entry only: %v %v", got, err)
	}
}

func TestServiceAccount(t *testing.T) {
	s, _ := newTest(t, func(c *Config) { c.UserSearch = false })
	c := dial(t, s)
	if err := c.Bind("cn=reader,dc=example,dc=org", "nope"); code(err) != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("service, wrong password: %v", err)
	}
	if err := c.Bind("cn=Reader,dc=example,dc=org", "readerpass"); err != nil {
		t.Fatalf("service bind: %v", err)
	}
	r, err := search(c, "ou=people,dc=example,dc=org", "(objectClass=person)")
	if got := dns(r); err != nil || len(got) != 2 {
		t.Errorf("service sees all: %v %v", got, err)
	}
	// search, then bind as the user (what a wiki does)
	if err := c.Bind(r.Entries[0].DN, "alicepass"); err != nil {
		t.Errorf("bind as found DN: %v", err)
	}
}

func TestRequireTLS(t *testing.T) {
	s, _ := newTest(t, nil)
	c := remote(t, s)
	if err := c.Bind("uid=alice,ou=people,dc=example,dc=org", "alicepass"); code(err) != ldap.LDAPResultConfidentialityRequired {
		t.Fatalf("plain bind from afar: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	if err := c.Bind("uid=alice,ou=people,dc=example,dc=org", "alicepass"); err != nil {
		t.Fatalf("bind after StartTLS: %v", err)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err == nil {
		t.Error("StartTLS twice")
	}
}

func TestLDAPS(t *testing.T) {
	s, _ := newTest(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln, true)
	t.Cleanup(s.Close)
	c, err := ldap.DialURL("ldaps://"+ln.Addr().String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("uid=bob,ou=people,dc=example,dc=org", "bobpass"); err != nil {
		t.Fatalf("ldaps bind: %v", err)
	}
}

func TestPasswordModify(t *testing.T) {
	s, fa := newTest(t, nil)
	c := dial(t, s)
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "alicepass", "newsecret")); code(err) != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("not bound, no user: %v", err)
	}
	if err := c.Bind("uid=alice,ou=people,dc=example,dc=org", "alicepass"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "", "newsecret")); code(err) != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("no old password: %v", err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "alicepass", "short")); code(err) != ldap.LDAPResultConstraintViolation {
		t.Errorf("short: %v", err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("uid=bob,ou=people,dc=example,dc=org", "bobpass", "newsecret")); code(err) != ldap.LDAPResultInsufficientAccessRights {
		t.Errorf("another user's: %v", err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "wrongpass", "newsecret")); code(err) != ldap.LDAPResultInvalidCredentials {
		t.Errorf("wrong old: %v", err)
	}
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest("", "alicepass", "newsecret")); err != nil {
		t.Fatalf("change: %v", err)
	}
	if fa.pws["alice"] != "newsecret" {
		t.Errorf("alice's password %q", fa.pws["alice"])
	}
	if err := c.Bind("uid=alice,ou=people,dc=example,dc=org", "newsecret"); err != nil {
		t.Errorf("bind with the new one: %v", err)
	}
}

func TestEscapeAndNorm(t *testing.T) {
	for in, want := range map[string]string{
		"UID=Alice, OU=People,DC=Example": "uid=alice,ou=people,dc=example",
		"cn=a\\,b,dc=x":                   "cn=a\\,b,dc=x",
		"":                                "",
	} {
		if got, err := NormDN(in); err != nil || got != want {
			t.Errorf("NormDN(%q) = %q, %v", in, got, err)
		}
	}
	if got := escapeRDN(" a,b "); got != "\\ a\\,b\\ " {
		t.Errorf("escapeRDN %q", got)
	}
}
