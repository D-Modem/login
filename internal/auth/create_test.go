// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/D-Modem/login/internal/config"
	"github.com/go-ldap/ldap/v3"
)

// TestFileCreateUser: a new line (locked when pending), a name in any
// case refused, and the line taken back without the others
func TestFileCreateUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	os.WriteFile(path, []byte("alice:{PLAIN}pw"), 0o600) // no line end
	f := FileAt(path, "auto")
	ctx := context.Background()
	if has, known, err := f.HasUser(ctx, "ALICE"); !has || !known || err != nil {
		t.Errorf("HasUser(ALICE): %v %v %v", has, known, err)
	}
	if err := f.CreateUser(ctx, NewAccount{User: "carol", Password: "carol-pw", Note: "signup a:b"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Authenticate(ctx, "carol", "carol-pw"); err != nil {
		t.Errorf("carol: %v", err)
	}
	if err := f.CreateUser(ctx, NewAccount{User: "Carol", Password: "x"}); !errors.Is(err, ErrTaken) {
		t.Errorf("a second carol: %v", err)
	}
	if err := f.CreateUser(ctx, NewAccount{User: "dave", Password: "dave-pw", Pending: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.Authenticate(ctx, "dave", "dave-pw"); !errors.Is(err, ErrBadPassword) {
		t.Errorf("pending dave: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "alice:{PLAIN}pw\ncarol:$2a$") || !strings.Contains(string(b), ":signup a b\n") ||
		!strings.Contains(string(b), "\ndave:!$2a$") {
		t.Errorf("users file:\n%s", b)
	}
	if err := f.RemoveUser(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveUser(ctx, "carol"); !errors.Is(err, ErrNoUser) {
		t.Errorf("carol again: %v", err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "carol") || !strings.HasPrefix(string(b), "alice:{PLAIN}pw\ndave:!") {
		t.Errorf("after the removal:\n%s", b)
	}
}

// sqlUsers: a [sql] backend on a new SQLite file with alice, and the
// keys of vals
func sqlUsers(t *testing.T, vals map[string]string) (*SQL, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "users.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE users (username TEXT UNIQUE, password TEXT, enabled INT, note TEXT);
		INSERT INTO users VALUES ('alice', '{PLAIN}pw', 1, '');`); err != nil {
		t.Fatal(err)
	}
	all := map[string]string{"driver": "sqlite", "dsn": dbPath,
		"query": "SELECT password FROM users WHERE username = ? AND enabled = 1"}
	for k, v := range vals {
		all[k] = v
	}
	a, err := NewSQL(&config.Section{Name: "sql", Vals: all})
	if err != nil {
		t.Fatal(err)
	}
	return a.(*SQL), db
}

// TestSQLCreateUser: insert_query with pending and note, HasUser by
// query and by exists_query, delete_query
func TestSQLCreateUser(t *testing.T) {
	ctx := context.Background()
	a, db := sqlUsers(t, map[string]string{
		"insert_query": "INSERT INTO users (username, password, enabled, note) VALUES (?, ?, 1 - ?, ?)",
		"insert_args":  "user password pending note",
		"delete_query": "DELETE FROM users WHERE username = ?"})
	if !a.CanCreate() || !a.CanLock() {
		t.Error("CanCreate, CanLock: false")
	}
	if has, known, err := a.HasUser(ctx, "alice"); !has || !known || err != nil {
		t.Errorf("HasUser(alice): %v %v %v", has, known, err)
	}
	if has, _, _ := a.HasUser(ctx, "carol"); has {
		t.Error("HasUser(carol): true")
	}
	if err := a.CreateUser(ctx, NewAccount{User: "carol", Password: "carol-pw", Note: "signup"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate(ctx, "carol", "carol-pw"); err != nil {
		t.Errorf("carol: %v", err)
	}
	if err := a.CreateUser(ctx, NewAccount{User: "dave", Password: "dave-pw", Pending: true}); err != nil {
		t.Fatal(err)
	}
	// the query refuses rows that are not enabled: pending
	if err := a.Authenticate(ctx, "dave", "dave-pw"); !errors.Is(err, ErrNoUser) {
		t.Errorf("pending dave: %v", err)
	}
	if err := a.CreateUser(ctx, NewAccount{User: "carol", Password: "x"}); err == nil {
		t.Error("a second carol (UNIQUE): no error")
	}
	if err := a.RemoveUser(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'carol'").Scan(&n)
	if n != 0 {
		t.Errorf("carol: %d rows after the removal", n)
	}

	// a query with the password as an argument cannot say: exists_query
	b, _ := sqlUsers(t, map[string]string{"args": "user password", "hash": "none",
		"query": "SELECT 1 FROM users WHERE username = ? AND password = ?"})
	if b.CanCreate() || b.CanLock() {
		t.Error("no insert_query: CanCreate or CanLock")
	}
	if _, known, _ := b.HasUser(ctx, "alice"); known {
		t.Error("args = user password: HasUser known")
	}
	if err := b.RemoveUser(ctx, "alice"); !errors.Is(err, ErrCannotRemove) {
		t.Errorf("no delete_query: %v", err)
	}
	c, _ := sqlUsers(t, map[string]string{"args": "user password", "hash": "none",
		"query":        "SELECT 1 FROM users WHERE username = ? AND password = ?",
		"exists_query": "SELECT 1 FROM users WHERE username = ?"})
	if has, known, err := c.HasUser(ctx, "alice"); !has || !known || err != nil {
		t.Errorf("exists_query: %v %v %v", has, known, err)
	}

	for _, bad := range []map[string]string{{"insert_args": "user nonsense"}, {"insert_hash": "md5"},
		{"insert_query": "INSERT INTO users (password) VALUES (?)", "insert_args": "password"}} {
		vals := map[string]string{"driver": "sqlite", "dsn": ":memory:", "query": "SELECT 1"}
		for k, v := range bad {
			vals[k] = v
		}
		if _, err := NewSQL(&config.Section{Name: "sql", Vals: vals}); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
}

// TestSystemCreateUser: create_command gets {user}, {pending} and the
// password; remove_command {user}; a failed command's output in its error
func TestSystemCreateUser(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	a := &System{
		createCommand:  "printf '%s %s %s\\n' {user} {pending} \"$(cat)\" >> " + out,
		removeCommand:  "echo removed {user} >> " + out,
		commandTimeout: 5 * time.Second,
		lookup:         func(string) (*Account, error) { return nil, ErrNoUser },
	}
	ctx := context.Background()
	if has, known, err := a.HasUser(ctx, "carol"); has || !known || err != nil {
		t.Errorf("HasUser: %v %v %v", has, known, err)
	}
	if err := a.CreateUser(ctx, NewAccount{User: "o'brien", Password: "pw $x", Pending: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveUser(ctx, "o'brien"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if string(b) != "o'brien yes pw $x\nremoved o'brien\n" {
		t.Errorf("the commands' output: %q", b)
	}
	a.createCommand = "echo useradd: no; exit 9"
	if err := a.CreateUser(ctx, NewAccount{User: "x", Password: "y"}); err == nil || !strings.Contains(err.Error(), "useradd: no") {
		t.Errorf("a failed command: %v", err)
	}
	a.removeCommand = ""
	if err := a.RemoveUser(ctx, "x"); !errors.Is(err, ErrCannotRemove) {
		t.Errorf("no remove_command: %v", err)
	}
}

// fakeCreator: an AccountCreator that records what it does, and fails
// CreateUser with fail
type fakeCreator struct {
	name string
	fail error
	log  *[]string
}

// Name: the fake's name
func (f *fakeCreator) Name() string { return f.name }

// CanCreate: always
func (f *fakeCreator) CanCreate() bool { return true }

// CanLock: always
func (f *fakeCreator) CanLock() bool { return true }

// HasUser: never
func (f *fakeCreator) HasUser(context.Context, string) (bool, bool, error) { return false, true, nil }

// CreateUser: recorded, or fail
func (f *fakeCreator) CreateUser(_ context.Context, acct NewAccount) error {
	if f.fail != nil {
		return f.fail
	}
	*f.log = append(*f.log, "create "+f.name)
	return nil
}

// RemoveUser: recorded
func (f *fakeCreator) RemoveUser(context.Context, string) error {
	*f.log = append(*f.log, "remove "+f.name)
	return nil
}

// TestCreateAccounts: each backend in turn; a failure takes back the
// accounts already made, in the reverse sequence
func TestCreateAccounts(t *testing.T) {
	var log []string
	logf := func(string, ...any) {}
	ok := []AccountCreator{&fakeCreator{"a", nil, &log}, &fakeCreator{"b", nil, &log}}
	names, err := CreateAccounts(context.Background(), ok, NewAccount{User: "u"}, logf)
	if err != nil || strings.Join(names, ",") != "a,b" {
		t.Errorf("%v %v", names, err)
	}
	log = nil
	bad := []AccountCreator{&fakeCreator{"a", nil, &log}, &fakeCreator{"b", nil, &log},
		&fakeCreator{"c", ErrTaken, &log}, &fakeCreator{"d", nil, &log}}
	_, err = CreateAccounts(context.Background(), bad, NewAccount{User: "u"}, logf)
	if !errors.Is(err, ErrTaken) || !strings.HasPrefix(err.Error(), "c: ") {
		t.Errorf("error: %v", err)
	}
	if strings.Join(log, ",") != "create a,create b,remove b,remove a" {
		t.Errorf("steps: %v", log)
	}
}

// TestLDAPAddRequest: add_attributes with {user}, the pending ones in
// place of those of the same name, the DN's attribute, and AD's unicodePwd
func TestLDAPAddRequest(t *testing.T) {
	a, err := NewLDAP(&config.Section{Name: "ldap", Vals: map[string]string{
		"search_base": "ou=people,dc=x", "add_dn": "uid={user},ou=people,dc=x", "add_bind_dn": "cn=admin,dc=x",
		"add_attributes":         "objectClass=inetOrgPerson | objectClass=posixAccount | cn={user} | sn={user} | description=a",
		"add_pending_attributes": "description=pending | pwdAccountLockedTime=000001010000Z"}})
	if err != nil {
		t.Fatal(err)
	}
	la := a.(*LDAP)
	attrs := func(r *ldap.AddRequest) string {
		var s []string
		for _, at := range r.Attributes {
			s = append(s, at.Type+"="+strings.Join(at.Vals, "+"))
		}
		return strings.Join(s, " ")
	}
	r, err := la.addRequest(NewAccount{User: "a,b"})
	if err != nil {
		t.Fatal(err)
	}
	if r.DN != `uid=a\,b,ou=people,dc=x` ||
		attrs(r) != "objectClass=inetOrgPerson+posixAccount cn=a,b sn=a,b description=a uid=a,b" {
		t.Errorf("%s: %s", r.DN, attrs(r))
	}
	r, _ = la.addRequest(NewAccount{User: "carol", Pending: true})
	if attrs(r) != "objectClass=inetOrgPerson+posixAccount cn=carol sn=carol description=pending pwdAccountLockedTime=000001010000Z uid=carol" {
		t.Errorf("pending: %s", attrs(r))
	}
	la.passwordChange = "ad"
	r, _ = la.addRequest(NewAccount{User: "carol", Password: "pw"})
	if !strings.HasSuffix(attrs(r), "unicodePwd="+adPassword("pw")) {
		t.Errorf("ad: %s", attrs(r))
	}
	for _, bad := range []map[string]string{{"add_dn": "ou=people,dc=x"}, {"add_dn": "uid={user},dc=x"},
		{"add_attributes": "objectClass"}} {
		vals := map[string]string{"search_base": "dc=x"}
		for k, v := range bad {
			vals[k] = v
		}
		if _, err := NewLDAP(&config.Section{Name: "ldap", Vals: vals}); err == nil {
			t.Errorf("%v: no error", bad)
		}
	}
}

// DMODEM_LOGIN_TEST_LDAP (see ldap_test.go) and
// DMODEM_LOGIN_TEST_LDAP_ADMIN=dn:password, an account that can add
// entries under ou=people: a new entry, its password, taken back
func TestLDAPCreateUser(t *testing.T) {
	url, admin := os.Getenv("DMODEM_LOGIN_TEST_LDAP"), os.Getenv("DMODEM_LOGIN_TEST_LDAP_ADMIN")
	if url == "" || admin == "" {
		t.Skip("DMODEM_LOGIN_TEST_LDAP or DMODEM_LOGIN_TEST_LDAP_ADMIN is not set")
	}
	dn, pw, _ := strings.Cut(admin, ":")
	a, err := NewLDAP(&config.Section{Name: "ldap", Vals: map[string]string{
		"url": url, "search_base": "ou=people,dc=example,dc=com",
		"add_dn": "uid={user},ou=people,dc=example,dc=com", "add_bind_dn": dn, "add_bind_password": pw}})
	if err != nil {
		t.Fatal(err)
	}
	la := a.(*LDAP)
	ctx := context.Background()
	if has, known, err := la.HasUser(ctx, "lduser"); !has || !known || err != nil {
		t.Errorf("HasUser(lduser): %v %v %v", has, known, err)
	}
	if has, _, err := la.HasUser(ctx, "ldnew"); has || err != nil {
		t.Errorf("HasUser(ldnew): %v %v", has, err)
	}
	if err := la.CreateUser(ctx, NewAccount{User: "ldnew", Password: "ldnew-pw"}); err != nil {
		t.Fatal(err)
	}
	defer la.RemoveUser(ctx, "ldnew")
	if err := a.Authenticate(ctx, "ldnew", "ldnew-pw"); err != nil {
		t.Errorf("the new entry: %v", err)
	}
	if has, _, _ := la.HasUser(ctx, "ldnew"); !has {
		t.Error("HasUser(ldnew) after: false")
	}
	if err := la.CreateUser(ctx, NewAccount{User: "ldnew", Password: "x"}); !errors.Is(err, ErrTaken) {
		t.Errorf("a second ldnew: %v", err)
	}
	if err := la.RemoveUser(ctx, "ldnew"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate(ctx, "ldnew", "ldnew-pw"); !errors.Is(err, ErrNoUser) {
		t.Errorf("after the removal: %v", err)
	}
}
