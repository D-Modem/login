// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signupConf: accessConf with auth = file sql, an SQLite database with
// erin in it (whom query cannot find without her password), and the
// [sql] keys of sqlKeys
func signupConf(t *testing.T, dir, sqlKeys string) (string, *sql.DB) {
	t.Helper()
	conf := accessConf(t, dir, "")
	dbPath := filepath.Join(dir, "users.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.Exec(`CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT, enabled INT);
		INSERT OR IGNORE INTO users VALUES ('erin', 'erin-pw', 1);`)
	b, _ := os.ReadFile(conf)
	s := strings.Replace(string(b), "auth = file\n", "auth = file sql\n", 1)
	s += fmt.Sprintf("\n[sql]\ndriver = sqlite\ndsn = %s\n"+
		"query = SELECT 1 FROM users WHERE username = ? AND password = ? AND enabled = 1\n"+
		"args = user password\nhash = none\n%s\n", dbPath, sqlKeys)
	p := filepath.Join(dir, "signup.conf")
	os.WriteFile(p, []byte(s), 0o600)
	return p, db
}

// TestSignupBackends: which backends make a signup's account, and the
// errors of [signup] that does not fit the backends
func TestSignupBackends(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		sqlKeys, signupKeys, want, err string
	}{
		{"", "", "file", ""},
		{"insert_query = INSERT INTO users VALUES (?, ?, 1)", "", "file sql", ""},
		{"insert_query = INSERT INTO users VALUES (?, ?, 1)", "backends = sql", "sql", ""},
		{"", "backends = sql", "", "sql cannot make accounts (set [sql] insert_query)"},
		{"", "backends = ldap", "", `"ldap" is not in [general] auth`},
		{"insert_query = INSERT INTO users VALUES (?, ?, 1)", "pending = yes", "",
			"sql cannot lock a new account (put pending in [sql] insert_args)"},
		{"insert_query = INSERT INTO users VALUES (?, ?, 1 - ?)\ninsert_args = user password pending",
			"pending = yes", "file sql", ""},
	} {
		conf, _ := signupConf(t, dir, tc.sqlKeys)
		b, _ := os.ReadFile(conf)
		os.WriteFile(conf, []byte(strings.Replace(string(b), "pending = no\n", "pending = no\n"+tc.signupKeys+"\n", 1)), 0o600)
		s, err := loadSettings(conf)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q %q: error %v, want %q", tc.sqlKeys, tc.signupKeys, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q %q: %v", tc.sqlKeys, tc.signupKeys, err)
			continue
		}
		var got []string
		for _, c := range s.signup.creators {
			got = append(got, c.Name())
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%q %q: %v, want %s", tc.sqlKeys, tc.signupKeys, got, tc.want)
		}
	}
}

// TestSignupEveryBackend: on a line, a signup makes the account in the
// users file and in SQL; when SQL refuses it (a name that only the
// database has), the line in the users file is taken back
func TestSignupEveryBackend(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "dmodem-login")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	conf, db := signupConf(t, dir, "insert_query = INSERT INTO users VALUES (?, ?, 1)\ninsert_hash = none\n"+
		"delete_query = DELETE FROM users WHERE username = ?")

	signup := func(name, pw string) *caller {
		c, cmd := callAs(t, bin, conf)
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		c.expect("login: ")
		c.send("new\r")
		c.expect("User name: ")
		c.send(name + "\r")
		c.expect("Password: ")
		c.send(pw + "\r")
		c.expect("Again: ")
		c.send(pw + "\r")
		return c
	}
	c := signup("carol", "carol-pw")
	c.expect("Selection")
	c.send("info\r")
	c.expect("INFO user=carol auth=file")
	c.send("g\r")

	var pw string
	if err := db.QueryRow("SELECT password FROM users WHERE username = 'carol'").Scan(&pw); err != nil || pw != "carol-pw" {
		t.Errorf("carol in SQL: %q %v", pw, err)
	}
	users, _ := os.ReadFile(filepath.Join(dir, "users"))
	if !strings.Contains(string(users), "carol:$2a$") {
		t.Errorf("users file:\n%s", users)
	}

	// erin: the query cannot say that she is there; the insert fails on
	// the UNIQUE key, and the users file's line is taken back
	c = signup("erin", "erin-new")
	c.expect("no new accounts now")
	users, _ = os.ReadFile(filepath.Join(dir, "users"))
	if strings.Contains(string(users), "erin") {
		t.Errorf("erin is still in the users file:\n%s", users)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "log"))
	for _, w := range []string{"signup user=carol pending=false backends=file,sql", "signup erin: file: taken back",
		"signup erin: sql: "} {
		if !strings.Contains(string(log), w) {
			t.Errorf("no %q in the log:\n%s", w, log)
		}
	}
}
