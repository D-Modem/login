// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSpeed: {speed} from the connect rates
func TestSpeed(t *testing.T) {
	for rate, want := range map[string]string{
		"33600/33600": "33600 bit/s",
		"33600/31200": "33600 bit/s down, 31200 bit/s up",
		"50666/31200": "50666 bit/s down, 31200 bit/s up",
		"2400":        "2400 bit/s",
		"":            "",
		"0/0":         "",
		"fast":        "",
	} {
		s := newSession(rate, "", "", time.Now())
		if got := s.Speed(); got != want {
			t.Errorf("%q: %q, want %q", rate, got, want)
		}
		if got := s.vars(false)["speed"]; got != want {
			t.Errorf("%q: {speed} %q, want %q", rate, got, want)
		}
		if env := strings.Join(s.environ(false), "\n"); !strings.Contains(env, "MODEM_SPEED="+want+"\n") {
			t.Errorf("%q: no MODEM_SPEED=%s in\n%s", rate, want, env)
		}
	}
}

// TestConnection: {modulation}, {protocol}, {compression}, {link} and
// {connection} from app_dmodem's names
func TestConnection(t *testing.T) {
	for _, c := range []struct {
		rate, mod, proto, comp       string
		modulation, link, connection string
	}{
		{"33600/33600", "V34", "LAPM", "V42bis", "V.34", "LAPM/V.42bis", "33600 bit/s (V.34, LAPM/V.42bis)"},
		{"50666/31200", "V90", "LAPM", "V44", "V.90", "LAPM/V.44", "50666 bit/s down, 31200 bit/s up (V.90, LAPM/V.44)"},
		{"52000/31200", "K56Flex", "LAPM", "NONE", "K56flex", "LAPM", "52000 bit/s down, 31200 bit/s up (K56flex, LAPM)"},
		{"14400/14400", "V32bis", "MNP", "MNP5", "V.32bis", "MNP/MNP5", "14400 bit/s (V.32bis, MNP/MNP5)"},
		{"300/300", "Bell103", "NONE", "NONE", "Bell 103", "", "300 bit/s (Bell 103)"},
		{"28800/28800", "", "LAPM", "V42bis", "", "LAPM/V.42bis", "28800 bit/s (LAPM/V.42bis)"},
		// a menu's header: already the names for persons
		{"33600/33600", "V.34", "LAPM", "V.42bis", "V.34", "LAPM/V.42bis", "33600 bit/s (V.34, LAPM/V.42bis)"},
		// not told (a getty): the rate alone, as before
		{"33600/33600", "", "", "", "", "", "33600 bit/s"},
		{"", "V34", "LAPM", "V42bis", "V.34", "LAPM/V.42bis", ""},
	} {
		s := newSession(c.rate, "", "", time.Now())
		s.Modulation, s.Protocol, s.Compression = c.mod, c.proto, c.comp
		v := s.vars(false)
		if v["modulation"] != c.modulation || v["link"] != c.link || v["connection"] != c.connection {
			t.Errorf("%+v: modulation %q, link %q, connection %q", c, v["modulation"], v["link"], v["connection"])
		}
		if env := strings.Join(s.environ(false), "\n") + "\n"; !strings.Contains(env, "MODEM_CONNECTION="+c.connection+"\n") {
			t.Errorf("%+v: no MODEM_CONNECTION in\n%s", c, env)
		}
	}
}

// the connect rate after the banner, before the login prompt
func TestConnectMessage(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "dmodem-login")
	if out, err := runGo("build", "-o", bin, "."); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	users := filepath.Join(dir, "users")
	os.WriteFile(users, nil, 0o600)
	conf := func(extra string) string {
		p := filepath.Join(dir, fmt.Sprintf("c%d.conf", len(extra)))
		os.WriteFile(p, []byte(fmt.Sprintf("[general]\nlog = none\nbanner = \"Test BBS\\r\\n\"\n%s\n[file]\npath = %s\n[item i]\ncommand = true\n", extra, users)), 0o600)
		return p
	}
	link := []string{"DMODEM_MODULATION=V90", "DMODEM_PROTOCOL=LAPM", "DMODEM_COMPRESSION=V42bis"}
	for _, c := range []struct {
		conf, rate, want string
		env              []string
	}{
		{conf(""), "DMODEM_RATE=50666/31200", "Test BBS\r\n\r\nConnected at 50666 bit/s down, 31200 bit/s up (V.90, LAPM/V.42bis).\r\n\r\nlogin: ", link},
		{conf(`connect_message = "CONNECT {tx_rate}/{protocol}/{compression} {modulation}\r\n"`), "DMODEM_RATE=50666/31200", "Test BBS\r\nCONNECT 50666/LAPM/V.42bis V.90\r\n\r\nlogin: ", link},
		{conf(""), "DMODEM_RATE=33600/33600", "Test BBS\r\n\r\nConnected at 33600 bit/s.\r\n\r\nlogin: ", nil},
		{conf(""), "DMODEM_RATE=50666/31200", "Connected at 50666 bit/s down, 31200 bit/s up.\r\n", nil},
		{conf(""), "DMODEM_RATE=", "Test BBS\r\n\r\nlogin: ", nil},
		{conf(`connect_message = "CONNECT {tx_rate}\r\n"`), "DMODEM_RATE=26400/24000", "Test BBS\r\nCONNECT 26400\r\n\r\nlogin: ", nil},
		{conf(`connect_message = ""`), "DMODEM_RATE=33600/33600", "Test BBS\r\n\r\nlogin: ", nil},
	} {
		cl, cmd := callAs(t, bin, c.conf, append([]string{c.rate}, c.env...)...)
		got := cl.expect("login: ")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q in it", c.rate, got, c.want)
		}
		cmd.Process.Kill()
	}
}
