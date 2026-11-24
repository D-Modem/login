// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// session is what is known of the call and the caller, handed to the
// selection in its environment, its command line and its session file
type session struct {
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	Auth     string `json:"auth"`
	Dialed   string `json:"dialed"`
	CallerID string `json:"callerid"`
	Baud     string `json:"baud"`
	Rate     string `json:"rate"`
	TxRate   string `json:"tx_rate"`
	RxRate   string `json:"rx_rate"`
	Channel  string `json:"channel"`
	// the modulation, error correction and compression of the
	// connection, as app_dmodem's DMODEM_MODULATION, DMODEM_PROTOCOL and
	// DMODEM_COMPRESSION give them (V90, LAPM, V42bis); "" if not told
	Modulation  string `json:"modulation"`
	Protocol    string `json:"protocol"`
	Compression string `json:"compression"`
	// the address the call came from by VoIP (the SIP peer's: app_dmodem's
	// DMODEM_PEER), "" if not told
	Peer      string    `json:"peer"`
	Profile   string    `json:"profile"`
	Connected time.Time `json:"connected"`
	Selection string    `json:"selection"`
	TimeLeft  string    `json:"time_left"` // whole minutes; "": no limit
	// the same in seconds
	SecondsLeft string `json:"seconds_left"`
	// the caller's terminal, as detected ("": not asked): ansi, vt (an
	// ANSI terminal that said what it is), vt52, petscii, ascii
	Terminal string `json:"terminal"`
	Term     string `json:"term"`      // a TERM for it: xterm, vt220, ansi, vt52, dumb...
	TermName string `json:"term_name"` // what it said it is: xterm(390), VT220, SyncTERM (CTerm 1.316)
	Rows     string `json:"rows"`
	Cols     string `json:"cols"`
	// the characters it shows: utf8, cp437 (SyncTERM), 8bit (not UTF-8),
	// "" not asked
	charset string
	// a DEC terminal itself (by its DA2), not an emulator: no colors
	hardware bool
	// an upstream menu's deadline, from its session header
	upstreamDeadline time.Time

	groupCache map[string]bool // the backends' group answers, for the call
}

// newSession from app_dmodem's environment (DMODEM_RATE "tx/rx",
// DMODEM_CALLERID, DMODEM_DIALED, DMODEM_CHANNEL, DMODEM_PROFILE,
// DMODEM_PEER, DMODEM_MODULATION, DMODEM_PROTOCOL, DMODEM_COMPRESSION),
// what the command line overrides of it
func newSession(rate, dialed, callerID string, now time.Time) *session {
	s := &session{
		Dialed:      dialed,
		CallerID:    callerID,
		Channel:     os.Getenv("DMODEM_CHANNEL"),
		Peer:        os.Getenv("DMODEM_PEER"),
		Profile:     os.Getenv("DMODEM_PROFILE"),
		Modulation:  os.Getenv("DMODEM_MODULATION"),
		Protocol:    os.Getenv("DMODEM_PROTOCOL"),
		Compression: os.Getenv("DMODEM_COMPRESSION"),
		Connected:   now,
	}
	// what an upstream menu found the terminal to be
	s.Terminal = os.Getenv("DMODEM_LOGIN_UPSTREAM_TERMINAL")
	s.Term = os.Getenv("DMODEM_LOGIN_UPSTREAM_TERM")
	s.TermName = os.Getenv("DMODEM_LOGIN_UPSTREAM_TERM_NAME")
	s.Rows = os.Getenv("DMODEM_LOGIN_UPSTREAM_ROWS")
	s.Cols = os.Getenv("DMODEM_LOGIN_UPSTREAM_COLS")
	for _, k := range []string{"TERMINAL", "TERM", "TERM_NAME", "ROWS", "COLS"} {
		os.Unsetenv("DMODEM_LOGIN_UPSTREAM_" + k)
	}
	s.Rate = rate
	tx, rx, ok := strings.Cut(rate, "/")
	if !ok {
		rx = tx
	}
	if _, err := strconv.Atoi(tx); err == nil {
		s.TxRate, s.RxRate = tx, rx
		// the speed the caller's modem reports: what reaches it
		s.Baud = tx
	}
	return s
}

// Speed: the connect rate for the caller to read: "33600 bit/s", or with
// the directions apart "50666 bit/s down, 31200 bit/s up" (down: to the
// caller); "" when it is not known
func (s *session) Speed() string {
	tx, errT := strconv.Atoi(s.TxRate)
	rx, errR := strconv.Atoi(s.RxRate)
	switch {
	case errT != nil || tx <= 0:
		return ""
	case errR != nil || rx <= 0 || rx == tx:
		return strconv.Itoa(tx) + " bit/s"
	}
	return fmt.Sprintf("%d bit/s down, %d bit/s up", tx, rx)
}

// modulationName: a modulation as app_dmodem names it (the pump names
// of AT+MS: V34, V90, V32bis, K56Flex, Bell103) in the form persons read
// (V.34, V.90, V.32bis, K56flex, Bell 103); a name already in that form,
// or one it does not know, as it is
func modulationName(m string) string {
	switch m {
	case "K56Flex":
		return "K56flex"
	case "VFC":
		return "V.FC"
	}
	if rest, ok := strings.CutPrefix(m, "Bell"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return "Bell " + rest
	}
	if len(m) > 1 && m[0] == 'V' && m[1] >= '0' && m[1] <= '9' {
		return "V." + m[1:]
	}
	return m
}

// protocolName: the error correction (LAPM, MNP, X.75...) for persons
// to read; "" for none (NONE) or not known
func protocolName(p string) string {
	if strings.EqualFold(p, "NONE") {
		return ""
	}
	return p
}

// compressionName: the compression (V42bis, V44, MNP5...) for persons
// to read (V.42bis, V.44, MNP5); "" for none (NONE) or not known
func compressionName(c string) string {
	switch {
	case strings.EqualFold(c, "NONE"):
		return ""
	case len(c) > 1 && c[0] == 'V' && c[1] >= '0' && c[1] <= '9':
		return "V." + c[1:]
	}
	return c
}

// Link: the error correction and the compression as CONNECT shows them,
// "LAPM/V.42bis", "MNP/MNP5" or "LAPM"; "" without error correction or
// when it is not known
func (s *session) Link() string {
	p := protocolName(s.Protocol)
	if p == "" {
		return ""
	}
	if c := compressionName(s.Compression); c != "" {
		return p + "/" + c
	}
	return p
}

// Connection: the connect rate with the modulation and the link, for
// the caller to read: "33600 bit/s (V.34, LAPM/V.42bis)"; the rate alone
// ({speed}) when neither is known; "" when the rate is not known
func (s *session) Connection() string {
	speed := s.Speed()
	if speed == "" {
		return ""
	}
	var parts []string
	if m := modulationName(s.Modulation); m != "" {
		parts = append(parts, m)
	}
	if l := s.Link(); l != "" {
		parts = append(parts, l)
	}
	if len(parts) == 0 {
		return speed
	}
	return speed + " (" + strings.Join(parts, ", ") + ")"
}

// vars: the placeholders of templates and the environment, by name
func (s *session) vars(withPassword bool) map[string]string {
	v := map[string]string{
		"user":         s.User,
		"auth":         s.Auth,
		"dialed":       s.Dialed,
		"callerid":     s.CallerID,
		"baud":         s.Baud,
		"rate":         s.Rate,
		"tx_rate":      s.TxRate,
		"rx_rate":      s.RxRate,
		"speed":        s.Speed(),
		"modulation":   modulationName(s.Modulation),
		"protocol":     protocolName(s.Protocol),
		"compression":  compressionName(s.Compression),
		"link":         s.Link(),
		"connection":   s.Connection(),
		"channel":      s.Channel,
		"peer":         s.Peer,
		"profile":      s.Profile,
		"selection":    s.Selection,
		"time_left":    s.TimeLeft,
		"seconds_left": s.SecondsLeft,
		"terminal":     s.Terminal,
		"term":         s.Term,
		"term_name":    s.TermName,
		"rows":         s.Rows,
		"cols":         s.Cols,
		"date":         s.Connected.Format("2006-01-02"),
		"time":         s.Connected.Format("15:04:05"),
		"datetime":     s.Connected.Format(time.RFC3339),
		"epoch":        strconv.FormatInt(s.Connected.Unix(), 10),
		"password":     "",
	}
	if withPassword {
		v["password"] = s.Password
	}
	return v
}

// environ: MODEM_<NAME> for every placeholder
func (s *session) environ(withPassword bool) []string {
	v := s.vars(withPassword)
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	env := make([]string, 0, len(v))
	for _, k := range names {
		if k == "password" && !withPassword {
			continue
		}
		env = append(env, "MODEM_"+strings.ToUpper(k)+"="+v[k])
	}
	return env
}

// writeFile: the session as JSON in a file only its owner reads
func (s *session) writeFile(withPassword bool, uid, gid int) (string, error) {
	c := *s
	if !withPassword {
		c.Password = ""
	}
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "dmodem-login-*.json")
	if err != nil {
		return "", err
	}
	if _, err = f.Write(append(b, '\n')); err == nil && uid >= 0 {
		err = f.Chown(uid, gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// shellQuote: a value as one word of /bin/sh
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
