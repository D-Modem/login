// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/D-Modem/login/internal/auth"
	"github.com/D-Modem/login/internal/term"
)

// errPending: the new account waits for the sysop
var errPending = errors.New("account pending approval")

// signup: a new account in each backend of [signup] (the users file, SQL,
// LDAP, system accounts), the caller logged in with it (or errPending
// with signup's pending = yes)
func signup(t *term.Term, s *settings, sess *session, deadline time.Time) error {
	su := s.signup
	if err := t.Write(su.message); err != nil {
		return err
	}
	var name string
	for try := 0; ; try++ {
		if try == 3 {
			return errors.New("signup: no name taken")
		}
		if err := t.Write("\r\nUser name: "); err != nil {
			return err
		}
		n, err := t.ReadLine(deadline, s.maxInput, true, "")
		if err != nil {
			return err
		}
		n = strings.TrimSpace(n)
		if why := s.nameTaken(n); why != "" {
			t.Write(why + "\r\n")
			continue
		}
		name = n
		break
	}
	var pw string
	for try := 0; ; try++ {
		if try == 3 {
			return errors.New("signup: no password")
		}
		if err := t.Write("Password: "); err != nil {
			return err
		}
		p, err := t.ReadLine(deadline, s.maxInput*2, false, s.mask)
		if err != nil {
			return err
		}
		if len(p) < su.minPassword {
			t.Write(fmt.Sprintf("At least %d characters, please.\r\n", su.minPassword))
			continue
		}
		if err := t.Write("Again: "); err != nil {
			return err
		}
		again, err := t.ReadLine(deadline, s.maxInput*2, false, s.mask)
		if err != nil {
			return err
		}
		if again != p {
			t.Write("They differ.\r\n")
			continue
		}
		pw = p
		break
	}
	acct := auth.NewAccount{
		User:     name,
		Password: pw,
		Pending:  su.pending,
		Note:     fmt.Sprintf("signup %s %s", time.Now().Format("2006-01-02 15:04"), sess.CallerID),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	made, err := auth.CreateAccounts(ctx, su.creators, acct, logf)
	if err != nil {
		logf("signup %s: %v", name, err)
		if errors.Is(err, auth.ErrTaken) {
			t.Write("\r\nThat name is taken.  Call again to choose another.\r\n")
		} else {
			t.Write("\r\nSorry, no new accounts now.\r\n")
		}
		return err
	}
	logf("signup user=%s pending=%v backends=%s %v", name, su.pending, strings.Join(made, ","), sess)
	if su.pending {
		t.Write("\r\nThank you.  Your account waits for the sysop's approval.\r\n")
		return errPending
	}
	// the first backend of [general] auth that has the account is the one
	// that a login finds it in
	sess.User, sess.Password, sess.Auth = name, pw, made[0]
	return nil
}

// nameTaken: why a new user may not have name, or ""
func (s *settings) nameTaken(name string) string {
	switch {
	case !s.userPattern.MatchString(name):
		return "Letters, digits and . _ @ - only, please."
	case strings.EqualFold(name, s.signup.name) || strings.EqualFold(name, s.guest.name) ||
		strings.EqualFold(name, "root"):
		return "That name is taken."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// the backends that make the account: each must be free of the name
	// (one that cannot be asked stops the signup)
	for _, c := range s.signup.creators {
		has, known, err := c.HasUser(ctx, name)
		if err != nil {
			logf("signup %s: %s: %v", name, c.Name(), err)
			return "That name cannot be checked now."
		}
		if known && has {
			return "That name is taken."
		}
	}
	// the other backends: a login that finds the new account first would
	// shadow an account there (one that cannot be asked is in the log only)
	for _, b := range s.backends {
		c, ok := b.(auth.UserChecker)
		if !ok || isCreator(s.signup.creators, b.Name()) {
			continue
		}
		has, known, err := c.HasUser(ctx, name)
		if err != nil {
			logf("signup %s: %s: %v", name, c.Name(), err)
			continue
		}
		if known && has {
			return "That name is taken."
		}
	}
	// a system account's name would let the new user log in to a
	// selection run_as that account
	if _, err := auth.LookupNSS(name); err == nil {
		return "That name is taken."
	}
	return ""
}

// isCreator: whether the backend name makes signups' accounts
func isCreator(creators []auth.AccountCreator, name string) bool {
	for _, c := range creators {
		if c.Name() == name {
			return true
		}
	}
	return false
}
