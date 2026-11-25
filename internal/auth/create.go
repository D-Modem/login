// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrTaken: the backend has an account of that name already
var ErrTaken = errors.New("user name taken")

// ErrCannotRemove: the backend cannot take back an account it made (the
// undo of a signup that failed in a later backend)
var ErrCannotRemove = errors.New("cannot remove accounts")

// NewAccount: what a signup gives each backend that makes the account
type NewAccount struct {
	User     string
	Password string // as the caller typed it; each backend hashes it its own way
	Pending  bool   // locked until the sysop unlocks it
	Note     string // signup DATE CALLERID, where the backend keeps one
}

// UserChecker: a backend that can tell whether it has an account of a
// name, without a password (a signup's check of the new name)
type UserChecker interface {
	Name() string
	// HasUser: whether the backend has user; known is false when this
	// backend, as configured, cannot tell
	HasUser(ctx context.Context, user string) (has, known bool, err error)
}

// AccountCreator: a backend that can make a new account (a signup)
type AccountCreator interface {
	UserChecker
	// CanCreate: whether this backend is set up to make accounts (sql:
	// insert_query; ldap: add_dn; system: create_command)
	CanCreate() bool
	// CanLock: whether a pending account can be made locked here
	CanLock() bool
	// CreateUser: the account made; ErrTaken when the name is there
	CreateUser(ctx context.Context, acct NewAccount) error
	// RemoveUser: the account that CreateUser made taken back, or
	// ErrCannotRemove
	RemoveUser(ctx context.Context, user string) error
}

// FileAt: a users file backend for path (a signup's [signup] file, which
// can differ from the [file] path)
func FileAt(path, scheme string) *File {
	return &File{path: path, scheme: strings.ToLower(scheme)}
}

// CreateAccounts: acct made in each of creators, in turn.  When one
// fails, the accounts already made are taken back (in the reverse
// sequence) and the error says which backend failed.  The result is the
// names of the backends that have the account.
func CreateAccounts(ctx context.Context, creators []AccountCreator, acct NewAccount, logf func(string, ...any)) ([]string, error) {
	var made []AccountCreator
	for _, c := range creators {
		if err := c.CreateUser(ctx, acct); err != nil {
			for i := len(made) - 1; i >= 0; i-- {
				if rerr := made[i].RemoveUser(ctx, acct.User); rerr != nil {
					logf("signup %s: %s: not taken back: %v", acct.User, made[i].Name(), rerr)
				} else {
					logf("signup %s: %s: taken back", acct.User, made[i].Name())
				}
			}
			return nil, fmt.Errorf("%s: %w", c.Name(), err)
		}
		made = append(made, c)
	}
	names := make([]string, len(made))
	for i, c := range made {
		names[i] = c.Name()
	}
	return names, nil
}

// UserTaken: the first backend of checkers that has user (in any case
// where it can tell), or ""; an error when a backend cannot be asked
func UserTaken(ctx context.Context, checkers []UserChecker, user string) (string, error) {
	for _, c := range checkers {
		has, known, err := c.HasUser(ctx, user)
		if err != nil {
			return "", fmt.Errorf("%s: %w", c.Name(), err)
		}
		if known && has {
			return c.Name(), nil
		}
	}
	return "", nil
}

// noteField: a note made safe for a : separated line
func noteField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ':' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}
