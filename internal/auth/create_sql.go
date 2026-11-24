// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// CanCreate: whether insert_query is set
func (a *SQL) CanCreate() bool { return a.insertQuery != "" }

// CanLock: whether insert_args gives the query pending (the query
// stores the lock, and query or the database refuses locked rows)
func (a *SQL) CanLock() bool { return contains(a.insertArgs, "pending") }

// HasUser: exists_query with the user (a row: the name is taken); else
// query, when its only argument is the user and it returns the stored
// password.  Without these, known is false: insert_query (a unique key)
// refuses a name that is there.
func (a *SQL) HasUser(ctx context.Context, user string) (bool, bool, error) {
	q := a.existsQuery
	if q == "" {
		if len(a.args) != 1 || a.args[0] != "user" {
			return false, false, nil
		}
		q = a.query
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	err := a.db.QueryRowContext(ctx, q, user).Scan(&discard{})
	if errors.Is(err, sql.ErrNoRows) {
		return false, true, nil
	}
	if err != nil {
		return false, true, err
	}
	return true, true, nil
}

// CreateUser: insert_query with insert_args (user, password, pending as
// 1 or 0, note), the password as insert_hash says.  An error of the
// database (for example, a unique key) is not ErrTaken: the database
// does not say why.
func (a *SQL) CreateUser(ctx context.Context, acct NewAccount) error {
	if a.insertQuery == "" {
		return fmt.Errorf("no insert_query")
	}
	stored := acct.Password
	if a.insertHash == "bcrypt" {
		h, err := bcrypt.GenerateFromPassword([]byte(acct.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		stored = string(h)
	}
	args := make([]any, len(a.insertArgs))
	for i, arg := range a.insertArgs {
		switch arg {
		case "user":
			args[i] = acct.User
		case "password":
			args[i] = stored
		case "pending":
			if acct.Pending {
				args[i] = 1
			} else {
				args[i] = 0
			}
		case "note":
			args[i] = acct.Note
		}
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	res, err := a.db.ExecContext(ctx, a.insertQuery, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n != 1 {
		return fmt.Errorf("insert_query added %d rows, not 1", n)
	}
	return nil
}

// RemoveUser: delete_query with the user, or ErrCannotRemove without one
func (a *SQL) RemoveUser(ctx context.Context, user string) error {
	if a.deleteQuery == "" {
		return ErrCannotRemove
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	_, err := a.db.ExecContext(ctx, a.deleteQuery, user)
	return err
}

// contains: whether list has s, in any case
func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
