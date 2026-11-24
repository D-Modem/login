// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/D-Modem/login/internal/config"
)

// CanCreate: whether create_command is set
func (a *System) CanCreate() bool { return a.createCommand != "" }

// CanLock: always (create_command gets {pending} and locks the account)
func (a *System) CanLock() bool { return true }

// HasUser: whether the name service has user (any account, also one
// below min_uid: a new user must not get the name of a system account)
func (a *System) HasUser(_ context.Context, user string) (bool, bool, error) {
	_, err := a.lookup(user)
	if errors.Is(err, ErrNoUser) {
		return false, true, nil
	}
	if err != nil {
		return false, true, err
	}
	return true, true, nil
}

// CreateUser: create_command by /bin/sh, {user} and {pending} (yes or
// no) in it, the password and a line end on its input
func (a *System) CreateUser(ctx context.Context, acct NewAccount) error {
	if a.createCommand == "" {
		return fmt.Errorf("no create_command")
	}
	pending := "no"
	if acct.Pending {
		pending = "yes"
	}
	return a.run(ctx, a.createCommand, map[string]string{"user": acct.User, "pending": pending}, acct.Password+"\n")
}

// RemoveUser: remove_command with {user}, or ErrCannotRemove without one
func (a *System) RemoveUser(ctx context.Context, user string) error {
	if a.removeCommand == "" {
		return ErrCannotRemove
	}
	return a.run(ctx, a.removeCommand, map[string]string{"user": user}, "")
}

// run: command by /bin/sh -c, its {names} quoted for the shell, input on
// its standard input, for command_timeout at most; the error has its output
func (a *System) run(ctx context.Context, command string, v map[string]string, input string) error {
	ctx, cancel := context.WithTimeout(ctx, a.commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", config.Expand(command, v, shQuote))
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(out.String()); msg != "" {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}

// shQuote: s in single quotes for /bin/sh
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
