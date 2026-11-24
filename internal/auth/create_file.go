// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/unix"
)

// CanCreate: always (a line at the end of the users file)
func (a *File) CanCreate() bool { return true }

// CanLock: always (user:!hash)
func (a *File) CanLock() bool { return true }

// HasUser: whether the users file has user, in any case
func (a *File) HasUser(_ context.Context, user string) (bool, bool, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return false, true, err
	}
	defer f.Close()
	has, err := scanUsers(f, user)
	return has, true, err
}

// scanUsers: whether the open users file has name (in any case)
func scanUsers(f io.Reader, name string) (bool, error) {
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if n, _, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":"); ok && strings.EqualFold(n, name) {
			return true, nil
		}
	}
	return false, sc.Err()
}

// CreateUser: user:bcrypt:note at the end of the users file (user:!bcrypt
// for a pending account), under the lock that password changes take.  The
// name is looked at again under the lock: two signups at one time.
func (a *File) CreateUser(_ context.Context, acct NewAccount) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(acct.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	lock := ""
	if acct.Pending {
		lock = "!"
	}
	line := acct.User + ":" + lock + string(hash)
	if acct.Note != "" {
		line += ":" + noteField(acct.Note)
	}
	line += "\n"
	f, err := os.OpenFile(a.path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	if has, err := scanUsers(f, acct.User); err != nil || has {
		if err == nil {
			err = fmt.Errorf("%w: %s", ErrTaken, acct.User)
		}
		return err
	}
	// a file without a line end at its end
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	_, err = f.WriteString(line)
	return err
}

// RemoveUser: the line of user (this name exactly) taken out of the users
// file, under its lock; the other lines stay as they are
func (a *File) RemoveUser(_ context.Context, user string) error {
	f, err := os.OpenFile(a.path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(b), "\n")
	out := lines[:0]
	found := false
	for _, line := range lines {
		if name, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && name == user && !found {
			found = true
			continue
		}
		out = append(out, line)
	}
	if !found {
		return ErrNoUser
	}
	data := []byte(strings.Join(out, ""))
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	return f.Sync()
}
