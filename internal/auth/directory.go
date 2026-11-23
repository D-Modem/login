// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bufio"
	"os"
	"os/user"
	"strings"
)

// DirUser is what the LDAP provider ([ldapd]) shows of a user.  It never
// has the password.
type DirUser struct {
	Name     string
	FullName string
	Posix    bool // a system account: UID, GID, Home and Shell are set
	UID, GID int
	Home     string
	Shell    string
}

// Lister is a backend that can list its users (the users file).
type Lister interface {
	ListUsers() ([]DirUser, error)
}

// Looker is a backend that can find one user by name without the
// password (the users file, the system's accounts).
type Looker interface {
	LookupUser(name string) (DirUser, error)
}

// ListUsers: the users of the users file, not the locked ones
func (a *File) ListUsers() ([]DirUser, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []DirUser
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, stored, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.HasPrefix(stored, "!") {
			continue
		}
		out = append(out, DirUser{Name: name})
	}
	return out, sc.Err()
}

// LookupUser: the user's line in the users file; ErrNoUser when it is not
// there or locked
func (a *File) LookupUser(name string) (DirUser, error) {
	us, err := a.ListUsers()
	if err != nil {
		return DirUser{}, err
	}
	for _, u := range us {
		if u.Name == name {
			return u, nil
		}
	}
	return DirUser{}, ErrNoUser
}

// LookupUser: the system account, when it is one that may log in (min_uid,
// root, groups)
func (a *System) LookupUser(name string) (DirUser, error) {
	acct, err := a.lookup(name)
	if err != nil {
		return DirUser{}, err
	}
	if err := a.allowed(acct); err != nil {
		return DirUser{}, ErrNoUser
	}
	d := DirUser{Name: acct.name, Posix: true, UID: acct.uid, GID: acct.gid}
	if u, err := user.Lookup(acct.name); err == nil {
		d.Home = u.HomeDir
		// the GECOS field: the full name before the first comma
		d.FullName, _, _ = strings.Cut(u.Name, ",")
	}
	return d, nil
}
