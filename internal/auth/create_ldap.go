// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/D-Modem/login/internal/config"
	"github.com/go-ldap/ldap/v3"
)

// ldapAttr: one attribute value of a new entry, {user} in it
type ldapAttr struct {
	name, value string
}

// parseLDAPAttrs: "name=value | name=value" as a list (a name can come
// more than one time, for more than one value)
func parseLDAPAttrs(s string) ([]ldapAttr, error) {
	var out []ldapAttr
	for _, part := range strings.Split(s, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, fmt.Errorf("%q: not name=value", part)
		}
		out = append(out, ldapAttr{name, value})
	}
	return out, nil
}

// CanCreate: whether add_dn is set
func (a *LDAP) CanCreate() bool { return a.addDN != "" }

// CanLock: whether add_pending_attributes is set (the attributes that
// lock an entry differ for each server: pwdAccountLockedTime for
// OpenLDAP, nsAccountLock for 389 DS, userAccountControl for AD)
func (a *LDAP) CanLock() bool { return len(a.pendingAttrs) > 0 }

// adminConn: a connection bound as add_bind_dn
func (a *LDAP) adminConn() (*ldap.Conn, error) {
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(a.addBindDN, a.addBindPass); err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind %s: %v", a.addBindDN, err)
	}
	return conn, nil
}

// newDN: add_dn for user, the value escaped for a DN
func (a *LDAP) newDN(user string) string {
	return config.Expand(a.addDN, map[string]string{"user": user}, ldap.EscapeDN)
}

// HasUser: with add_dn, whether the entry at add_dn or an entry that
// search_filter finds is there, searched as add_bind_dn.  Without
// add_dn, the search of a login (search_base) only; with bind_dn and
// no search, known is false.
func (a *LDAP) HasUser(_ context.Context, user string) (bool, bool, error) {
	if a.addDN == "" && a.base == "" {
		return false, false, nil
	}
	var conn *ldap.Conn
	var err error
	if a.addDN != "" {
		conn, err = a.adminConn()
	} else {
		conn, err = a.dial()
	}
	if err != nil {
		return false, true, err
	}
	defer conn.Close()
	if a.addDN != "" {
		res, err := conn.Search(ldap.NewSearchRequest(a.newDN(user), ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 1, int(a.timeout/time.Second), false,
			"(objectClass=*)", []string{"dn"}, nil))
		if err == nil && len(res.Entries) > 0 {
			return true, true, nil
		}
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, true, fmt.Errorf("search %s: %v", a.newDN(user), err)
		}
	}
	if a.base == "" {
		return false, true, nil
	}
	if a.addDN == "" && a.searchDN != "" {
		if err := conn.Bind(a.searchDN, a.searchPass); err != nil {
			return false, true, fmt.Errorf("bind %s: %v", a.searchDN, err)
		}
	}
	// the login's filter, without the group check a filter can have: the
	// uid alone is the name
	filter := config.Expand(a.filter, map[string]string{"user": user}, ldap.EscapeFilter)
	res, err := conn.Search(ldap.NewSearchRequest(a.base, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, int(a.timeout/time.Second), false,
		filter, []string{"dn"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return false, true, fmt.Errorf("search %s: %v", filter, err)
	}
	return res != nil && len(res.Entries) > 0, true, nil
}

// addRequest: the new entry of acct: add_attributes (and, for a
// pending account, add_pending_attributes in place of the attributes of
// the same name), the attribute of the DN's first part, and for AD
// (password_change = ad) the password as unicodePwd
func (a *LDAP) addRequest(acct NewAccount) (*ldap.AddRequest, error) {
	dn := a.newDN(acct.User)
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		return nil, fmt.Errorf("add_dn: %q is not a DN", dn)
	}
	attrs := a.addAttrs
	if acct.Pending {
		replaced := map[string]bool{}
		for _, p := range a.pendingAttrs {
			replaced[strings.ToLower(p.name)] = true
		}
		var keep []ldapAttr
		for _, at := range attrs {
			if !replaced[strings.ToLower(at.name)] {
				keep = append(keep, at)
			}
		}
		attrs = append(keep, a.pendingAttrs...)
	}
	var names []string
	vals := map[string][]string{}
	add := func(name, value string) {
		key := strings.ToLower(name)
		if _, ok := vals[key]; !ok {
			names = append(names, name)
		}
		for _, v := range vals[key] {
			if v == value {
				return
			}
		}
		vals[key] = append(vals[key], value)
	}
	for _, at := range attrs {
		add(at.name, config.Expand(at.value, map[string]string{"user": acct.User}, nil))
	}
	for _, rdn := range parsed.RDNs[0].Attributes {
		add(rdn.Type, rdn.Value)
	}
	if a.passwordChange == "ad" {
		add("unicodePwd", adPassword(acct.Password))
	}
	req := ldap.NewAddRequest(dn, nil)
	for _, n := range names {
		req.Attribute(n, vals[strings.ToLower(n)])
	}
	return req, nil
}

// CreateUser: the entry added as add_bind_dn, then (not for AD, where
// the entry has unicodePwd) its password set by the Password Modify
// extended operation, so that the server makes the hash by its own
// policy.  If the password cannot be set, the entry is deleted again.
func (a *LDAP) CreateUser(_ context.Context, acct NewAccount) error {
	if a.addDN == "" {
		return fmt.Errorf("no add_dn")
	}
	req, err := a.addRequest(acct)
	if err != nil {
		return err
	}
	conn, err := a.adminConn()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Add(req); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("%w: %s", ErrTaken, req.DN)
		}
		return fmt.Errorf("add %s: %v", req.DN, err)
	}
	if a.passwordChange == "ad" {
		return nil
	}
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(req.DN, "", acct.Password)); err != nil {
		derr := conn.Del(ldap.NewDelRequest(req.DN, nil))
		return errors.Join(fmt.Errorf("password of %s: %v", req.DN, err), derr)
	}
	return nil
}

// RemoveUser: the entry at add_dn deleted, as add_bind_dn
func (a *LDAP) RemoveUser(_ context.Context, user string) error {
	if a.addDN == "" {
		return ErrCannotRemove
	}
	conn, err := a.adminConn()
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Del(ldap.NewDelRequest(a.newDN(user), nil))
}
