// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package ldapd

import (
	"sort"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// attr is one attribute of an entry.
type attr struct {
	name string
	vals []string
}

// entry is one entry of the directory.
type entry struct {
	dn    string // as it is sent
	norm  string // normalized
	attrs []attr
}

func (e *entry) get(name string) []string {
	name = canonAttr(name)
	for _, a := range e.attrs {
		if strings.EqualFold(a.name, name) {
			return a.vals
		}
	}
	return nil
}

// aliases of the attribute types that ldapd gives
var aliases = map[string]string{
	"commonname": "cn", "surname": "sn", "userid": "uid",
	"organizationalunitname": "ou", "domaincomponent": "dc",
	"organizationname": "o", "2.5.4.3": "cn", "0.9.2342.19200300.100.1.1": "uid",
	"2.5.4.0": "objectclass",
}

// dnAttrs have DN values: they compare as DNs
var dnAttrs = map[string]bool{"member": true, "memberof": true, "entrydn": true,
	"namingcontexts": true}

func canonAttr(name string) string {
	l := strings.ToLower(strings.TrimSpace(name))
	if a, ok := aliases[l]; ok {
		return a
	}
	return l
}

// rootDSE is the entry with the empty DN.
func (s *Server) rootDSE() *entry {
	exts := []string{OIDWhoAmI}
	if s.cfg.TLS != nil {
		exts = append(exts, OIDStartTLS)
	}
	if s.cfg.ChangePassword != nil {
		exts = append(exts, OIDPasswordModify)
	}
	return &entry{attrs: []attr{
		{"objectClass", []string{"top"}},
		{"namingContexts", []string{s.disp}},
		{"supportedLDAPVersion", []string{"3"}},
		{"supportedExtension", exts},
		{"supportedControl", []string{OIDPaging}},
		{"supportedSASLMechanisms", nil},
		{"vendorName", []string{"D-Modem"}},
	}}
}

// entries is the directory as it is now.  want: user names that a
// search names, looked up when Users does not list them.
func (s *Server) entries(want []string) []*entry {
	var out []*entry
	add := func(dn string, attrs ...attr) {
		norm, _ := NormDN(dn)
		out = append(out, &entry{dn: dn, norm: norm, attrs: attrs})
	}

	// the base entry
	var top []attr
	if dn, err := ldap.ParseDN(s.disp); err == nil && len(dn.RDNs) > 0 && len(dn.RDNs[0].Attributes) > 0 {
		a := dn.RDNs[0].Attributes[0]
		switch canonAttr(a.Type) {
		case "dc":
			top = []attr{{"objectClass", []string{"top", "dcObject", "organization"}}, {"dc", []string{a.Value}}, {"o", []string{a.Value}}}
		case "o":
			top = []attr{{"objectClass", []string{"top", "organization"}}, {"o", []string{a.Value}}}
		case "ou":
			top = []attr{{"objectClass", []string{"top", "organizationalUnit"}}, {"ou", []string{a.Value}}}
		default:
			top = []attr{{"objectClass", []string{"top", "extensibleObject"}}, {a.Type, []string{a.Value}}}
		}
	}
	add(s.disp, top...)
	add("ou=people,"+s.disp, attr{"objectClass", []string{"top", "organizationalUnit"}}, attr{"ou", []string{"people"}})
	add("ou=groups,"+s.disp, attr{"objectClass", []string{"top", "organizationalUnit"}}, attr{"ou", []string{"groups"}})

	groups := s.cfg.Dir.Groups()
	users := map[string]User{}
	for _, u := range s.cfg.Dir.Users() {
		users[u.Name] = u
	}
	// the members of [groups] are users, also when no backend lists them
	for _, ms := range groups {
		for _, m := range ms {
			if _, ok := users[m]; !ok {
				if u, ok := s.cfg.Dir.Lookup(m); ok {
					users[m] = u
				} else {
					users[m] = User{Name: m}
				}
			}
		}
	}
	for _, w := range want {
		if _, ok := users[w]; !ok && s.cfg.ValidUser(w) {
			if u, ok := s.cfg.Dir.Lookup(w); ok {
				users[w] = u
			}
		}
	}
	memberOf := map[string][]string{}
	gnames := make([]string, 0, len(groups))
	for g := range groups {
		gnames = append(gnames, g)
	}
	sort.Strings(gnames)
	for _, g := range gnames {
		for _, m := range groups[g] {
			memberOf[m] = append(memberOf[m], s.groupDN(g))
		}
	}
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := users[n]
		cn := u.FullName
		if cn == "" {
			cn = u.Name
		}
		sn := cn
		if i := strings.LastIndexByte(cn, ' '); i >= 0 {
			sn = cn[i+1:]
		}
		oc := []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
		attrs := []attr{{"objectClass", oc}, {"uid", []string{u.Name}}, {"cn", []string{cn}},
			{"sn", []string{sn}}, {"displayName", []string{cn}}}
		if u.Posix {
			attrs[0].vals = append(oc, "posixAccount")
			attrs = append(attrs, attr{"uidNumber", []string{strconv.Itoa(u.UID)}},
				attr{"gidNumber", []string{strconv.Itoa(u.GID)}})
			if u.Home != "" {
				attrs = append(attrs, attr{"homeDirectory", []string{u.Home}})
			}
			if u.Shell != "" {
				attrs = append(attrs, attr{"loginShell", []string{u.Shell}})
			}
		}
		if len(memberOf[n]) > 0 {
			attrs = append(attrs, attr{"memberOf", memberOf[n]})
		}
		add(s.userDN(n), attrs...)
	}
	for _, g := range gnames {
		var dns []string
		for _, m := range groups[g] {
			dns = append(dns, s.userDN(m))
		}
		attrs := []attr{{"objectClass", []string{"top", "groupOfNames"}}, {"cn", []string{g}}}
		if len(dns) > 0 {
			attrs = append(attrs, attr{"member", dns}, attr{"memberUid", groups[g]})
		}
		add(s.groupDN(g), attrs...)
	}
	return out
}

// inScope: whether the entry is in the scope of a search from base
func inScope(e *entry, base string, scope int64) bool {
	switch scope {
	case ldap.ScopeBaseObject:
		return e.norm == base
	case ldap.ScopeSingleLevel:
		i := strings.IndexByte(e.norm, ',')
		if base == "" {
			return i < 0 && e.norm != ""
		}
		return i >= 0 && e.norm[i+1:] == base
	default:
		return base == "" || e.norm == base || strings.HasSuffix(e.norm, ","+base)
	}
}

// mayRead: whether the bound client may see the entry
func (c *conn) mayRead(e *entry) bool {
	if c.server {
		return true
	}
	if c.user == "" {
		return c.s.cfg.AnonymousSearch
	}
	if c.s.cfg.UserSearch {
		return true
	}
	// only the user's own entry, the groups and the containers
	own, _ := NormDN(c.dn)
	return e.norm == own || !strings.HasPrefix(e.norm, "uid=")
}

// search answers a SearchRequest.
func (c *conn) search(id int64, op *ber.Packet, ctrls []control) bool {
	done := func(code uint16, msg string, extra ...*ber.Packet) bool {
		return c.send(id, result(ldap.ApplicationSearchResultDone, code, "", msg), extra...) == nil
	}
	if len(op.Children) < 8 {
		return done(ldap.LDAPResultProtocolError, "bad search request")
	}
	base, err := NormDN(str(op.Children[0]))
	if err != nil {
		return done(ldap.LDAPResultInvalidDNSyntax, "bad base DN")
	}
	scope := num(op.Children[1])
	limit := int(num(op.Children[3]))
	typesOnly := num(op.Children[5]) != 0
	filter := op.Children[6]
	var want []string
	for _, a := range op.Children[7].Children {
		want = append(want, str(a))
	}

	// simple paged results (RFC 2696): the cookie is the offset of the
	// next page
	paging, pageSize, offset := false, 0, 0
	for _, ct := range ctrls {
		if ct.oid == OIDPaging && ct.value != nil {
			if v, err := ber.DecodePacketErr([]byte(str(ct.value))); err == nil && len(v.Children) == 2 {
				paging = true
				pageSize = int(num(v.Children[0]))
				offset, _ = strconv.Atoi(str(v.Children[1]))
			}
		}
	}
	pageControl := func(cookie string) []*ber.Packet {
		if !paging {
			return nil
		}
		v := ber.NewSequence("paging")
		v.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "size"))
		v.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, "cookie"))
		x := ber.NewSequence("control")
		x.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDPaging, "type"))
		x.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v.Bytes()), "value"))
		return []*ber.Packet{x}
	}
	paged := pageControl("")

	// the root DSE: for everyone, so that clients can see what is here
	if base == "" && scope == ldap.ScopeBaseObject {
		e := c.s.rootDSE()
		if matches(e, filter) {
			if c.sendEntry(id, e, want, typesOnly) != nil {
				return false
			}
		}
		return done(ldap.LDAPResultSuccess, "", paged...)
	}
	if c.user == "" && !c.server && !c.s.cfg.AnonymousSearch {
		return done(ldap.LDAPResultInsufficientAccessRights, "bind first")
	}
	if base != "" && base != c.s.base && !strings.HasSuffix(base, ","+c.s.base) {
		return done(ldap.LDAPResultNoSuchObject, "not in "+c.s.disp)
	}

	names := uidValues(filter)
	if c.user != "" {
		names = append(names, c.user)
	}
	all := c.s.entries(names)
	found := false
	for _, e := range all {
		if e.norm == base {
			found = true
			break
		}
	}
	if !found && base != "" {
		return done(ldap.LDAPResultNoSuchObject, "no such entry")
	}
	if limit <= 0 || limit > c.s.cfg.SizeLimit {
		limit = c.s.cfg.SizeLimit
	}
	var hits []*entry
	for _, e := range all {
		if inScope(e, base, scope) && c.mayRead(e) && matches(e, filter) {
			hits = append(hits, e)
		}
	}
	next := ""
	if paging {
		if pageSize == 0 {
			// size 0: the client stops the paged search
			return done(ldap.LDAPResultSuccess, "", paged...)
		}
		if offset < 0 || offset > len(hits) {
			return done(ldap.LDAPResultUnwillingToPerform, "bad paging cookie")
		}
		hits = hits[offset:]
		if len(hits) > pageSize {
			hits = hits[:pageSize]
			next = strconv.Itoa(offset + pageSize)
		}
	}
	for n, e := range hits {
		if n == limit {
			return done(ldap.LDAPResultSizeLimitExceeded, "", pageControl(next)...)
		}
		if c.sendEntry(id, e, want, typesOnly) != nil {
			return false
		}
	}
	return done(ldap.LDAPResultSuccess, "", pageControl(next)...)
}

// sendEntry sends one SearchResultEntry with the attributes asked for.
func (c *conn) sendEntry(id int64, e *entry, want []string, typesOnly bool) error {
	all, ops := len(want) == 0, false
	sel := map[string]bool{}
	for _, w := range want {
		switch w {
		case "*":
			all = true
		case "+":
			ops = true
		case "1.1":
		default:
			sel[canonAttr(w)] = true
		}
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "entry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "dn"))
	as := ber.NewSequence("attributes")
	put := func(a attr) {
		x := ber.NewSequence("attribute")
		x.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.name, "type"))
		vs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		if !typesOnly {
			for _, v := range a.vals {
				vs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
			}
		}
		x.AppendChild(vs)
		as.AppendChild(x)
	}
	for _, a := range e.attrs {
		if len(a.vals) > 0 && (all || sel[strings.ToLower(a.name)]) {
			put(a)
		}
	}
	if e.dn != "" && (ops || sel["entrydn"]) {
		put(attr{"entryDN", []string{e.dn}})
	}
	p.AppendChild(as)
	return c.send(id, p)
}

// uidValues: the user names that a filter asks for by (uid=name)
func uidValues(f *ber.Packet) []string {
	var out []string
	switch f.Tag {
	case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
		for _, x := range f.Children {
			out = append(out, uidValues(x)...)
		}
	case ldap.FilterEqualityMatch:
		if len(f.Children) == 2 && canonAttr(str(f.Children[0])) == "uid" {
			out = append(out, str(f.Children[1]))
		}
	}
	return out
}

// norm is a value as it compares: case and outer spaces ignored, DNs
// normalized
func normValue(attr, v string) string {
	if dnAttrs[attr] {
		if n, err := NormDN(v); err == nil {
			return n
		}
	}
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}

// matches: whether the entry matches the filter
func matches(e *entry, f *ber.Packet) bool {
	if f == nil || f.ClassType != ber.ClassContext {
		return false
	}
	switch f.Tag {
	case ldap.FilterAnd:
		for _, x := range f.Children {
			if !matches(e, x) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, x := range f.Children {
			if matches(e, x) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(f.Children) == 1 && !matches(e, f.Children[0])
	case ldap.FilterPresent:
		name := canonAttr(str(f))
		return name == "objectclass" || len(e.get(name)) > 0 || (name == "entrydn" && e.dn != "")
	case ldap.FilterEqualityMatch, ldap.FilterApproxMatch, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		if len(f.Children) != 2 {
			return false
		}
		name := canonAttr(str(f.Children[0]))
		want := normValue(name, str(f.Children[1]))
		vals := e.get(name)
		if name == "entrydn" {
			vals = []string{e.dn}
		}
		for _, v := range vals {
			v = normValue(name, v)
			switch f.Tag {
			case ldap.FilterEqualityMatch, ldap.FilterApproxMatch:
				if v == want {
					return true
				}
			case ldap.FilterGreaterOrEqual:
				if compare(v, want) >= 0 {
					return true
				}
			case ldap.FilterLessOrEqual:
				if compare(v, want) <= 0 {
					return true
				}
			}
		}
		return false
	case ldap.FilterSubstrings:
		if len(f.Children) != 2 {
			return false
		}
		name := canonAttr(str(f.Children[0]))
		for _, v := range e.get(name) {
			if substrings(normValue(name, v), f.Children[1].Children) {
				return true
			}
		}
		return false
	}
	// extensible match: not supported, no entry matches
	return false
}

// compare: numbers as numbers, the rest as text
func compare(a, b string) int {
	x, err1 := strconv.ParseInt(a, 10, 64)
	y, err2 := strconv.ParseInt(b, 10, 64)
	if err1 == nil && err2 == nil {
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}

// substrings: initial, any and final parts, in order
func substrings(v string, parts []*ber.Packet) bool {
	for _, p := range parts {
		s := strings.ToLower(strings.Join(strings.Fields(str(p)), " "))
		switch p.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case ldap.FilterSubstringsAny:
			i := strings.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v, s) {
				return false
			}
			v = ""
		}
	}
	return true
}

// compare answers a CompareRequest.
func (c *conn) compare(id int64, op *ber.Packet) bool {
	reply := func(code uint16, msg string) bool {
		return c.send(id, result(ldap.ApplicationCompareResponse, code, "", msg)) == nil
	}
	if len(op.Children) < 2 || len(op.Children[1].Children) < 2 {
		return reply(ldap.LDAPResultProtocolError, "bad compare request")
	}
	if c.user == "" && !c.server && !c.s.cfg.AnonymousSearch {
		return reply(ldap.LDAPResultInsufficientAccessRights, "bind first")
	}
	dn, err := NormDN(str(op.Children[0]))
	if err != nil {
		return reply(ldap.LDAPResultInvalidDNSyntax, "bad DN")
	}
	name := canonAttr(str(op.Children[1].Children[0]))
	want := normValue(name, str(op.Children[1].Children[1]))
	var names []string
	if c.user != "" {
		names = append(names, c.user)
	}
	if u, ok := c.s.userOf(str(op.Children[0]), dn); ok {
		names = append(names, u)
	}
	for _, e := range c.s.entries(names) {
		if e.norm != dn || !c.mayRead(e) {
			continue
		}
		vals := e.get(name)
		if vals == nil {
			return reply(ldap.LDAPResultNoSuchAttribute, "")
		}
		for _, v := range vals {
			if normValue(name, v) == want {
				return reply(ldap.LDAPResultCompareTrue, "")
			}
		}
		return reply(ldap.LDAPResultCompareFalse, "")
	}
	return reply(ldap.LDAPResultNoSuchObject, "")
}
