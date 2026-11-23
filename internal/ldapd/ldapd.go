// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

// Package ldapd is modemmenu's LDAP provider ([ldapd] in modemmenu.conf):
// an LDAPv3 server over the same backends as the login prompt, so that
// other programs (the BBS, a wiki, a mail server, a PBX) take the same
// user names and passwords as the dial-up line.
//
// The directory is read only and small:
//
//	<base_dn>                         the base entry
//	ou=people,<base_dn>               uid=<user>,ou=people,<base_dn>
//	ou=groups,<base_dn>               cn=<group>,ou=groups,<base_dn>
//
// It does simple binds (a user, or the service account), searches,
// compares, StartTLS, Who am I? (RFC 4532) and Password Modify (RFC
// 3062).  Add, delete, modify and modify DN are refused.  No password or
// password hash is ever in an entry.
package ldapd

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// The OIDs of the extended operations and the control that ldapd knows
const (
	OIDStartTLS       = "1.3.6.1.4.1.1466.20037"
	OIDWhoAmI         = "1.3.6.1.4.1.4203.1.11.3"
	OIDPasswordModify = "1.3.6.1.4.1.4203.1.11.1"
	OIDPaging         = "1.2.840.113556.1.4.319"
)

// MaxMessage is the largest LDAP message that ldapd reads.  A bigger one
// closes the connection.
const MaxMessage = 256 << 10

// ErrBadPassword and ErrNoUser are what Config.Authenticate and
// Config.ChangePassword give for a wrong password and an unknown user.
// ErrRefused is a new password that the backend did not accept.
var (
	ErrBadPassword = errors.New("wrong password")
	ErrNoUser      = errors.New("no such user")
	ErrRefused     = errors.New("new password refused")
	ErrCannot      = errors.New("the password cannot be changed here")
)

// User is one person entry.
type User struct {
	Name     string // uid
	FullName string // cn; Name when empty
	Posix    bool   // the system account: uidNumber, gidNumber, homeDirectory
	UID, GID int
	Home     string
	Shell    string
}

// Directory gives the users and the groups.  Users and Groups are read at
// each search, so that edits to the users file show at once.
type Directory interface {
	// Users: all the users that the directory can list
	Users() []User
	// Lookup: one user, also one that Users does not list (a system
	// account); false when nothing knows the name
	Lookup(name string) (User, bool)
	// Groups: each group's name and its members
	Groups() map[string][]string
}

// Config is what a Server serves.
type Config struct {
	BaseDN string
	Dir    Directory
	// Authenticate: the password checked by the backends; the backend's
	// name when it is right
	Authenticate func(ctx context.Context, user, password string) (string, error)
	// ChangePassword: nil when Password Modify is refused
	ChangePassword func(ctx context.Context, user, old, new string) error
	// ValidUser: whether a name is one that the login takes (user_pattern)
	ValidUser func(string) bool
	// Burn: the time that a password check takes, for a name that is
	// not checked
	Burn func(password string)

	// the service account: a DN and a check of its password; empty
	// ServiceDN: none
	ServiceDN    string
	ServiceCheck func(password string) bool

	TLS             *tls.Config // nil: no StartTLS
	RequireTLS      bool        // a bind needs TLS, except on a unix socket or loopback
	AnonymousSearch bool        // searches before a bind (the root DSE is always given)
	UserSearch      bool        // a user can see all entries (false: only the user's own and groups)
	MinPassword     int         // the shortest new password
	FailDelay       time.Duration
	IdleTimeout     time.Duration
	SizeLimit       int // the most entries that one search gives
	MaxClients      int
	Logf            func(string, ...any)
}

// Server is an LDAP server for one Config.
type Server struct {
	cfg   *Config
	base  string // normalized, to compare
	disp  string // as the configuration gives it, in the entries
	slots chan struct{}

	mu    sync.Mutex
	lns   map[net.Listener]bool
	conns map[net.Conn]bool
}

// New checks cfg and gives a Server.
func New(cfg *Config) (*Server, error) {
	base, err := NormDN(cfg.BaseDN)
	if err != nil || base == "" {
		return nil, fmt.Errorf("base_dn: %q is not a DN", cfg.BaseDN)
	}
	if cfg.ServiceDN != "" {
		sdn, err := NormDN(cfg.ServiceDN)
		if err != nil || sdn == "" {
			return nil, fmt.Errorf("bind_dn: %q is not a DN", cfg.ServiceDN)
		}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Burn == nil {
		cfg.Burn = func(string) {}
	}
	if cfg.ValidUser == nil {
		cfg.ValidUser = func(string) bool { return true }
	}
	if cfg.MaxClients < 1 {
		cfg.MaxClients = 64
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.SizeLimit <= 0 {
		cfg.SizeLimit = 1000
	}
	disp := strings.TrimSpace(cfg.BaseDN)
	return &Server{cfg: cfg, base: base, disp: disp, slots: make(chan struct{}, cfg.MaxClients),
		lns: map[net.Listener]bool{}, conns: map[net.Conn]bool{}}, nil
}

// Serve answers on ln until Close.  implicitTLS: ln is an ldaps port,
// each connection starts with a TLS handshake.
func (s *Server) Serve(ln net.Listener, implicitTLS bool) error {
	if implicitTLS && s.cfg.TLS == nil {
		return errors.New("ldaps: no TLS certificate")
	}
	s.mu.Lock()
	s.lns[ln] = true
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.cfg.Logf("ldap accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.cfg.Logf("ldap %s: %d connections already, refused", conn.RemoteAddr(), s.cfg.MaxClients)
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-s.slots }()
			s.serveConn(conn, implicitTLS)
		}()
	}
}

// Close stops the listeners and the connections.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ln := range s.lns {
		ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
}

// conn is the state of one client connection.
type conn struct {
	s      *Server
	nc     net.Conn
	r      *bufio.Reader
	who    string
	local  bool // a unix socket or loopback: TLS is not needed
	tls    bool
	dn     string // the bound DN, normalized; "" anonymous
	user   string // the bound user; "" anonymous or the service
	server bool   // bound as the service account
}

func (s *Server) serveConn(nc net.Conn, implicitTLS bool) {
	s.mu.Lock()
	s.conns[nc] = true
	s.mu.Unlock()
	c := &conn{s: s, nc: nc, who: peerName(nc), local: isLocal(nc)}
	defer func() {
		s.mu.Lock()
		delete(s.conns, c.nc)
		delete(s.conns, nc)
		s.mu.Unlock()
		c.nc.Close()
	}()
	if implicitTLS {
		tc := tls.Server(nc, s.cfg.TLS)
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			s.cfg.Logf("ldap %s: TLS: %v", c.who, err)
			return
		}
		tc.SetDeadline(time.Time{})
		c.nc, c.tls = tc, true
	}
	c.r = bufio.NewReader(c.nc)
	for {
		c.nc.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		p, err := readMessage(c.r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.cfg.Logf("ldap %s: %v", c.who, err)
			}
			return
		}
		c.nc.SetDeadline(time.Now().Add(time.Minute))
		if !c.handle(p) {
			return
		}
	}
}

// readMessage reads one BER SEQUENCE of at most MaxMessage bytes.
func readMessage(r *bufio.Reader) (*ber.Packet, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, fmt.Errorf("not an LDAP message (tag 0x%02x)", tag)
	}
	l0, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	head := []byte{tag, l0}
	size := int(l0)
	if l0&0x80 != 0 {
		n := int(l0 & 0x7f)
		if n == 0 || n > 3 {
			return nil, errors.New("bad message length")
		}
		size = 0
		for i := 0; i < n; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			head = append(head, b)
			size = size<<8 | int(b)
		}
	}
	if size > MaxMessage {
		return nil, fmt.Errorf("message of %d bytes, more than %d", size, MaxMessage)
	}
	buf := make([]byte, len(head)+size)
	copy(buf, head)
	if _, err := io.ReadFull(r, buf[len(head):]); err != nil {
		return nil, err
	}
	return ber.DecodePacketErr(buf)
}

// send writes one LDAP message: msgID, op and the controls (nil: none).
func (c *conn) send(id int64, op *ber.Packet, controls ...*ber.Packet) error {
	m := ber.NewSequence("LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	m.AppendChild(op)
	if len(controls) > 0 {
		cs := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
		for _, x := range controls {
			cs.AppendChild(x)
		}
		m.AppendChild(cs)
	}
	_, err := c.nc.Write(m.Bytes())
	return err
}

// result is an LDAPResult with the application tag of a response.
func result(tag ber.Tag, code uint16, matched, msg string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, matched, "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, "diagnosticMessage"))
	return p
}

// str is the text of a primitive packet, of any class.
func str(p *ber.Packet) string {
	if p == nil {
		return ""
	}
	if v, ok := p.Value.(string); ok {
		return v
	}
	if p.Data != nil {
		return p.Data.String()
	}
	return ""
}

// num is the value of an INTEGER, ENUMERATED or BOOLEAN packet.
func num(p *ber.Packet) int64 {
	switch v := p.Value.(type) {
	case int64:
		return v
	case bool:
		if v {
			return 1
		}
	}
	return 0
}

// control is one control of a request.
type control struct {
	oid      string
	critical bool
	value    *ber.Packet
}

func controlsOf(m *ber.Packet) []control {
	if len(m.Children) < 3 {
		return nil
	}
	cs := m.Children[2]
	if cs.ClassType != ber.ClassContext || cs.Tag != 0 {
		return nil
	}
	var out []control
	for _, x := range cs.Children {
		if len(x.Children) == 0 {
			continue
		}
		ct := control{oid: str(x.Children[0])}
		for _, y := range x.Children[1:] {
			switch y.Tag {
			case ber.TagBoolean:
				ct.critical = num(y) != 0
			case ber.TagOctetString:
				ct.value = y
			}
		}
		out = append(out, ct)
	}
	return out
}

// handle answers one message; false closes the connection.
func (c *conn) handle(m *ber.Packet) bool {
	if len(m.Children) < 2 {
		return false
	}
	id := num(m.Children[0])
	op := m.Children[1]
	if op.ClassType != ber.ClassApplication {
		return false
	}
	ctrls := controlsOf(m)
	// a critical control that ldapd does not know refuses the operation
	for _, ct := range ctrls {
		if ct.critical && !(ct.oid == OIDPaging && op.Tag == ldap.ApplicationSearchRequest) {
			if resp, ok := responseTag[op.Tag]; ok {
				c.send(id, result(resp, ldap.LDAPResultUnavailableCriticalExtension, "", "control "+ct.oid+" is not supported"))
				return true
			}
		}
	}
	switch op.Tag {
	case ldap.ApplicationBindRequest:
		return c.bind(id, op)
	case ldap.ApplicationUnbindRequest:
		return false
	case ldap.ApplicationSearchRequest:
		return c.search(id, op, ctrls)
	case ldap.ApplicationCompareRequest:
		return c.compare(id, op)
	case ldap.ApplicationExtendedRequest:
		return c.extended(id, op)
	case ldap.ApplicationAbandonRequest:
		// one request at a time: there is nothing to abandon
		return true
	case ldap.ApplicationModifyRequest, ldap.ApplicationAddRequest,
		ldap.ApplicationDelRequest, ldap.ApplicationModifyDNRequest:
		c.send(id, result(responseTag[op.Tag], ldap.LDAPResultUnwillingToPerform, "", "the directory is read only"))
		return true
	}
	c.s.cfg.Logf("ldap %s: operation %d is not known", c.who, op.Tag)
	return false
}

// responseTag is the response of each request.
var responseTag = map[ber.Tag]ber.Tag{
	ldap.ApplicationBindRequest:     ldap.ApplicationBindResponse,
	ldap.ApplicationSearchRequest:   ldap.ApplicationSearchResultDone,
	ldap.ApplicationModifyRequest:   ldap.ApplicationModifyResponse,
	ldap.ApplicationAddRequest:      ldap.ApplicationAddResponse,
	ldap.ApplicationDelRequest:      ldap.ApplicationDelResponse,
	ldap.ApplicationModifyDNRequest: ldap.ApplicationModifyDNResponse,
	ldap.ApplicationCompareRequest:  ldap.ApplicationCompareResponse,
	ldap.ApplicationExtendedRequest: ldap.ApplicationExtendedResponse,
}

// secure: a password may cross this connection
func (c *conn) secure() bool {
	return c.tls || c.local || !c.s.cfg.RequireTLS
}

// bind: a simple bind, as a user, as the service account, or anonymous
func (c *conn) bind(id int64, op *ber.Packet) bool {
	reply := func(code uint16, msg string) bool {
		return c.send(id, result(ldap.ApplicationBindResponse, code, "", msg)) == nil
	}
	if len(op.Children) < 3 {
		return reply(ldap.LDAPResultProtocolError, "bad bind request")
	}
	// a new bind ends the old one, also when it fails
	c.dn, c.user, c.server = "", "", false
	if v := num(op.Children[0]); v != 3 {
		return reply(ldap.LDAPResultProtocolError, "LDAPv3 only")
	}
	name := str(op.Children[1])
	auth := op.Children[2]
	if auth.ClassType != ber.ClassContext || auth.Tag != 0 {
		return reply(ldap.LDAPResultAuthMethodNotSupported, "simple bind only")
	}
	password := str(auth)
	if name == "" && password == "" {
		return reply(ldap.LDAPResultSuccess, "")
	}
	if password == "" {
		// RFC 4513 5.1.2: an unauthenticated bind is refused
		return reply(ldap.LDAPResultUnwillingToPerform, "unauthenticated bind")
	}
	if !c.secure() {
		c.s.cfg.Logf("ldap %s: bind dn=%q without TLS, refused", c.who, name)
		return reply(ldap.LDAPResultConfidentialityRequired, "use StartTLS or ldaps first")
	}
	deny := func(why string) bool {
		c.s.cfg.Logf("ldap %s: bind dn=%q denied (%s)", c.who, name, why)
		time.Sleep(c.s.cfg.FailDelay)
		return reply(ldap.LDAPResultInvalidCredentials, "")
	}
	norm, err := NormDN(name)
	if err != nil {
		// a bare user name, as some programs send
		norm = ""
	}
	if c.s.cfg.ServiceDN != "" && norm != "" {
		if sdn, _ := NormDN(c.s.cfg.ServiceDN); sdn == norm {
			if !c.s.cfg.ServiceCheck(password) {
				return deny("wrong password")
			}
			c.dn, c.server = strings.TrimSpace(name), true
			c.s.cfg.Logf("ldap %s: bind as the service account", c.who)
			return reply(ldap.LDAPResultSuccess, "")
		}
	}
	user, ok := c.s.userOf(name, norm)
	if !ok || !c.s.cfg.ValidUser(user) {
		c.s.cfg.Burn(password)
		return deny("not a user DN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	via, err := c.s.cfg.Authenticate(ctx, user, password)
	cancel()
	if err != nil {
		return deny(err.Error())
	}
	c.dn, c.user = c.s.userDN(user), user
	c.s.cfg.Logf("ldap %s: bind user=%s auth=%s", c.who, user, via)
	return reply(ldap.LDAPResultSuccess, "")
}

// userOf: the user name of a bind name, a DN under ou=people (or the
// base) or a bare name
func (s *Server) userOf(name, norm string) (string, bool) {
	if norm == "" {
		if strings.ContainsAny(name, "=,") || name == "" {
			return "", false
		}
		return name, true
	}
	dn, err := ldap.ParseDN(name)
	if err != nil || len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) != 1 {
		return "", false
	}
	first := dn.RDNs[0].Attributes[0]
	if !strings.EqualFold(first.Type, "uid") {
		return "", false
	}
	parent := norm[strings.Index(norm, ",")+1:]
	if !strings.Contains(norm, ",") || (parent != "ou=people,"+s.base && parent != s.base) {
		return "", false
	}
	return first.Value, true
}

func (s *Server) userDN(name string) string  { return "uid=" + escapeRDN(name) + ",ou=people," + s.disp }
func (s *Server) groupDN(name string) string { return "cn=" + escapeRDN(name) + ",ou=groups," + s.disp }

// escapeRDN escapes an RDN value (RFC 4514).
func escapeRDN(v string) string {
	var b strings.Builder
	for i, r := range v {
		switch {
		case strings.ContainsRune(`,+"\<>;=`, r),
			i == 0 && (r == ' ' || r == '#'),
			i == len(v)-1 && r == ' ':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			fmt.Fprintf(&b, "\\%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormDN: a DN in one form, to compare: attribute types and values in
// lower case, no spaces between RDNs.  "" is the root.
func NormDN(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	dn, err := ldap.ParseDN(s)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(dn.RDNs))
	for _, rdn := range dn.RDNs {
		as := make([]string, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			as = append(as, strings.ToLower(strings.TrimSpace(a.Type))+"="+escapeRDN(strings.ToLower(a.Value)))
		}
		parts = append(parts, strings.Join(as, "+"))
	}
	return strings.Join(parts, ","), nil
}

// extended: StartTLS, Who am I? and Password Modify
func (c *conn) extended(id int64, op *ber.Packet) bool {
	resp := func(code uint16, msg, name string, value *ber.Packet) *ber.Packet {
		p := result(ldap.ApplicationExtendedResponse, code, "", msg)
		if name != "" {
			p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, name, "responseName"))
		}
		if value != nil {
			p.AppendChild(value)
		}
		return p
	}
	if len(op.Children) < 1 {
		return c.send(id, resp(ldap.LDAPResultProtocolError, "bad extended request", "", nil)) == nil
	}
	oid := str(op.Children[0])
	var value []byte
	if len(op.Children) > 1 && op.Children[1].Data != nil {
		value = op.Children[1].Data.Bytes()
	}
	switch oid {
	case OIDStartTLS:
		switch {
		case c.s.cfg.TLS == nil:
			return c.send(id, resp(ldap.LDAPResultProtocolError, "no TLS certificate", OIDStartTLS, nil)) == nil
		case c.tls:
			return c.send(id, resp(ldap.LDAPResultOperationsError, "TLS is on already", OIDStartTLS, nil)) == nil
		}
		if c.send(id, resp(ldap.LDAPResultSuccess, "", OIDStartTLS, nil)) != nil {
			return false
		}
		tc := tls.Server(c.nc, c.s.cfg.TLS)
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			c.s.cfg.Logf("ldap %s: StartTLS: %v", c.who, err)
			return false
		}
		tc.SetDeadline(time.Time{})
		c.s.mu.Lock()
		c.s.conns[tc] = true
		c.s.mu.Unlock()
		c.nc, c.tls = tc, true
		c.r = bufio.NewReader(tc)
		return true
	case OIDWhoAmI:
		authz := ""
		if c.dn != "" {
			authz = "dn:" + c.dn
		}
		v := ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, authz, "authzId")
		return c.send(id, resp(ldap.LDAPResultSuccess, "", "", v)) == nil
	case OIDPasswordModify:
		code, msg := c.passwordModify(value)
		return c.send(id, resp(code, msg, "", nil)) == nil
	}
	return c.send(id, resp(ldap.LDAPResultProtocolError, "extended operation "+oid+" is not supported", "", nil)) == nil
}

// passwordModify: RFC 3062, with the old password always
func (c *conn) passwordModify(value []byte) (uint16, string) {
	if c.s.cfg.ChangePassword == nil {
		return ldap.LDAPResultUnwillingToPerform, "passwords cannot be changed here"
	}
	if !c.secure() {
		return ldap.LDAPResultConfidentialityRequired, "use StartTLS or ldaps first"
	}
	var ident, old, nw string
	var haveNew bool
	if len(value) > 0 {
		p, err := ber.DecodePacketErr(value)
		if err != nil {
			return ldap.LDAPResultProtocolError, "bad Password Modify request"
		}
		for _, x := range p.Children {
			switch x.Tag {
			case 0:
				ident = str(x)
			case 1:
				old = str(x)
			case 2:
				nw, haveNew = str(x), true
			}
		}
	}
	user := c.user
	if ident != "" {
		norm, err := NormDN(ident)
		if err != nil {
			norm = ""
		}
		u, ok := c.s.userOf(ident, norm)
		if !ok {
			return ldap.LDAPResultNoSuchObject, "not a user"
		}
		user = u
	}
	switch {
	case user == "":
		return ldap.LDAPResultUnwillingToPerform, "bind first, or give the user"
	case c.user != "" && user != c.user:
		return ldap.LDAPResultInsufficientAccessRights, "a user can change only the user's own password"
	case old == "":
		return ldap.LDAPResultUnwillingToPerform, "give the old password"
	case !haveNew:
		return ldap.LDAPResultUnwillingToPerform, "give the new password"
	case len(nw) < c.s.cfg.MinPassword:
		return ldap.LDAPResultConstraintViolation, fmt.Sprintf("at least %d characters", c.s.cfg.MinPassword)
	case nw == old:
		return ldap.LDAPResultConstraintViolation, "the new password is the old one"
	case !c.s.cfg.ValidUser(user):
		c.s.cfg.Burn(old)
		time.Sleep(c.s.cfg.FailDelay)
		return ldap.LDAPResultInvalidCredentials, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := c.s.cfg.ChangePassword(ctx, user, old, nw)
	switch {
	case err == nil:
		c.s.cfg.Logf("ldap %s: password of %s changed", c.who, user)
		return ldap.LDAPResultSuccess, ""
	case errors.Is(err, ErrBadPassword), errors.Is(err, ErrNoUser):
		c.s.cfg.Logf("ldap %s: password of %s: %v", c.who, user, err)
		time.Sleep(c.s.cfg.FailDelay)
		return ldap.LDAPResultInvalidCredentials, ""
	case errors.Is(err, ErrRefused):
		return ldap.LDAPResultConstraintViolation, "the new password was not accepted"
	case errors.Is(err, ErrCannot):
		return ldap.LDAPResultUnwillingToPerform, "this password cannot be changed here"
	}
	c.s.cfg.Logf("ldap %s: password of %s: %v", c.who, user, err)
	return ldap.LDAPResultOther, "the password cannot be changed now"
}

// peerName is the client's address, for the log.
func peerName(nc net.Conn) string {
	if a := nc.RemoteAddr(); a != nil && a.String() != "" && a.String() != "@" {
		return a.String()
	}
	return "unix"
}

// isLocal: a unix socket, or a TCP peer on loopback
func isLocal(nc net.Conn) bool {
	switch a := nc.RemoteAddr().(type) {
	case *net.UnixAddr:
		return true
	case *net.TCPAddr:
		return a.IP.IsLoopback()
	}
	return false
}
