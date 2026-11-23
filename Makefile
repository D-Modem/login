# dmodem-login: the login and menu of a dial-up line (Go 1.22 or later)
#
#   make                 build, with PAM when libpam's headers are there,
#                        and the pppd plugin when pppd's are (ppp-dev)
#   make PAM=0           without PAM (PAM=1: with, or fail)
#   make PPPD=0          without the pppd plugin (PPPD=1: with, or fail)
#   make test            the tests
#   make install         into $(BINDIR), samples into $(CONF_DIR), the
#                        plugin into pppd's plugin directory
#   make install-freepbx into $(BINDIR), freepbx/'s samples into
#                        /etc/dmodem-login and dmodem-login.service into systemd
#   make install-dialup  the PPP callers' network (docs/dialup-network.md):
#                        dmodem-login-dialup, pppd's hooks, the units, and
#                        dialup.conf, dnsmasq.conf, dns.d/ in /etc/dmodem-login

GO ?= go
BINDIR ?= /usr/local/bin
CONF_DIR ?= /etc/asterisk
PAM ?= $(shell [ -e /usr/include/security/pam_appl.h ] && echo 1 || echo 0)
TAGS := $(if $(filter 1,$(PAM)),-tags pam)
CC ?= cc
CFLAGS ?= -O2 -g
PPPD ?= $(shell [ -e /usr/include/pppd/pppd.h ] && echo 1 || echo 0)
PPPD_VERSION ?= $(shell sed -n 's/^\#define VERSION[^"]*"\(.*\)"/\1/p' /usr/include/pppd/patchlevel.h 2>/dev/null)
PPPD_PLUGIN_DIR ?= /usr/lib/pppd/$(PPPD_VERSION)

all: dmodem-login $(if $(filter 1,$(PPPD)),pppd/dmodem-login.so)

# AutoPPP's PAP logins: pppd's plugin, for the pppd of these headers
pppd/dmodem-login.so: pppd/dmodem-login.c
	$(CC) $(CFLAGS) -Wall -fPIC -shared -o $@ $<

# -buildvcs=false: nothing reads the VCS stamp, and git refuses a checkout
# owned by another user (sudo make in your own clone), which fails the build
dmodem-login: FORCE
	$(GO) build -buildvcs=false $(TAGS) -o $@ ./cmd/dmodem-login

test:
	$(GO) vet $(TAGS) ./...
	$(GO) test $(TAGS) ./...

install: all
	install -D -m 755 dmodem-login $(DESTDIR)$(BINDIR)/dmodem-login
	# modemmenu: the old name, for app_dmodem profiles that still use it
	ln -sf dmodem-login $(DESTDIR)$(BINDIR)/modemmenu
	[ -e $(DESTDIR)$(CONF_DIR)/dmodem-login.conf ] || \
		install -D -m 640 samples/dmodem-login.conf.sample $(DESTDIR)$(CONF_DIR)/dmodem-login.conf
	[ -e $(DESTDIR)$(CONF_DIR)/dmodem-login.users ] || \
		install -D -m 600 samples/dmodem-login.users.sample $(DESTDIR)$(CONF_DIR)/dmodem-login.users
	[ $(PAM) != 1 ] || [ -e $(DESTDIR)/etc/pam.d/dmodem-login ] || \
		install -D -m 644 samples/dmodem-login.pam.sample $(DESTDIR)/etc/pam.d/dmodem-login
	[ $(PPPD) != 1 ] || \
		{ install -D -m 644 pppd/dmodem-login.so $(DESTDIR)$(PPPD_PLUGIN_DIR)/dmodem-login.so && \
		  ln -sf dmodem-login.so $(DESTDIR)$(PPPD_PLUGIN_DIR)/modemmenu.so; }

# FreePBX (freepbx/README.md): the files in /etc/dmodem-login, out of
# fwconsole chown's way; files already there are kept
FREEPBX_CONF_DIR ?= /etc/dmodem-login
install-freepbx: all
	install -D -m 755 dmodem-login $(DESTDIR)$(BINDIR)/dmodem-login
	# modemmenu: the old name, for app_dmodem profiles that still use it
	ln -sf dmodem-login $(DESTDIR)$(BINDIR)/modemmenu
	[ -e $(DESTDIR)$(FREEPBX_CONF_DIR)/dmodem-login.conf ] || \
		install -D -m 644 freepbx/dmodem-login.conf $(DESTDIR)$(FREEPBX_CONF_DIR)/dmodem-login.conf
	[ -e $(DESTDIR)$(FREEPBX_CONF_DIR)/dmodem-login.users ] || \
		install -D -m 600 freepbx/dmodem-login.users $(DESTDIR)$(FREEPBX_CONF_DIR)/dmodem-login.users
	[ -e $(DESTDIR)/etc/systemd/system/dmodem-login.service ] || \
		install -D -m 644 freepbx/dmodem-login.service $(DESTDIR)/etc/systemd/system/dmodem-login.service
	[ $(PPPD) != 1 ] || \
		{ install -D -m 644 pppd/dmodem-login.so $(DESTDIR)$(PPPD_PLUGIN_DIR)/dmodem-login.so && \
		  ln -sf dmodem-login.so $(DESTDIR)$(PPPD_PLUGIN_DIR)/modemmenu.so; }

clean:
	rm -f dmodem-login pppd/dmodem-login.so

FORCE:
.PHONY: all test install install-freepbx install-dialup clean FORCE

# the PPP callers' network: files already in /etc/dmodem-login are kept
SBINDIR ?= /usr/local/sbin
install-dialup:
	install -D -m 755 dialup/dmodem-login-dialup $(DESTDIR)$(SBINDIR)/dmodem-login-dialup
	install -D -m 755 dialup/ip-up $(DESTDIR)/etc/ppp/ip-up.d/dmodem-login-dialup
	install -D -m 755 dialup/ip-down $(DESTDIR)/etc/ppp/ip-down.d/dmodem-login-dialup
	install -D -m 644 dialup/dmodem-login-dialup.service $(DESTDIR)/etc/systemd/system/dmodem-login-dialup.service
	install -D -m 644 dialup/dmodem-login-dns.service $(DESTDIR)/etc/systemd/system/dmodem-login-dns.service
	[ -e $(DESTDIR)$(FREEPBX_CONF_DIR)/dialup.conf ] || \
		install -D -m 644 dialup/dialup.conf.sample $(DESTDIR)$(FREEPBX_CONF_DIR)/dialup.conf
	[ -e $(DESTDIR)$(FREEPBX_CONF_DIR)/dnsmasq.conf ] || \
		install -D -m 644 dialup/dnsmasq.conf $(DESTDIR)$(FREEPBX_CONF_DIR)/dnsmasq.conf
	[ -e $(DESTDIR)$(FREEPBX_CONF_DIR)/dns.d/services.conf ] || \
		install -D -m 644 dialup/dns.d/services.conf $(DESTDIR)$(FREEPBX_CONF_DIR)/dns.d/services.conf
