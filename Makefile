VERSION := 0.1.0
KDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=

.PHONY: all module cli clean install install-module uninstall test

all: module cli

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

cli:
	$(MAKE) -C cli

clean:
	$(MAKE) -C cli clean
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean

install: all
	install -Dm0755 cli/rayfwctl $(DESTDIR)$(PREFIX)/sbin/rayfwctl
	install -Dm0644 packaging/systemd/rayfw.service $(DESTDIR)/usr/lib/systemd/system/rayfw.service
	install -Dm0644 packaging/bash-completion/rayfwctl $(DESTDIR)/usr/share/bash-completion/completions/rayfwctl
	install -Dm0644 docs/rayfwctl.8 $(DESTDIR)$(PREFIX)/share/man/man8/rayfwctl.8

install-module: module
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules_install
	depmod -a

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/rayfwctl
	rm -f $(DESTDIR)/usr/lib/systemd/system/rayfw.service
	rm -f $(DESTDIR)/usr/share/bash-completion/completions/rayfwctl
	rm -f $(DESTDIR)$(PREFIX)/share/man/man8/rayfwctl.8

test: all
	./tests/test-cli.sh
