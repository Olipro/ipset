#!/usr/bin/make

IPSET_VERSION:=v1.0
IPSET_LIB_DIR:=$(DESTDIR)$(LIBDIR)/ipset
#IPSET_LIB_DIR:=.
#CFLAGS:=-I$(KERNEL_DIR)/include

SETTYPES:=ipmap portmap macipmap iphash

EXTRAS+=$(shell [ -f $(KERNEL_DIR)/include/linux/netfilter_ipv4/ip_set.h ] && echo ipset/ipset)
EXTRAS+=$(foreach T, $(SETTYPES),ipset/libipset_$(T).so)
EXTRA_INSTALLS+=$(DESTDIR)$(BINDIR)/ipset $(DESTDIR)$(MANDIR)/man8/ipset.8
EXTRA_INSTALLS+=$(foreach T, $(SETTYPES), $(DESTDIR)$(LIBDIR)/ipset/libipset_$(T).so)

ifndef TOPLEVEL_INCLUDED
local:
	cd .. && $(MAKE) $(KERN_TARGETS) $(SHARED_LIBS) $(EXTRAS)

else
EXTRA_DEPENDS+=$(shell [ -f $(KERNEL_DIR)/include/linux/netfilter_ipv4/ip_set.h ] && echo "")
CFLAGS+=-DIPSET_VERSION=$(IPSET_VERSION) -DIPSET_LIB_DIR=\"$(IPSET_LIB_DIR)\"

#The ipset(8) self
ipset/ipset.o: ipset/ipset.c
	$(CC) $(CFLAGS) -g -c -o $@ $<

ipset/ipset: ipset/ipset.o
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ $^

#Pooltypes
ipset/ipset_%.o: ipset/ipset_%.c
	$(CC) $(CFLAGS) -c -o $@ $<

ipset/libipset_%.so: ipset/ipset_%.o
	$(LD) -shared -o $@ $<

$(DESTDIR)$(LIBDIR)/ipset/libipset_%.so: ipset/libipset_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/ipset ] || mkdir -p $(DESTDIR)$(LIBDIR)/ipset
	cp $< $@

$(DESTDIR)$(BINDIR)/ipset: ipset/ipset
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(DESTDIR)$(MANDIR)/man8/ipset.8: ipset/ipset.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@
endif
