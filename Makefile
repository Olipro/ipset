#!/usr/bin/make

######################################################################
# YOU SHOULD NOT NEED TO TOUCH ANYTHING BELOW THIS LINE
######################################################################

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif
ifndef IP_NF_SET_MAX
IP_NF_SET_MAX=256
endif
ifndef IP_NF_SET_HASHSIZE
IP_NF_SET_HASHSIZE=1024
endif

IPSET_VERSION:=2.3.2

PREFIX:=/usr/local
LIBDIR:=$(PREFIX)/lib
BINDIR:=$(PREFIX)/sbin
MANDIR:=$(PREFIX)/man
INCDIR:=$(PREFIX)/include
IPSET_LIB_DIR:=$(LIBDIR)/ipset

# directory for new iptables releases
RELEASE_DIR:=/tmp

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -Ikernel/include -I. # -g -DIPSET_DEBUG #-pg # -DIPTC_DEBUG
SH_CFLAGS:=$(CFLAGS) -fPIC
SETTYPES:=ipmap portmap macipmap iphash nethash iptree iptreemap ipporthash

PROGRAMS=ipset
SHARED_LIBS=$(foreach T, $(SETTYPES),libipset_$(T).so)
INSTALL=$(DESTDIR)$(BINDIR)/ipset $(DESTDIR)$(MANDIR)/man8/ipset.8
INSTALL+=$(foreach T, $(SETTYPES), $(DESTDIR)$(LIBDIR)/ipset/libipset_$(T).so)

all: $(PROGRAMS) $(SHARED_LIBS)
	cd kernel; make -C $(KERNEL_DIR) M=`pwd` IP_NF_SET_MAX=$(IP_NF_SET_MAX) IP_NF_SET_HASHSIZE=$(IP_NF_SET_HASHSIZE) modules

.PHONY: tests

tests:
	cd tests; ./runtest.sh

ipset_install: all $(INSTALL)

modules_install:
	cd kernel; make -C $(KERNEL_DIR) M=`pwd` modules_install

install: ipset_install modules_install

clean: $(EXTRA_CLEANS)
	rm -rf $(PROGRAMS) $(SHARED_LIBS) *.o *~
	cd kernel; make -C $(KERNEL_DIR) M=`pwd` clean

#The ipset(8) self
ipset.o: ipset.c
	$(CC) $(CFLAGS) -DIPSET_VERSION=\"$(IPSET_VERSION)\" -DIPSET_LIB_DIR=\"$(IPSET_LIB_DIR)\" -c -o $@ $<

ipset: ipset.o
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ $^

#Pooltypes
ipset_%.o: ipset_%.c
	$(CC) $(SH_CFLAGS) -o $@ -c $<

libipset_%.so: ipset_%.o
	$(LD) -shared -o $@ $<

$(DESTDIR)$(LIBDIR)/ipset/libipset_%.so: libipset_%.so
	@[ -d $(DESTDIR)$(LIBDIR)/ipset ] || mkdir -p $(DESTDIR)$(LIBDIR)/ipset
	cp $< $@

$(DESTDIR)$(BINDIR)/ipset: ipset
	@[ -d $(DESTDIR)$(BINDIR) ] || mkdir -p $(DESTDIR)$(BINDIR)
	cp $< $@

$(DESTDIR)$(MANDIR)/man8/ipset.8: ipset.8
	@[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp $< $@
