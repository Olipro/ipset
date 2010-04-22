## Process this file with automake to produce Makefile.in

include $(top_srcdir)/Make_global.am

if ! WITH_KBUILDDIR
KBUILD_OUTPUT=/lib/modules/`uname -r`/build
else
KBUILD_OUTPUT=$(KBUILDDIR)
endif
if ! WITH_MAXSETS
IP_SET_MAX=256
else
IP_SET_MAX=$(MAXSETS)
endif
if ENABLE_VERBOSE
V=1
else
V=0
endif

SUBDIRS		= lib src

modules:
	cd kernel; make -C $(KBUILD_OUTPUT) M=`pwd` V=$V IP_SET_MAX=$(IP_SET_MAX) modules

modules_install:
	cd kernel; make -C $(KBUILD_OUTPUT) M=`pwd` modules_install

modules_clean:
	cd kernel; make -C $(KBUILD_OUTPUT) M=`pwd` clean

update_includes:
	./update ip_set.h
	./update ip_set_bitmap.h
	./update ip_set_hash.h

tests:
	cd tests; ./runtest.sh

cleanup_dirs := . include/libipset lib src tests

tidy: distclean
	rm -rf .deps $(foreach dir,$(cleanup_dirs),$(wildcard $(dir)/*~))
	rm -rf aclocal.m4 autom4te.cache 
	rm -rf config.* configure depcomp install-sh libtool ltmain.sh
	rm -rf Makefile Makefile.in */Makefile */Makefile.in
	rm -rf missing stamp-h1

.PHONY: modules modules_instal modules_clean update_includes tests
