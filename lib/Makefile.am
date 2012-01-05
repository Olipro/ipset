include $(top_srcdir)/Make_global.am

AM_CFLAGS += ${libmnl_CFLAGS}

lib_LTLIBRARIES = libipset.la

libipset_la_LDFLAGS = -Wl,--version-script=$(top_srcdir)/lib/libipset.map -version-info $(LIBVERSION)
libipset_la_LIBADD  = ${libmnl_LIBS}
libipset_la_SOURCES = \
	data.c \
	errcode.c \
	icmp.c \
	icmpv6.c \
	mnl.c \
	parse.c \
	print.c \
	session.c \
	types.c \
	ipset_bitmap_ip.c \
	ipset_bitmap_ipmac.c \
	ipset_bitmap_port.c \
	ipset_hash_ip.c \
	ipset_hash_ipport.c \
	ipset_hash_ipportip.c \
	ipset_hash_ipportnet.c \
	ipset_hash_net.c \
	ipset_hash_netport.c \
	ipset_hash_netiface.c \
	ipset_list_set.c

#%.o: %.c
#	${AM_VERBOSE_CC} ${CC} ${AM_DEPFLAGS} ${AM_CFLAGS} ${CFLAGS} -o $@ -c $<
