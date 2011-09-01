include $(top_srcdir)/Make_global.am

sbin_PROGRAMS	= ipset
ipset_SOURCES	= ipset.c \
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
	ipset_list_set.c \
	ui.c
ipset_LDADD	= ../lib/libipset.la
AM_LDFLAGS	= -static

man_MANS = ipset.8

#%.o: %.c
#	${AM_VERBOSE_CC} ${CC} ${AM_DEPFLAGS} ${AM_CFLAGS} ${CFLAGS} -o $@ -c $<
