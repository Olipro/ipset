include $(top_srcdir)/Make_global.am

sbin_PROGRAMS	= ipset
ipset_SOURCES	= ipset.c \
	errcode.c \
	ipset_bitmap_ip.c \
	ipset_bitmap_ipmac.c \
	ipset_bitmap_port.c \
	ipset_hash_ip.c \
	ipset_hash_ipport.c \
	ipset_hash_ipportip.c \
	ipset_hash_ipportnet.c \
	ipset_hash_net.c \
	ipset_list_set.c \
	ipset_tree_ip.c \
	ui.c
ipset_LDADD	= ../lib/libipset.la
AM_LDFLAGS	= -static

#%.o: %.c
#	${AM_VERBOSE_CC} ${CC} ${AM_DEPFLAGS} ${AM_CFLAGS} ${CFLAGS} -o $@ -c $<
