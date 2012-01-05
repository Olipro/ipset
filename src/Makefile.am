include $(top_srcdir)/Make_global.am

sbin_PROGRAMS	= ipset
ipset_SOURCES	= ipset.c ui.c
ipset_LDADD	= ../lib/libipset.la
AM_LDFLAGS	= -static

dist_man_MANS = ipset.8

#%.o: %.c
#	${AM_VERBOSE_CC} ${CC} ${AM_DEPFLAGS} ${AM_CFLAGS} ${CFLAGS} -o $@ -c $<
