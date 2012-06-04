noinst_LIBRARIES = libdsync.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/doveadm

libdsync_a_SOURCES = \
	doveadm-dsync.c \
	dsync-brain.c \
	dsync-brain-mailbox.c \
	dsync-brain-mailbox-tree.c \
	dsync-brain-mailbox-tree-sync.c \
	dsync-brain-mails.c \
	dsync-deserializer.c \
	dsync-mail.c \
	dsync-mailbox-import.c \
	dsync-mailbox-export.c \
	dsync-mailbox-state.c \
	dsync-mailbox-tree.c \
	dsync-mailbox-tree-fill.c \
	dsync-mailbox-tree-sync.c \
	dsync-serializer.c \
	dsync-slave.c \
	dsync-slave-io.c \
	dsync-slave-pipe.c \
	dsync-transaction-log-scan.c

noinst_HEADERS = \
	doveadm-dsync.h \
	dsync-brain.h \
	dsync-brain-private.h \
	dsync-mail.h \
	dsync-mailbox.h \
	dsync-mailbox-import.h \
	dsync-mailbox-export.h \
	dsync-mailbox-state.h \
	dsync-mailbox-state-export.h \
	dsync-mailbox-tree.h \
	dsync-mailbox-tree-private.h \
	dsync-serializer.h \
	dsync-deserializer.h \
	dsync-slave.h \
	dsync-slave-private.h \
	dsync-transaction-log-scan.h
