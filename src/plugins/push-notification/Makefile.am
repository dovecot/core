AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-http \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/plugins/notify

NOPLUGIN_LDFLAGS =
lib20_push_notification_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = lib20_push_notification_plugin.la

if DOVECOT_PLUGIN_DEPS
notify_deps = ../notify/lib15_notify_plugin.la
endif

lib20_push_notification_plugin_la_LIBADD = \
	$(notify_deps)

lib20_push_notification_plugin_la_SOURCES = \
	push-notification-driver-dlog.c \
	push-notification-driver-ox.c \
	push-notification-drivers.c \
	push-notification-event-flagsclear.c \
	push-notification-event-flagsset.c \
	push-notification-event-mailboxcreate.c \
	push-notification-event-mailboxdelete.c \
	push-notification-event-mailboxrename.c \
	push-notification-event-mailboxsubscribe.c \
	push-notification-event-mailboxunsubscribe.c \
	push-notification-event-messageappend.c \
	push-notification-event-messageexpunge.c \
	push-notification-event-messagenew.c \
	push-notification-event-messageread.c \
	push-notification-event-messagetrash.c \
	push-notification-event-message-common.c \
	push-notification-events.c \
	push-notification-events-rfc5423.c \
	push-notification-plugin.c \
	push-notification-triggers.c \
	push-notification-txn-mbox.c \
	push-notification-txn-msg.c

headers = \
	push-notification-drivers.h \
	push-notification-event-flagsclear.h \
	push-notification-event-flagsset.h \
	push-notification-event-mailboxcreate.h \
	push-notification-event-mailboxdelete.h \
	push-notification-event-mailboxrename.h \
	push-notification-event-mailboxsubscribe.h \
	push-notification-event-mailboxunsubscribe.h \
	push-notification-event-message-common.h \
	push-notification-event-messageappend.h \
	push-notification-event-messageexpunge.h \
	push-notification-event-messagenew.h \
	push-notification-event-messageread.h \
	push-notification-event-messagetrash.h \
	push-notification-events.h \
	push-notification-events-rfc5423.h \
	push-notification-plugin.h \
	push-notification-triggers.h \
	push-notification-txn-mbox.h \
	push-notification-txn-msg.h

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

if HAVE_LUA
lib22_push_notification_lua_plugin_la_CFLAGS = $(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/lib-lua \
	-I$(top_srcdir)/src/plugins/mail-lua \
	$(LUA_CFLAGS)
lib22_push_notification_lua_plugin_la_LDFLAGS = module -avoid-version
module_LTLIBRARIES += \
	lib22_push_notification_lua_plugin.la
lib22_push_notification_lua_plugin_la_LIBADD = $(notify_deps) $(LUA_LIBS)
lib22_push_notification_lua_plugin_la_SOURCES = \
	push-notification-driver-lua.c
endif
