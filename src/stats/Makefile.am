pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = stats

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	$(BINARY_CFLAGS)

stats_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

stats_DEPENDENCIES = $(LIBDOVECOT_DEPS)

stats_SOURCES = \
	client-reader.c \
	client-writer.c \
	event-exporter-fmt.c \
	event-exporter-fmt-json.c \
	event-exporter-fmt-none.c \
	event-exporter-transport-drop.c \
	main.c \
	stats-event-category.c \
	stats-metrics.c \
	stats-settings.c

noinst_HEADERS = \
	client-reader.h \
	client-writer.h \
	event-exporter.h \
	stats-event-category.h \
	stats-metrics.h \
	stats-settings.h
