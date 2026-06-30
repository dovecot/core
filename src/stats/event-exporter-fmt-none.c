/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "event-exporter.h"

void event_export_fmt_none(const struct metric *metric ATTR_UNUSED,
			   struct event *event ATTR_UNUSED,
			   buffer_t *dest ATTR_UNUSED)
{
	/* nothing to do */
}
