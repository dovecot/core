/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "event-exporter.h"

static void
event_exporter_log_send(struct event_exporter *exporter ATTR_UNUSED,
			const buffer_t *buf)
{
	i_info("%.*s", (int)buf->used, (const char *)buf->data);
}

const struct event_exporter_transport event_exporter_transport_log = {
	.name = "log",

	.send = event_exporter_log_send,
};
