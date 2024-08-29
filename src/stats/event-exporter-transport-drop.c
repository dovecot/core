/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "event-exporter.h"

static void
event_exporter_drop_send(struct event_exporter *exporter ATTR_UNUSED,
			 const buffer_t *buf ATTR_UNUSED)
{
}

const struct event_exporter_transport event_exporter_transport_drop = {
	.name = "drop",

	.send = event_exporter_drop_send,
};
