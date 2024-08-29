/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "event-exporter.h"

#define LOG_EXPORTER_LONG_FIELD_TRUNCATE_LEN 1000

static int event_exporter_log_init(pool_t pool, struct event *event ATTR_UNUSED,
				   struct event_exporter **exporter_r,
				   const char **error_r ATTR_UNUSED)
{
	struct event_exporter *exporter = p_new(pool, struct event_exporter, 1);
	exporter->format_max_field_len =
		LOG_EXPORTER_LONG_FIELD_TRUNCATE_LEN;
	*exporter_r = exporter;
	return 0;
}

static void
event_exporter_log_send(struct event_exporter *exporter ATTR_UNUSED,
			const buffer_t *buf)
{
	i_info("%.*s", (int)buf->used, (const char *)buf->data);
}

const struct event_exporter_transport event_exporter_transport_log = {
	.name = "log",

	.init = event_exporter_log_init,
	.send = event_exporter_log_send,
};
