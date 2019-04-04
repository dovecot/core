/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "event-exporter.h"

void event_export_transport_log(const struct exporter *exporter ATTR_UNUSED,
				const buffer_t *buf)
{
	i_info("%.*s", (int)buf->used, (const char *)buf->data);
}
