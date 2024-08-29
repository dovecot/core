/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "event-exporter.h"

static const struct event_exporter_transport *event_exporter_transports[] = {
	&event_exporter_transport_drop,
	&event_exporter_transport_file,
	&event_exporter_transport_unix,
	&event_exporter_transport_http_post,
	&event_exporter_transport_log,
};

const struct event_exporter_transport *
event_exporter_transport_find(const char *name)
{
	for (unsigned int i = 0; i < N_ELEMENTS(event_exporter_transports); i++) {
		if (strcmp(event_exporter_transports[i]->name, name) == 0)
			return event_exporter_transports[i];
	}
	return NULL;
}

void event_exporter_transports_reopen(void)
{
	for (unsigned int i = 0; i < N_ELEMENTS(event_exporter_transports); i++) {
		if (event_exporter_transports[i]->reopen != NULL)
			event_exporter_transports[i]->reopen();
	}
}

void event_exporter_transports_deinit(void)
{
	for (unsigned int i = 0; i < N_ELEMENTS(event_exporter_transports); i++) {
		if (event_exporter_transports[i]->reopen != NULL)
			event_exporter_transports[i]->deinit();
	}
}
