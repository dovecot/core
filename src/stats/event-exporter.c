/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "array.h"
#include "event-exporter.h"

static const struct event_exporter_transport *event_exporter_transports[] = {
	&event_exporter_transport_drop,
	&event_exporter_transport_file,
	&event_exporter_transport_unix,
	&event_exporter_transport_http_post,
	&event_exporter_transport_log,
};

static ARRAY(struct event_exporter *) event_exporters;

const struct event_exporter_transport *
event_exporter_transport_find(const char *name)
{
	for (unsigned int i = 0; i < N_ELEMENTS(event_exporter_transports); i++) {
		if (strcmp(event_exporter_transports[i]->name, name) == 0)
			return event_exporter_transports[i];
	}
	return NULL;
}

void event_exporters_reopen(void)
{
	struct event_exporter *exporter;

	array_foreach_elem(&event_exporters, exporter) {
		if (exporter->transport->reopen != NULL)
			exporter->transport->reopen(exporter);
	}
}

void event_exporters_deinit(void)
{
	struct event_exporter *exporter;

	if (!array_is_created(&event_exporters))
		return;

	array_foreach_elem(&event_exporters, exporter) {
		if (exporter->transport->deinit != NULL)
			exporter->transport->deinit(exporter);
	}
}

int event_exporter_init(const struct event_exporter_transport *transport,
			pool_t pool, struct event *event,
			struct event_exporter **exporter_r,
			const char **error_r)
{
	struct event_exporter *exporter;

	if (transport->init == NULL)
		exporter = p_new(pool, struct event_exporter, 1);
	else if (transport->init(pool, event, &exporter, error_r) < 0)
		return -1;

	if (!array_is_created(&event_exporters))
		i_array_init(&event_exporters, 4);
	array_push_back(&event_exporters, &exporter);
	*exporter_r = exporter;
	return 0;
}
