#ifndef EVENT_EXPORTER_H
#define EVENT_EXPORTER_H

#include "stats-metrics.h"

struct event_exporter_transport {
	const char *name;

	int (*init)(pool_t pool, struct event *event,
		    struct event_exporter **exporter_r, const char **error_r);
	void (*deinit)(struct event_exporter *exporter);

	/* function to send the event */
	void (*send)(struct event_exporter *exporter, const buffer_t *buf);

	void (*reopen)(struct event_exporter *exporter);
};

extern const struct event_exporter_transport event_exporter_transport_drop;
extern const struct event_exporter_transport event_exporter_transport_file;
extern const struct event_exporter_transport event_exporter_transport_unix;
extern const struct event_exporter_transport event_exporter_transport_http_post;
extern const struct event_exporter_transport event_exporter_transport_log;

const struct event_exporter_transport *
event_exporter_transport_find(const char *name);

void event_exporters_reopen(void);
void event_exporters_deinit(void);

int event_exporter_init(const struct event_exporter_transport *transport,
			pool_t pool, struct event *event,
			struct event_exporter **exporter_r,
			const char **error_r);

/* fmt functions */
void event_export_fmt_json(const struct metric *metric, struct event *event, buffer_t *dest);
void event_export_fmt_none(const struct metric *metric, struct event *event, buffer_t *dest);
void event_export_fmt_tabescaped_text(const struct metric *metric, struct event *event, buffer_t *dest);

/* append a microsecond resolution RFC3339 UTC timestamp */
void event_export_helper_fmt_rfc3339_time(string_t *dest, const struct timeval *time);
/* append a microsecond resolution unix timestamp in seconds (i.e., %u.%06u) */
void event_export_helper_fmt_unix_time(string_t *dest, const struct timeval *time);
/* append category names using 'append' function pointer, separated by 'separator' arg

   The result has no duplicates regardless of if the array has any or if any
   of the categories' ancestors are implicitly or explicitly duplicated. */
void event_export_helper_fmt_categories(string_t *dest,
					const struct event *event,
					void (*append)(string_t *, const char *),
					const char *separator);

#endif
