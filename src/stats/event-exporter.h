#ifndef EVENT_EXPORTER_H
#define EVENT_EXPORTER_H

#include "stats-metrics.h"

struct event_exporter_transport {
	const char *name;

	void (*deinit)(void);

	/* function to send the event */
	void (*send)(struct exporter *exporter, const buffer_t *buf);

	void (*reopen)(void);
};

extern const struct event_exporter_transport event_exporter_transport_drop;
extern const struct event_exporter_transport event_exporter_transport_file;
extern const struct event_exporter_transport event_exporter_transport_unix;
extern const struct event_exporter_transport event_exporter_transport_http_post;
extern const struct event_exporter_transport event_exporter_transport_log;

const struct event_exporter_transport *
event_exporter_transport_find(const char *name);
void event_exporter_transports_reopen(void);
void event_exporter_transports_deinit(void);

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
   of the categories' ancestors are implictly or explicitly duplicated. */
void event_export_helper_fmt_categories(string_t *dest,
					const struct event *event,
					void (*append)(string_t *, const char *),
					const char *separator);

/* assign transport context to a event exporter */
void event_export_transport_assign_context(const struct exporter *exporter,
					   void *context);

#endif
