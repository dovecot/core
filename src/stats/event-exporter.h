#ifndef EVENT_EXPORTER_H
#define EVENT_EXPORTER_H

#include "stats-metrics.h"

/* fmt functions */
void event_export_fmt_json(const struct metric *metric, struct event *event, buffer_t *dest);
void event_export_fmt_none(const struct metric *metric, struct event *event, buffer_t *dest);
void event_export_fmt_tabescaped_text(const struct metric *metric, struct event *event, buffer_t *dest);

/* transport functions */
void event_export_transport_drop(const struct exporter *exporter, const buffer_t *buf);
void event_export_transport_http_post(const struct exporter *exporter, const buffer_t *buf);
void event_export_transport_http_post_deinit(void);
void event_export_transport_log(const struct exporter *exporter, const buffer_t *buf);

/* append a microsecond resolution RFC3339 UTC timestamp */
void event_export_helper_fmt_rfc3339_time(string_t *dest, const struct timeval *time);
/* append a microsecond resolution unix timestamp in seconds (i.e., %u.%06u) */
void event_export_helper_fmt_unix_time(string_t *dest, const struct timeval *time);
/* append category names using 'append' function pointer, separated by 'separator' arg

   The result has no duplicates regardless of if the array has any or if any
   of the categories' ancestors are implictly or explicitly duplicated. */
void event_export_helper_fmt_categories(string_t *dest,
					struct event_category *const *cats,
					unsigned int count,
					void (*append)(string_t *, const char *),
					const char *separator);

#endif
