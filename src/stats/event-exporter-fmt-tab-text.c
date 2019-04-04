/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "lib-event-private.h"
#include "event-exporter.h"
#include "str.h"
#include "strescape.h"
#include "hostpid.h"

static void append_int(string_t *dest, intmax_t val)
{
	str_printfa(dest, "%jd", val);
}

static void append_time(string_t *dest, const struct timeval *time,
			enum event_exporter_time_fmt fmt)
{
	switch (fmt) {
	case EVENT_EXPORTER_TIME_FMT_NATIVE:
		i_panic("tab-text format does not have a native date/time type");
	case EVENT_EXPORTER_TIME_FMT_UNIX:
		event_export_helper_fmt_unix_time(dest, time);
		break;
	case EVENT_EXPORTER_TIME_FMT_RFC3339:
		event_export_helper_fmt_rfc3339_time(dest, time);
		break;
	}
}

static void append_field_value(string_t *dest, const struct event_field *field,
			       const struct metric_export_info *info)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		str_append_tabescaped(dest, field->value.str);
		break;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		append_int(dest, field->value.intmax);
		break;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		append_time(dest, &field->value.timeval,
			    info->exporter->time_format);
		break;
	}
}

static void tabtext_export_name(string_t *dest, struct event *event,
				const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_NAME) == 0)
		return;

	str_append(dest, "event:");
	str_append_tabescaped(dest, event->sending_name);
	str_append_c(dest, '\t');
}

static void tabtext_export_hostname(string_t *dest,
				    const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_HOSTNAME) == 0)
		return;

	str_append(dest, "hostname:");
	str_append_tabescaped(dest, my_hostname);
	str_append_c(dest, '\t');
}

static void tabtext_export_timestamps(string_t *dest, struct event *event,
				      const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_TIMESTAMPS) == 0)
		return;

	str_append(dest, "start_time:");
	append_time(dest, &event->tv_created, info->exporter->time_format);
	str_append(dest, "\tend_time:");
	append_time(dest, &ioloop_timeval, info->exporter->time_format);
	str_append_c(dest, '\t');
}

static void append_category(string_t *dest, struct event_category *cat)
{
	/* append parent's categories */
	if (cat->parent != NULL)
		append_category(dest, cat->parent);

	/* append this */
	str_append(dest, "category:");
	str_append_tabescaped(dest, cat->name);
	str_append_c(dest, '\t');
}

static void tabtext_export_categories(string_t *dest, struct event *event,
				      const struct metric_export_info *info)
{
	struct event_category *const *cats;
	unsigned int count;
	unsigned int i;

	if ((info->include & EVENT_EXPORTER_INCL_CATEGORIES) == 0)
		return;

	cats = event_get_categories(event, &count);
	for (i = 0; i < count; i++)
		append_category(dest, cats[i]);
}

static void tabtext_export_fields(string_t *dest, struct event *event,
				  const struct metric_export_info *info,
				  const unsigned int fields_count,
				  const struct metric_field *fields)
{
	if ((info->include & EVENT_EXPORTER_INCL_FIELDS) == 0)
		return;

	if (fields_count == 0) {
		/* include all fields */
		const struct event_field *fields;
		unsigned int count;

		fields = event_get_fields(event, &count);

		for (unsigned int i = 0; i < count; i++) {
			const struct event_field *field = &fields[i];

			str_append(dest, "field:");
			str_append_tabescaped(dest, field->key);
			str_append_c(dest, '=');
			append_field_value(dest, field, info);
			str_append_c(dest, '\t');
		}
	} else {
		for (unsigned int i = 0; i < fields_count; i++) {
			const char *name = fields[i].field_key;
			const struct event_field *field;

			field = event_find_field(event, name);
			if (field == NULL)
				continue; /* doesn't exist, skip it */

			str_append(dest, "field:");
			str_append_tabescaped(dest, name);
			str_append_c(dest, '=');
			append_field_value(dest, field, info);
			str_append_c(dest, '\t');
		}
	}
}

/*
 * Serialize the event as tab delimited collection of the following:
 *
 *    event:<event name>
 *    hostname:<tab escaped hostname>
 *    start_time:<event creation timestamp>
 *    end_time:<event export timestamp>
 *    category:<category>
 *    field:<name>=<tab escaped value>
 *
 * Note: cat and field can occur multiple times.
 */
void event_export_fmt_tabescaped_text(const struct metric *metric,
				      struct event *event, buffer_t *dest)
{
	const struct metric_export_info *info = &metric->export_info;

	if (info->include == EVENT_EXPORTER_INCL_NONE)
		return;

	tabtext_export_name(dest, event, info);
	tabtext_export_hostname(dest, info);
	tabtext_export_timestamps(dest, event, info);
	tabtext_export_categories(dest, event, info);
	tabtext_export_fields(dest, event, info, metric->fields_count,
			      metric->fields);

	/* remove trailing tab */
	str_truncate(dest, str_len(dest) - 1);
}
