/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "lib-event-private.h"
#include "event-exporter.h"
#include "str.h"
#include "json-parser.h"
#include "hostpid.h"

static void append_str(string_t *dest, const char *str)
{
	str_append_c(dest, '"');
	json_append_escaped(dest, str);
	str_append_c(dest, '"');
}

static void append_str_max_len(string_t *dest, const char *str,
			       const struct metric_export_info *info)
{
	str_append_c(dest, '"');
	if (info->exporter->format_max_field_len == 0)
		json_append_escaped(dest, str);
	else {
		size_t len = strlen(str);
		json_append_escaped_data(dest, (const unsigned char *)str,
			I_MIN(len, info->exporter->format_max_field_len));
		if (len > info->exporter->format_max_field_len)
			str_append(dest, "...");
	}
	str_append_c(dest, '"');
}

static void
append_strlist(string_t *dest, const ARRAY_TYPE(const_string) *strlist,
	       const struct metric_export_info *info)
{
	const char *value;
	bool first = TRUE;

	str_append_c(dest, '[');
	array_foreach_elem(strlist, value) {
		if (first)
			first = FALSE;
		else
			str_append_c(dest, ',');
		append_str_max_len(dest, value, info);
	}
	str_append_c(dest, ']');
}

static void append_int(string_t *dest, intmax_t val)
{
	str_printfa(dest, "%jd", val);
}

static void append_time(string_t *dest, const struct timeval *time,
			enum event_exporter_time_fmt fmt)
{
	switch (fmt) {
	case EVENT_EXPORTER_TIME_FMT_NATIVE:
		i_panic("JSON does not have a native date/time type");
	case EVENT_EXPORTER_TIME_FMT_UNIX:
		event_export_helper_fmt_unix_time(dest, time);
		break;
	case EVENT_EXPORTER_TIME_FMT_RFC3339:
		str_append_c(dest, '"');
		event_export_helper_fmt_rfc3339_time(dest, time);
		str_append_c(dest, '"');
		break;
	}
}

static void append_field_value(string_t *dest, const struct event_field *field,
			       const struct metric_export_info *info)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		append_str_max_len(dest, field->value.str, info);
		break;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		append_int(dest, field->value.intmax);
		break;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		append_time(dest, &field->value.timeval,
			    info->exporter->time_format);
		break;
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		append_strlist(dest, &field->value.strlist, info);
		break;
	}
}

static void json_export_name(string_t *dest, struct event *event,
			     const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_NAME) == 0)
		return;

	append_str(dest, "event");
	str_append_c(dest, ':');
	append_str(dest, event->sending_name);
	str_append_c(dest, ',');
}

static void json_export_hostname(string_t *dest,
				 const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_HOSTNAME) == 0)
		return;

	append_str(dest, "hostname");
	str_append_c(dest, ':');
	append_str(dest, my_hostname);
	str_append_c(dest, ',');
}

static void json_export_timestamps(string_t *dest, struct event *event,
				   const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_TIMESTAMPS) == 0)
		return;

	append_str(dest, "start_time");
	str_append_c(dest, ':');
	append_time(dest, &event->tv_created, info->exporter->time_format);
	str_append_c(dest, ',');

	append_str(dest, "end_time");
	str_append_c(dest, ':');
	append_time(dest, &ioloop_timeval, info->exporter->time_format);
	str_append_c(dest, ',');
}

static void json_export_categories(string_t *dest, struct event *event,
				   const struct metric_export_info *info)
{
	struct event_category *const *cats;
	unsigned int count;

	if ((info->include & EVENT_EXPORTER_INCL_CATEGORIES) == 0)
		return;

	append_str(dest, "categories");
	str_append(dest, ":[");

	cats = event_get_categories(event, &count);
	event_export_helper_fmt_categories(dest, cats, count,
					   append_str, ",");

	str_append(dest, "],");
}

static void json_export_fields(string_t *dest, struct event *event,
			       const struct metric_export_info *info,
			       const unsigned int fields_count,
			       const struct metric_field *fields)
{
	bool appended = FALSE;

	if ((info->include & EVENT_EXPORTER_INCL_FIELDS) == 0)
		return;

	append_str(dest, "fields");
	str_append(dest, ":{");

	if (fields_count == 0) {
		/* include all fields */
		const struct event_field *fields;
		unsigned int count;

		fields = event_get_fields(event, &count);

		for (unsigned int i = 0; i < count; i++) {
			const struct event_field *field = &fields[i];

			append_str(dest, field->key);
			str_append_c(dest, ':');
			append_field_value(dest, field, info);
			str_append_c(dest, ',');

			appended = TRUE;
		}
	} else {
		for (unsigned int i = 0; i < fields_count; i++) {
			const char *name = fields[i].field_key;
			const struct event_field *field;

			field = event_find_field_recursive(event, name);
			if (field == NULL)
				continue; /* doesn't exist, skip it */

			append_str(dest, name);
			str_append_c(dest, ':');
			append_field_value(dest, field, info);
			str_append_c(dest, ',');

			appended = TRUE;
		}
	}

	/* remove trailing comma */
	if (appended)
		str_truncate(dest, str_len(dest) - 1);

	str_append(dest, "},");
}

/*
 * Serialize the event as:
 *
 * {
 *	"name": <event name>,
 *	"hostname": <hostname>,
 *	"start_time": <event creation timestamp>,
 *	"end_time": <event export timestamp>,
 *	"categories": [ <categories>, ... ],
 *	"fields": {
 *		<name>: <value>,
 *		...
 *	}
 * }
 *
 */
void event_export_fmt_json(const struct metric *metric,
			   struct event *event, buffer_t *dest)
{
	const struct metric_export_info *info = &metric->export_info;

	if (info->include == EVENT_EXPORTER_INCL_NONE) {
		str_append(dest, "{}");
		return;
	}

	str_append_c(dest, '{');

	json_export_name(dest, event, info);
	json_export_hostname(dest, info);
	json_export_timestamps(dest, event, info);
	json_export_categories(dest, event, info);
	json_export_fields(dest, event, info, metric->fields_count,
			   metric->fields);

	/* remove trailing comma */
	str_truncate(dest, str_len(dest) - 1);

	str_append_c(dest, '}');
}
