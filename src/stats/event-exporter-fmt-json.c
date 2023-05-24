/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "ioloop.h"
#include "array.h"
#include "lib-event-private.h"
#include "event-exporter.h"
#include "str.h"
#include "json-ostream.h"
#include "hostpid.h"

static void append_str_max_len(struct json_ostream *joutput, const char *str,
			       const struct metric_export_info *info)
{
	if (info->exporter->format_max_field_len == 0) {
		json_ostream_nwrite_string(joutput, NULL, str);
		return;
	}

	size_t len = strlen(str);

	if (len < info->exporter->format_max_field_len) {
		json_ostream_nwrite_string(joutput, NULL, str);
		return;
	}

	len = uni_utf8_data_truncate((const unsigned char *)str, len,
				     info->exporter->format_max_field_len);
	json_ostream_nopen_string(joutput, NULL);
	json_ostream_nwrite_string_data(joutput, NULL, str, len);
	json_ostream_nwrite_string(joutput, NULL, "...");
	json_ostream_nclose_string(joutput);
}

static void
append_strlist(struct json_ostream *joutput,
	       const ARRAY_TYPE(const_string) *strlist,
	       const struct metric_export_info *info)
{
	const char *value;

	json_ostream_ndescend_array(joutput, NULL);
	array_foreach_elem(strlist, value)
		append_str_max_len(joutput, value, info);
	json_ostream_nascend_array(joutput);
}

static void append_int(struct json_ostream *joutput, intmax_t val)
{
	json_ostream_nwrite_number(joutput, NULL, val);
}

static void
append_time(struct json_ostream *joutput, const struct timeval *time,
	    enum event_exporter_time_fmt fmt)
{
	string_t *time_str = t_str_new(64);

	switch (fmt) {
	case EVENT_EXPORTER_TIME_FMT_NATIVE:
		i_panic("JSON does not have a native date/time type");
	case EVENT_EXPORTER_TIME_FMT_UNIX:
		event_export_helper_fmt_unix_time(time_str, time);
		json_ostream_nwrite_number_raw(joutput, NULL, str_c(time_str));
		break;
	case EVENT_EXPORTER_TIME_FMT_RFC3339:
		event_export_helper_fmt_rfc3339_time(time_str, time);
		json_ostream_nwrite_string_buffer(joutput, NULL, time_str);
		break;
	}
}

static void append_ip(struct json_ostream *joutput, const struct ip_addr *ip)
{
	json_ostream_nwrite_string(joutput, NULL, net_ip2addr(ip));
}

static void
append_field_value(struct json_ostream *joutput,
		   const struct event_field *field,
		   const struct metric_export_info *info)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		append_str_max_len(joutput, field->value.str, info);
		break;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		append_int(joutput, field->value.intmax);
		break;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		append_time(joutput, &field->value.timeval,
			    info->exporter->time_format);
		break;
	case EVENT_FIELD_VALUE_TYPE_IP:
		append_ip(joutput, &field->value.ip);
		break;
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		append_strlist(joutput, &field->value.strlist, info);
		break;
	}
}

static void
json_export_name(struct json_ostream *joutput, struct event *event,
		 const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_NAME) == 0 ||
	    event->sending_name == NULL)
		return;

	json_ostream_nwrite_string(joutput, "event", event->sending_name);
}

static void
json_export_hostname(struct json_ostream *joutput,
		     const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_HOSTNAME) == 0)
		return;

	json_ostream_nwrite_string(joutput, "hostname", my_hostname);
}

static void
json_export_timestamps(struct json_ostream *joutput, struct event *event,
		       const struct metric_export_info *info)
{
	if ((info->include & EVENT_EXPORTER_INCL_TIMESTAMPS) == 0)
		return;

	json_ostream_nwrite_object_member(joutput, "start_time");
	append_time(joutput, &event->tv_created, info->exporter->time_format);

	json_ostream_nwrite_object_member(joutput, "end_time");
	append_time(joutput, &ioloop_timeval, info->exporter->time_format);
}

static void
json_export_categories(struct json_ostream *joutput, struct event *event,
		       const struct metric_export_info *info)
{
	struct event_category_iterator *iter;
	const struct event_category *cat;

	if ((info->include & EVENT_EXPORTER_INCL_CATEGORIES) == 0)
		return;

	json_ostream_ndescend_array(joutput, "categories");

	iter = event_categories_iterate_init(event);
	while (event_categories_iterate(iter, &cat))
		json_ostream_nwrite_string(joutput, NULL, cat->name);
	event_categories_iterate_deinit(&iter);

	json_ostream_nascend_array(joutput);
}

static void
json_export_fields(struct json_ostream *joutput, struct event *event,
		   const struct metric_export_info *info,
		   const unsigned int fields_count,
		   const struct metric_field *fields)
{
	if ((info->include & EVENT_EXPORTER_INCL_FIELDS) == 0)
		return;

	json_ostream_ndescend_object(joutput, "fields");

	if (fields_count == 0) {
		/* include all fields */
		const struct event_field *fields;
		unsigned int count;

		fields = event_get_fields(event, &count);

		for (unsigned int i = 0; i < count; i++) {
			const struct event_field *field = &fields[i];

			json_ostream_nwrite_object_member(joutput, field->key);
			append_field_value(joutput, field, info);
		}
	} else {
		for (unsigned int i = 0; i < fields_count; i++) {
			const char *name = fields[i].field_key;
			const struct event_field *field;

			field = event_find_field_recursive(event, name);
			if (field == NULL)
				continue; /* doesn't exist, skip it */

			json_ostream_nwrite_object_member(joutput, name);
			append_field_value(joutput, field, info);
		}
	}

	json_ostream_nascend_object(joutput);
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

	struct json_ostream *joutput;

	joutput = json_ostream_create_str(dest, 0);
	json_ostream_ndescend_object(joutput, NULL);

	json_export_name(joutput, event, info);
	json_export_hostname(joutput, info);
	json_export_timestamps(joutput, event, info);
	json_export_categories(joutput, event, info);
	json_export_fields(joutput, event, info, metric->fields_count,
			   metric->fields);

	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
}
