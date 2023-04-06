/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "stats-dist.h"
#include "time-util.h"
#include "event-filter.h"
#include "event-exporter.h"
#include "stats-settings.h"
#include "stats-metrics.h"
#include "settings-parser.h"

#include <ctype.h>

#define LOG_EXPORTER_LONG_FIELD_TRUNCATE_LEN 1000

struct stats_metrics {
	pool_t pool;
	struct event_filter *filter; /* stats & export */
	ARRAY(struct exporter *) exporters;
	ARRAY(struct metric *) metrics;
};

static void
stats_metric_event(struct metric *metric, struct event *event, pool_t pool);
static struct metric *
stats_metric_sub_metric_alloc(struct metric *metric, const char *name, pool_t pool);
static void stats_metric_free(struct metric *metric);

static void stats_exporters_add_set(struct stats_metrics *metrics,
				    const struct stats_exporter_settings *set)
{
	struct exporter *exporter;

	exporter = p_new(metrics->pool, struct exporter, 1);
	exporter->name = p_strdup(metrics->pool, set->name);
	exporter->transport_args = p_strdup(metrics->pool, set->transport_args);
	exporter->transport_timeout = set->transport_timeout;
	exporter->time_format = set->parsed_time_format;

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporter_settings_check().
	 */
	if (strcmp(set->format, "none") == 0) {
		exporter->format = event_export_fmt_none;
		exporter->format_mime_type = "application/octet-stream";
	} else if (strcmp(set->format, "json") == 0) {
		exporter->format = event_export_fmt_json;
		exporter->format_mime_type = "application/json";
	} else if (strcmp(set->format, "tab-text") == 0) {
		exporter->format = event_export_fmt_tabescaped_text;
		exporter->format_mime_type = "text/plain";
	} else {
		i_unreached();
	}

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporter_settings_check().
	 */
	if (strcmp(set->transport, "drop") == 0) {
		exporter->transport = event_export_transport_drop;
	} else if (strcmp(set->transport, "http-post") == 0) {
		exporter->transport = event_export_transport_http_post;
	} else if (strcmp(set->transport, "log") == 0) {
		exporter->transport = event_export_transport_log;
		exporter->format_max_field_len =
			LOG_EXPORTER_LONG_FIELD_TRUNCATE_LEN;
	} else {
		i_unreached();
	}

	exporter->transport_args = set->transport_args;

	array_push_back(&metrics->exporters, &exporter);
}

static struct metric *
stats_metric_alloc(pool_t pool, const char *name,
		   const struct stats_metric_settings *set,
		   const char *const *fields)
{
	struct metric *metric = p_new(pool, struct metric, 1);
	metric->name = p_strdup(pool, name);
	metric->set = set;
	metric->duration_stats = stats_dist_init();
	metric->fields_count = str_array_length(fields);
	if (metric->fields_count > 0) {
		metric->fields = p_new(pool, struct metric_field,
				       metric->fields_count);
		for (unsigned int i = 0; i < metric->fields_count; i++) {
			metric->fields[i].field_key = p_strdup(pool, fields[i]);
			metric->fields[i].stats = stats_dist_init();
		}
	}
	return metric;
}

static void stats_metrics_add_set(struct stats_metrics *metrics,
				  const struct stats_metric_settings *set)
{
	struct exporter *exporter;
	struct metric *metric;
	const char *const *fields;
	const char *const *tmp;

	fields = t_strsplit_spaces(set->fields, " ");
	metric = stats_metric_alloc(metrics->pool, set->metric_name, set, fields);

	if (array_is_created(&set->parsed_group_by))
		metric->group_by = array_get(&set->parsed_group_by,
					     &metric->group_by_count);

	array_push_back(&metrics->metrics, &metric);

	event_filter_merge_with_context(metrics->filter, set->parsed_filter, metric);

	/*
	 * Metrics may also be exported - make sure exporter info is set
	 */

	if (set->exporter[0] == '\0')
		return; /* not exported */

	array_foreach_elem(&metrics->exporters, exporter) {
		if (strcmp(set->exporter, exporter->name) == 0) {
			metric->export_info.exporter = exporter;
			break;
		}
	}

	if (metric->export_info.exporter == NULL)
		i_panic("Could not find exporter (%s) for metric (%s)",
			set->exporter, set->metric_name);

	/* Defaults */
	metric->export_info.include = EVENT_EXPORTER_INCL_NONE;

	tmp = t_strsplit_spaces(set->exporter_include, " ");
	for (; *tmp != NULL; tmp++) {
		if (strcmp(*tmp, "name") == 0)
			metric->export_info.include |= EVENT_EXPORTER_INCL_NAME;
		else if (strcmp(*tmp, "hostname") == 0)
			metric->export_info.include |= EVENT_EXPORTER_INCL_HOSTNAME;
		else if (strcmp(*tmp, "timestamps") == 0)
			metric->export_info.include |= EVENT_EXPORTER_INCL_TIMESTAMPS;
		else if (strcmp(*tmp, "categories") == 0)
			metric->export_info.include |= EVENT_EXPORTER_INCL_CATEGORIES;
		else if (strcmp(*tmp, "fields") == 0)
			metric->export_info.include |= EVENT_EXPORTER_INCL_FIELDS;
		else
			i_warning("Ignoring unknown exporter include '%s'", *tmp);
	}
}

static struct stats_metric_settings *
stats_metric_settings_dup(pool_t pool, const struct stats_metric_settings *src)
{
	struct stats_metric_settings *set = p_new(pool, struct stats_metric_settings, 1);

	set->metric_name = p_strdup(pool, src->metric_name);
	set->description = p_strdup(pool, src->description);
	set->fields = p_strdup(pool, src->fields);
	set->group_by = p_strdup(pool, src->group_by);
	set->filter = p_strdup(pool, src->filter);
	set->exporter = p_strdup(pool, src->exporter);
	set->exporter_include = p_strdup(pool, src->exporter_include);

	return set;
}

static struct metric *
stats_metrics_find(struct stats_metrics *metrics,
		   const char *name, unsigned int *idx_r)
{
	struct metric *const *m;
	array_foreach(&metrics->metrics, m) {
		if (strcmp((*m)->name, name) == 0) {
			*idx_r = array_foreach_idx(&metrics->metrics, m);
			return *m;
		}
	}
	return NULL;
}

static bool
stats_metrics_check_for_exporter(struct stats_metrics *metrics, const char *name)
{
	struct exporter *exporter;

	if (!array_is_created(&metrics->exporters))
		return FALSE;

	bool is_found = FALSE;
	array_foreach_elem(&metrics->exporters, exporter) {
		if (strcmp(exporter->name, name) == 0) {
			is_found = TRUE;
			break;
		}
	}

	return is_found;
}

bool stats_metrics_add_dynamic(struct stats_metrics *metrics,
			       struct stats_metric_settings *set,
			       const char **error_r)
{
	unsigned int existing_idx ATTR_UNUSED;
	if (stats_metrics_find(metrics, set->metric_name, &existing_idx) != NULL) {
		*error_r = "Metric already exists";
		return FALSE;
	}

	struct stats_metric_settings *_set =
		stats_metric_settings_dup(metrics->pool, set);
	if (!stats_metric_setting_parser_info.check_func(_set, metrics->pool, error_r))
		return FALSE;

	if (!stats_metrics_check_for_exporter(metrics, set->exporter)) {
		*error_r = t_strdup_printf("Exporter '%s' does not exist.",
					   set->exporter);
		return FALSE;
	}

	stats_metrics_add_set(metrics, _set);
	return TRUE;
}

bool stats_metrics_remove_dynamic(struct stats_metrics *metrics,
				  const char *name)
{
	unsigned int m_idx;
	bool ret = FALSE;
	struct metric *m = stats_metrics_find(metrics, name, &m_idx);
	if (m != NULL) {
		array_delete(&metrics->metrics, m_idx, 1);
		ret = event_filter_remove_queries_with_context(metrics->filter, m);
		stats_metric_free(m);
	}
	return ret;
}

static void
stats_metrics_add_from_settings(struct stats_metrics *metrics,
				const struct stats_settings *set)
{
	/* add all the exporters first */
	if (!array_is_created(&set->exporters)) {
		p_array_init(&metrics->exporters, metrics->pool, 0);
	} else {
		struct stats_exporter_settings *exporter_set;

		p_array_init(&metrics->exporters, metrics->pool,
			     array_count(&set->exporters));
		array_foreach_elem(&set->exporters, exporter_set)
			stats_exporters_add_set(metrics, exporter_set);
	}

	/* then add all the metrics */
	if (!array_is_created(&set->metrics)) {
		p_array_init(&metrics->metrics, metrics->pool, 0);
	} else {
		struct stats_metric_settings *metric_set;

		p_array_init(&metrics->metrics, metrics->pool,
			     array_count(&set->metrics));
		array_foreach_elem(&set->metrics, metric_set) T_BEGIN {
			stats_metrics_add_set(metrics, metric_set);
		} T_END;
	}
}

struct stats_metrics *stats_metrics_init(const struct stats_settings *set)
{
	struct stats_metrics *metrics;
	pool_t pool = pool_alloconly_create("stats metrics", 1024);

	metrics = p_new(pool, struct stats_metrics, 1);
	metrics->pool = pool;
	metrics->filter = event_filter_create();
	stats_metrics_add_from_settings(metrics, set);
	return metrics;
}

static void stats_metric_free(struct metric *metric)
{
	struct metric *sub_metric;
	stats_dist_deinit(&metric->duration_stats);
	for (unsigned int i = 0; i < metric->fields_count; i++)
		stats_dist_deinit(&metric->fields[i].stats);
	if (!array_is_created(&metric->sub_metrics))
		return;
	array_foreach_elem(&metric->sub_metrics, sub_metric)
		stats_metric_free(sub_metric);
}

static void stats_export_deinit(void)
{
	/* no need for event_export_transport_drop_deinit() - no-op */
	event_export_transport_http_post_deinit();
	/* no need for event_export_transport_log_deinit() - no-op */
}

void stats_metrics_deinit(struct stats_metrics **_metrics)
{
	struct stats_metrics *metrics = *_metrics;
	struct metric *metric;

	*_metrics = NULL;

	stats_export_deinit();

	array_foreach_elem(&metrics->metrics, metric)
		stats_metric_free(metric);
	event_filter_unref(&metrics->filter);
	pool_unref(&metrics->pool);
}

static void stats_metric_reset(struct metric *metric)
{
	struct metric *sub_metric;
	stats_dist_reset(metric->duration_stats);
	for (unsigned int i = 0; i < metric->fields_count; i++)
		stats_dist_reset(metric->fields[i].stats);
	if (!array_is_created(&metric->sub_metrics))
		return;
	array_foreach_elem(&metric->sub_metrics, sub_metric)
		stats_metric_reset(sub_metric);
}

void stats_metrics_reset(struct stats_metrics *metrics)
{
	struct metric *metric;

	array_foreach_elem(&metrics->metrics, metric)
		stats_metric_reset(metric);
}

struct event_filter *
stats_metrics_get_event_filter(struct stats_metrics *metrics)
{
	return metrics->filter;
}

static struct metric *
stats_metric_find_sub_metric(struct metric *metric,
			     const struct metric_value *value)
{
	struct metric *sub_metrics;

	/* lookup sub-metric */
	array_foreach_elem(&metric->sub_metrics, sub_metrics) {
		switch (sub_metrics->group_value.type) {
		case METRIC_VALUE_TYPE_STR:
			if (memcmp(sub_metrics->group_value.hash, value->hash,
				   SHA1_RESULTLEN) == 0)
				return sub_metrics;
			break;
		case METRIC_VALUE_TYPE_INT:
			if (sub_metrics->group_value.intmax == value->intmax)
				return sub_metrics;
			break;
		case METRIC_VALUE_TYPE_IP:
			if (net_ip_compare(&sub_metrics->group_value.ip,
					   &value->ip))
				return sub_metrics;
			break;
		case METRIC_VALUE_TYPE_BUCKET_INDEX:
			if (sub_metrics->group_value.intmax == value->intmax)
				return sub_metrics;
			break;
		}
	}
	return NULL;
}

static struct metric *
stats_metric_sub_metric_alloc(struct metric *metric, const char *name, pool_t pool)
{
	struct metric *sub_metric;
	ARRAY_TYPE(const_string) fields;
	t_array_init(&fields, metric->fields_count);
	for (unsigned int i = 0; i < metric->fields_count; i++)
		array_append(&fields, &metric->fields[i].field_key, 1);
	array_append_zero(&fields);
	sub_metric = stats_metric_alloc(pool, metric->name, metric->set,
					array_idx(&fields, 0));
	sub_metric->sub_name = p_strdup(pool, str_sanitize_utf8(name, 32));
	array_append(&metric->sub_metrics, &sub_metric, 1);
	return sub_metric;
}

static bool
stats_metric_group_by_discrete(const struct event_field *field,
			       struct metric_value *value_r)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		value_r->type = METRIC_VALUE_TYPE_STR;
		/* use sha1 of value to avoid excessive memory usage in case the
		   actual value is quite long */
		sha1_get_digest(field->value.str, strlen(field->value.str),
				value_r->hash);
		return TRUE;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		value_r->type = METRIC_VALUE_TYPE_INT;
		value_r->intmax = field->value.intmax;
		return TRUE;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		return FALSE;
	case EVENT_FIELD_VALUE_TYPE_IP:
		value_r->type = METRIC_VALUE_TYPE_IP;
		value_r->ip = field->value.ip;
		return TRUE;
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		return FALSE;
	}

	i_unreached();
}

/* convert the value to a bucket index */
static bool
stats_metric_group_by_quantized(const struct event_field *field,
				struct metric_value *value_r,
				const struct stats_metric_settings_group_by *group_by)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
	case EVENT_FIELD_VALUE_TYPE_IP:
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		return FALSE;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		break;
	}

	value_r->type = METRIC_VALUE_TYPE_BUCKET_INDEX;

	for (unsigned int i = 0; i < group_by->num_ranges; i++) {
		if ((field->value.intmax <= group_by->ranges[i].min) ||
		    (field->value.intmax > group_by->ranges[i].max))
			continue;

		value_r->intmax = i;
		return TRUE;
	}

	i_panic("failed to find a matching bucket for '%s'=%jd",
		group_by->field, field->value.intmax);
}

/* convert value to a bucket label */
static const char *
stats_metric_group_by_quantized_label(const struct event_field *field,
				      const struct stats_metric_settings_group_by *group_by,
				      const size_t bucket_index)
{
	const struct stats_metric_settings_bucket_range *range = &group_by->ranges[bucket_index];
	const char *name = group_by->field;
	const char *label;

	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
	case EVENT_FIELD_VALUE_TYPE_IP:
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		i_unreached();
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		break;
	}

	if (range->min == INTMAX_MIN)
		label = t_strdup_printf("%s_ninf_%jd", name, range->max);
	else if (range->max == INTMAX_MAX)
		label = t_strdup_printf("%s_%jd_inf", name, range->min + 1);
	else
		label = t_strdup_printf("%s_%jd_%jd", name,
					range->min + 1, range->max);

	return label;
}

static bool
stats_metric_group_by_get_value(const struct event_field *field,
				const struct stats_metric_settings_group_by *group_by,
				struct metric_value *value_r)
{
	switch (group_by->func) {
	case STATS_METRIC_GROUPBY_DISCRETE:
		if (!stats_metric_group_by_discrete(field, value_r))
			return FALSE;
		return TRUE;
	case STATS_METRIC_GROUPBY_QUANTIZED:
		if (!stats_metric_group_by_quantized(field, value_r, group_by))
			return FALSE;
		return TRUE;
	}

	i_panic("unknown group-by function %d", group_by->func);
}

static const char *
stats_metric_group_by_get_label(const struct event_field *field,
				const struct stats_metric_settings_group_by *group_by,
				const struct metric_value *value)
{
	switch (group_by->func) {
	case STATS_METRIC_GROUPBY_DISCRETE:
		i_unreached();
	case STATS_METRIC_GROUPBY_QUANTIZED:
		return stats_metric_group_by_quantized_label(field, group_by,
							     value->intmax);
	}

	i_panic("unknown group-by function %d", group_by->func);
}

/* Handle string modifiers */
static inline const char *
label_by_mod_str(const struct stats_metric_settings_group_by *group_by,
		 const char *value)
{
	if ((group_by->mod & STATS_METRICS_GROUPBY_DOMAIN) != 0) {
		const char *domain = strrchr(value, '@');
		if (domain != NULL)
			value = domain+1;
		else
			value = "";
	}
	if ((group_by->mod & STATS_METRICS_GROUPBY_UPPERCASE) != 0)
		value = t_str_ucase(value);
	if ((group_by->mod & STATS_METRICS_GROUPBY_LOWERCASE) != 0)
		value = t_str_lcase(value);
	return value;
}

static const char *
stats_metric_group_by_value_label(const struct event_field *field,
				  const struct stats_metric_settings_group_by *group_by,
				  const struct metric_value *value)
{
	switch (value->type) {
	case METRIC_VALUE_TYPE_STR:
		return label_by_mod_str(group_by, field->value.str);
	case METRIC_VALUE_TYPE_INT:
		return dec2str(field->value.intmax);
	case METRIC_VALUE_TYPE_IP:
		return net_ip2addr(&field->value.ip);
	case METRIC_VALUE_TYPE_BUCKET_INDEX:
		return stats_metric_group_by_get_label(field, group_by, value);
	}
	i_unreached();
}

static struct metric *
stats_metric_get_sub_metric(struct metric *metric,
			    const struct event_field *field,
			    const struct metric_value *value,
			    pool_t pool)
{
	struct metric *sub_metric;

	sub_metric = stats_metric_find_sub_metric(metric, value);
	if (sub_metric != NULL)
		return sub_metric;

	T_BEGIN {
		const char *value_label =
			stats_metric_group_by_value_label(field,
				&metric->group_by[0], value);
		sub_metric = stats_metric_sub_metric_alloc(metric, value_label,
							   pool);
	} T_END;
	if (metric->group_by_count > 1) {
		sub_metric->group_by_count = metric->group_by_count - 1;
		sub_metric->group_by = &metric->group_by[1];
	}
	sub_metric->group_value.type = value->type;
	sub_metric->group_value.intmax = value->intmax;
	sub_metric->group_value.ip = value->ip;
	memcpy(sub_metric->group_value.hash, value->hash, SHA1_RESULTLEN);
	return sub_metric;
}

static void
stats_metric_group_by_field(struct metric *metric, struct event *event,
			    const struct event_field *field, pool_t pool)
{
	struct metric *sub_metric;
	struct metric_value value;

	if (!stats_metric_group_by_get_value(field, &metric->group_by[0], &value))
		return;

	if (!array_is_created(&metric->sub_metrics))
		p_array_init(&metric->sub_metrics, pool, 8);
	sub_metric = stats_metric_get_sub_metric(metric, field, &value, pool);

	/* sub-metrics are recursive, so each sub-metric can have additional
	   sub-metrics. */
	stats_metric_event(sub_metric, event, pool);
}

static void
stats_event_get_strlist(struct event *event, const char *name,
			ARRAY_TYPE(const_string) *strings)
{
	if (event == NULL)
		return;

	const struct event_field *field =
		event_find_field_nonrecursive(event, name);
	if (field != NULL) {
		const char *str;
		array_foreach_elem(&field->value.strlist, str)
			array_push_back(strings, &str);
	}
	stats_event_get_strlist(event_get_parent(event), name, strings);
}

static void
stats_metric_group_by(struct metric *metric, struct event *event, pool_t pool)
{
	const struct event_field *field =
		event_find_field_recursive(event, metric->group_by[0].field);

	/* ignore missing field */
	if (field == NULL)
		return;

	if (field->value_type != EVENT_FIELD_VALUE_TYPE_STRLIST)
		stats_metric_group_by_field(metric, event, field, pool);
	else {
		/* Handle each string in strlist separately. The strlist needs
		   to be combined from the event and its parents, as well as
		   the global event and its parents. */
		ARRAY_TYPE(const_string) strings;

		t_array_init(&strings, 8);
		stats_event_get_strlist(event, metric->group_by[0].field,
					&strings);
		stats_event_get_strlist(event_get_global(),
					metric->group_by[0].field, &strings);

		struct event_field str_field = {
			.value_type = EVENT_FIELD_VALUE_TYPE_STR,
		};
		const char *str;

		/* sort strings so duplicates can be easily skipped */
		array_sort(&strings, i_strcmp_p);
		array_foreach_elem(&strings, str) {
			if (str_field.value.str == NULL ||
			    strcmp(str_field.value.str, str) != 0) {
				str_field.value.str = str;
				stats_metric_group_by_field(metric, event,
							    &str_field, pool);
			}
		}
	}
}

static void
stats_metric_event_field(struct event *event, const char *fieldname,
			 struct stats_dist *stats)
{
	const struct event_field *field =
		event_find_field_recursive(event, fieldname);
	intmax_t num = 0;

	if (field == NULL)
		return;

	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
	case EVENT_FIELD_VALUE_TYPE_IP:
		break;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		num = field->value.intmax;
		break;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		num = field->value.timeval.tv_sec * 1000000ULL +
			field->value.timeval.tv_usec;
		break;
	}

	stats_dist_add(stats, num);
}

static void
stats_metric_event(struct metric *metric, struct event *event, pool_t pool)
{
	/* duration is special - we always add it */
	stats_metric_event_field(event, STATS_EVENT_FIELD_NAME_DURATION,
				 metric->duration_stats);

	for (unsigned int i = 0; i < metric->fields_count; i++)
		stats_metric_event_field(event,
					 metric->fields[i].field_key,
					 metric->fields[i].stats);

	if (metric->group_by != NULL)
		stats_metric_group_by(metric, event, pool);
}

static void
stats_export_event(struct metric *metric, struct event *oldevent)
{
	const struct metric_export_info *info = &metric->export_info;
	const struct exporter *exporter = info->exporter;
	struct event *event;

	i_assert(exporter != NULL);

	event = event_flatten(oldevent);

	T_BEGIN {
		buffer_t *buf;

		buf = t_buffer_create(128);

		exporter->format(metric, event, buf);
		exporter->transport(exporter, buf);
	} T_END;

	event_unref(&event);
}

void stats_metrics_event(struct stats_metrics *metrics, struct event *event,
			 const struct failure_context *ctx)
{
	struct event_filter_match_iter *iter;
	struct metric *metric;
	uintmax_t duration;

	/* Note: Adding the field here means that it will get exported
	   below.  This is necessary to allow group-by functions to quantize
	   based on the event duration. */
	event_get_last_duration(event, &duration);
	event_add_int(event, STATS_EVENT_FIELD_NAME_DURATION, duration);

	/* process stats & exports */
	iter = event_filter_match_iter_init(metrics->filter, event, ctx);
	while ((metric = event_filter_match_iter_next(iter)) != NULL) T_BEGIN {
		/* every metric is fed into stats */
		stats_metric_event(metric, event, metrics->pool);

		/* some metrics are exported */
		if (metric->export_info.exporter != NULL)
			stats_export_event(metric, event);
	} T_END;
	event_filter_match_iter_deinit(&iter);
}

struct stats_metrics_iter {
	struct stats_metrics *metrics;
	unsigned int idx;
};

struct stats_metrics_iter *
stats_metrics_iterate_init(struct stats_metrics *metrics)
{
	struct stats_metrics_iter *iter;

	iter = i_new(struct stats_metrics_iter, 1);
	iter->metrics = metrics;
	return iter;
}

const struct metric *stats_metrics_iterate(struct stats_metrics_iter *iter)
{
	struct metric *const *metrics;
	unsigned int count;

	metrics = array_get(&iter->metrics->metrics, &count);
	if (iter->idx >= count)
		return NULL;
	return metrics[iter->idx++];
}

void stats_metrics_iterate_deinit(struct stats_metrics_iter **_iter)
{
	struct stats_metrics_iter *iter = *_iter;

	*_iter = NULL;
	i_free(iter);
}
