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

#include <ctype.h>

struct stats_metrics {
	pool_t pool;
	struct event_filter *stats_filter; /* stats-only */
	struct event_filter *export_filter; /* export-only */
	struct event_filter *combined_filter; /* stats & export */
	ARRAY(struct exporter *) exporters;
	ARRAY(struct metric *) metrics;
};

static void
stats_metric_event(struct metric *metric, struct event *event, pool_t pool);
static struct metric *
stats_metric_sub_metric_alloc(struct metric *metric, const char *name, pool_t pool);

static void
stats_metric_settings_to_query(const struct stats_metric_settings *set,
			       struct event_filter_query *query_r)
{
	i_zero(query_r);

	/* generate fields for event filter */
	if (array_is_created(&set->filter)) {
		struct event_filter_field *filter_fields;
		const char *const *filters;
		unsigned int i, count;

		filters = array_get(&set->filter, &count);
		i_assert(count % 2 == 0);
		count /= 2;

		filter_fields = t_new(struct event_filter_field, count + 1);
		for (i = 0; i < count; i++) {
			filter_fields[i].key = filters[i*2];
			filter_fields[i].value = filters[i*2+1];
		}
		query_r->fields = filter_fields;
	}

	/* add query to the event filter */
	query_r->categories = t_strsplit_spaces(set->categories, " ");
	query_r->name = set->event_name;
	query_r->source_filename = t_strcut(set->source_location, ':');
	query_r->source_linenum = set->parsed_source_linenum;
}

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
	struct event_filter_query query;
	struct exporter *const *exporter;
	struct metric *metric;
	const char *const *fields;
	const char *const *tmp;

	fields = t_strsplit_spaces(set->fields, " ");
	metric = stats_metric_alloc(metrics->pool, set->metric_name, set, fields);

	if (array_is_created(&set->parsed_group_by))
		metric->group_by = array_get(&set->parsed_group_by,
					     &metric->group_by_count);

	array_push_back(&metrics->metrics, &metric);

	stats_metric_settings_to_query(set, &query);
	query.context = metric;
	event_filter_add(metrics->stats_filter, &query);
	event_filter_add(metrics->combined_filter, &query);

	/*
	 * Done with statistics setup, now onto exporter setup
	 */

	if (set->exporter[0] == '\0')
		return; /* not exported */

	array_foreach(&metrics->exporters, exporter) {
		if (strcmp(set->exporter, (*exporter)->name) == 0) {
			metric->export_info.exporter = *exporter;
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

	/* query already constructed */
	event_filter_add(metrics->export_filter, &query);
}

static void
stats_metrics_add_from_settings(struct stats_metrics *metrics,
				const struct stats_settings *set)
{
	/* add all the exporters first */
	if (!array_is_created(&set->exporters)) {
		p_array_init(&metrics->exporters, metrics->pool, 0);
	} else {
		struct stats_exporter_settings *const *exporter_setp;

		p_array_init(&metrics->exporters, metrics->pool,
			     array_count(&set->exporters));
		array_foreach(&set->exporters, exporter_setp)
			stats_exporters_add_set(metrics, *exporter_setp);
	}

	/* then add all the metrics */
	if (!array_is_created(&set->metrics)) {
		p_array_init(&metrics->metrics, metrics->pool, 0);
	} else {
		struct stats_metric_settings *const *metric_setp;

		p_array_init(&metrics->metrics, metrics->pool,
			     array_count(&set->metrics));
		array_foreach(&set->metrics, metric_setp) T_BEGIN {
			stats_metrics_add_set(metrics, *metric_setp);
		} T_END;
	}
}

struct stats_metrics *stats_metrics_init(const struct stats_settings *set)
{
	struct stats_metrics *metrics;
	pool_t pool = pool_alloconly_create("stats metrics", 1024);

	metrics = p_new(pool, struct stats_metrics, 1);
	metrics->pool = pool;
	metrics->stats_filter = event_filter_create();
	metrics->export_filter = event_filter_create();
	metrics->combined_filter = event_filter_create();
	stats_metrics_add_from_settings(metrics, set);
	return metrics;
}

static void stats_metric_free(struct metric *metric)
{
	struct metric *const *metricp;
	stats_dist_deinit(&metric->duration_stats);
	for (unsigned int i = 0; i < metric->fields_count; i++)
		stats_dist_deinit(&metric->fields[i].stats);
	if (!array_is_created(&metric->sub_metrics))
		return;
	array_foreach(&metric->sub_metrics, metricp)
		stats_metric_free(*metricp);
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
	struct metric *const *metricp;

	*_metrics = NULL;

	stats_export_deinit();

	array_foreach(&metrics->metrics, metricp)
		stats_metric_free(*metricp);
	event_filter_unref(&metrics->stats_filter);
	event_filter_unref(&metrics->export_filter);
	event_filter_unref(&metrics->combined_filter);
	pool_unref(&metrics->pool);
}

static void stats_metric_reset(struct metric *metric)
{
	struct metric *const *metricp;
	stats_dist_reset(metric->duration_stats);
	for (unsigned int i = 0; i < metric->fields_count; i++)
		stats_dist_reset(metric->fields[i].stats);
	if (!array_is_created(&metric->sub_metrics))
		return;
	array_foreach(&metric->sub_metrics, metricp)
		stats_metric_reset(*metricp);
}

void stats_metrics_reset(struct stats_metrics *metrics)
{
	struct metric *const *metricp;

	array_foreach(&metrics->metrics, metricp)
		stats_metric_reset(*metricp);
}

struct event_filter *
stats_metrics_get_event_filter(struct stats_metrics *metrics)
{
	return metrics->combined_filter;
}

static struct metric *
stats_metric_get_sub_metric(struct metric *metric,
			    const struct metric_value *value)
{
	struct metric *const *sub_metrics;

	/* lookup sub-metric */
	array_foreach (&metric->sub_metrics, sub_metrics) {
		switch ((*sub_metrics)->group_value.type) {
		case METRIC_VALUE_TYPE_STR:
			if (memcmp((*sub_metrics)->group_value.hash, value->hash,
				   SHA1_RESULTLEN) == 0)
				return *sub_metrics;
			break;
		case METRIC_VALUE_TYPE_INT:
			if ((*sub_metrics)->group_value.intmax == value->intmax)
				return *sub_metrics;
			break;
		case METRIC_VALUE_TYPE_BUCKET_INDEX:
			if ((*sub_metrics)->group_value.intmax == value->intmax)
				return *sub_metrics;
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
			       struct metric_value *value)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		value->type = METRIC_VALUE_TYPE_STR;
		/* use sha1 of value to avoid excessive memory usage in case the
		   actual value is quite long */
		sha1_get_digest(field->value.str, strlen(field->value.str),
				value->hash);
		return TRUE;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		value->type = METRIC_VALUE_TYPE_INT;
		value->intmax = field->value.intmax;
		return TRUE;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		return FALSE;
	}

	i_unreached();
}

/* convert the value to a bucket index */
static bool
stats_metric_group_by_quantized(const struct event_field *field,
				struct metric_value *value,
				const struct stats_metric_settings_group_by *group_by)
{
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		return FALSE;
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		break;
	}

	value->type = METRIC_VALUE_TYPE_BUCKET_INDEX;

	for (unsigned int i = 0; i < group_by->num_ranges; i++) {
		if ((field->value.intmax <= group_by->ranges[i].min) ||
		    (field->value.intmax > group_by->ranges[i].max))
			continue;

		value->intmax = i;
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
				struct metric_value *value)
{
	switch (group_by->func) {
	case STATS_METRIC_GROUPBY_DISCRETE:
		if (!stats_metric_group_by_discrete(field, value))
			return FALSE;
		return TRUE;
	case STATS_METRIC_GROUPBY_QUANTIZED:
		if (!stats_metric_group_by_quantized(field, value, group_by))
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

static void
stats_metric_group_by(struct metric *metric, struct event *event, pool_t pool)
{
	const struct stats_metric_settings_group_by *group_by = &metric->group_by[0];
	const struct event_field *field = event_find_field(event, group_by->field);
	struct metric *sub_metric;
	struct metric_value value;

	/* ignore missing field */
	if (field == NULL)
		return;

	if (!stats_metric_group_by_get_value(field, group_by, &value))
		return;

	if (!array_is_created(&metric->sub_metrics))
		p_array_init(&metric->sub_metrics, pool, 8);

	sub_metric = stats_metric_get_sub_metric(metric, &value);

	if (sub_metric == NULL) T_BEGIN {
		const char *value_label = NULL;

		switch (value.type) {
		case METRIC_VALUE_TYPE_STR:
			value_label = field->value.str;
			break;
		case METRIC_VALUE_TYPE_INT:
			value_label = dec2str(field->value.intmax);
			break;
		case METRIC_VALUE_TYPE_BUCKET_INDEX:
			value_label = stats_metric_group_by_get_label(field,
								      group_by,
								      &value);
			break;
		}

		sub_metric = stats_metric_sub_metric_alloc(metric, value_label,
							   pool);
		if (metric->group_by_count > 1) {
			sub_metric->group_by_count = metric->group_by_count - 1;
			sub_metric->group_by = &metric->group_by[1];
		}
		sub_metric->group_value.type = value.type;
		sub_metric->group_value.intmax = value.intmax;
		memcpy(sub_metric->group_value.hash, value.hash, SHA1_RESULTLEN);
	} T_END;

	/* sub-metrics are recursive, so each sub-metric can have additional
	   sub-metrics. */
	stats_metric_event(sub_metric, event, pool);
}

static void
stats_metric_event_field(struct event *event, const char *fieldname,
			 struct stats_dist *stats)
{
	const struct event_field *field = event_find_field(event, fieldname);
	intmax_t num = 0;

	if (field == NULL)
		return;

	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
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
	stats_metric_event_field(event, "duration",
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
	intmax_t duration;

	/* Note: Adding the field here means that it will get exported
	   below.  This is necessary to allow group-by functions to quantize
	   based on the event duration. */
	event_get_last_duration(event, &duration);
	event_add_int(event, "duration", duration);

	/* process stats */
	iter = event_filter_match_iter_init(metrics->stats_filter, event, ctx);
	while ((metric = event_filter_match_iter_next(iter)) != NULL) T_BEGIN {
		stats_metric_event(metric, event, metrics->pool);
	} T_END;
	event_filter_match_iter_deinit(&iter);

	/* process exports */
	iter = event_filter_match_iter_init(metrics->export_filter, event, ctx);
	while ((metric = event_filter_match_iter_next(iter)) != NULL) T_BEGIN {
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
