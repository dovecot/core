/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "dovecot-version.h"
#include "str.h"
#include "array.h"
#include "ioloop.h"
#include "stats-dist.h"
#include "http-server.h"
#include "client-http.h"
#include "stats-settings.h"
#include "stats-metrics.h"
#include "stats-service-private.h"

#define OPENMETRICS_CONTENT_VERSION "0.0.4"

#ifdef DOVECOT_REVISION
#define OPENMETRICS_BUILD_INFO \
	"version=\""DOVECOT_VERSION"\"," \
	"revision=\""DOVECOT_REVISION"\""
#else
#define OPENMETRICS_BUILD_INFO \
	"version=\""DOVECOT_VERSION"\""
#endif

/* https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels:

   Every time series is uniquely identified by its metric name and optional
   key-value pairs called labels.

   The metric name specifies the general feature of a system that is measured
   (e.g. http_requests_total - the total number of HTTP requests received). It
   may contain ASCII letters and digits, as well as underscores and colons. It
   must match the regex [a-zA-Z_:][a-zA-Z0-9_:]*.
 */

static void
openmetrics_export_submetrics(string_t *out, const struct metric *metric,
			      string_t *labels, bool count, int64_t timestamp);

static bool openmetrics_check_name(const char *name)
{
	const unsigned char *p, *pend;

	p = (const unsigned char *)name;
	pend = p + strlen(name);

	if (p == pend)
		return FALSE;

	if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
	    *p != '_' && *p != ':')
		return FALSE;
	p++;
	while (p < pend) {
		if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
		    !(*p >= '0' && *p <= '9') && *p != '_' && *p != ':')
			return FALSE;
		p++;
	}
	return TRUE;
}

static bool openmetrics_check_metric(const struct metric *metric)
{
	const char *const *filters;
	unsigned int i, count;

	if (!openmetrics_check_name(metric->name))
		return FALSE;

	if (!array_is_created(&metric->set->filter))
		return TRUE;

	filters = array_get(&metric->set->filter, &count);
	if (count == 0)
		return TRUE;
	i_assert(count % 2 == 0);

	count /= 2;
	for (i = 1; i < count; i++) {
		if (!openmetrics_check_name(filters[i * 2]))
			return FALSE;
	}
	return TRUE;
}

/* https://prometheus.io/docs/prometheus/latest/querying/basics/#literals:

   PromQL follows the same escaping rules as Go. In single or double quotes a
   backslash begins an escape sequence, which may be followed by a, b, f, n, r,
   t, v or \. Specific characters can be provided using octal (\nnn) or
   hexadecimal (\xnn, \unnnn and \Unnnnnnnn).

   https://golang.org/ref/spec#String_literals:

   Interpreted string literals are character sequences between double quotes, as
   in "bar". Within the quotes, any character may appear except newline and
   unescaped double quote. The text between the quotes forms the value of the
   literal, with backslash escapes interpreted as they are in rune literals
   (except that \' is illegal and \" is legal), with the same restrictions.

   -> Cannot use strescape.h, since \' is illegal.
 */
static void openmetrics_escape_string(string_t *dest, const char *value)
{
	const unsigned char *pstart, *p, *pend;

	pstart = p = (const unsigned char *)value;
	pend = pstart + strlen(value);

	/* See if we need to quote it */
	for (; p < pend; p++) {
		if (*p == '\n' || *p == '"')
			break;
	}

	/* Quote */
	str_append_data(dest, pstart, (size_t)(p - pstart));

	for (; p < pend; p++) {
		if (*p == '\n' || *p == '"')
			str_append_c(dest, '\\');
		str_append_data(dest, p, 1);
	}
}

static void
openmetrics_export_metric_labels(string_t *out, const struct metric *metric)
{
	const char *const *filters;
	unsigned int i, count;

	if (!array_is_created(&metric->set->filter))
		return;

	filters = array_get(&metric->set->filter, &count);
	if (count == 0)
		return;
	i_assert(count % 2 == 0);

	str_append(out, filters[0]);
	str_append(out, "=\"");
	openmetrics_escape_string(out, filters[1]);
	str_append_c(out, '"');

	count /= 2;
	for (i = 1; i < count; i++) {
		str_append_c(out, ',');
		str_append(out, filters[i * 2]);
		str_append(out, "=\"");
		openmetrics_escape_string(out, filters[i * 2 + 1]);
		str_append_c(out, '"');
	}
}

static void
openmetrics_export_submetric(string_t *out, const struct metric *metric,
			     string_t *labels, bool count, int64_t timestamp)
{
	if (!openmetrics_check_name(metric->sub_name))
		return;
	str_append_c(labels, '"');
	openmetrics_escape_string(labels, metric->sub_name);
	str_append_c(labels, '"');

	str_append(out, "dovecot_");
	str_append(out, metric->name);
	if (count) {
		str_append(out, "_count");
		str_append_c(out, '{');
		str_append_str(out, labels);
		str_append_c(out, '}');
		str_printfa(out, " %u %"PRId64"\n",
			    stats_dist_get_count(metric->duration_stats),
			    timestamp);
	} else {
		str_append(out, "_duration_usecs_sum");
		str_append_c(out, '{');
		str_append_str(out, labels);
		str_append_c(out, '}');
		str_printfa(out, " %"PRIu64" %"PRId64"\n",
			    stats_dist_get_sum(metric->duration_stats),
			    timestamp);
	}
	size_t label_pos = str_len(labels);
	openmetrics_export_submetrics(out, metric, labels, count, timestamp);
	str_truncate(labels, label_pos);
}

static void
openmetrics_export_submetrics(string_t *out, const struct metric *metric,
			      string_t *labels, bool count, int64_t timestamp)
{
	struct metric *const *sub_metric;
	if (!array_is_created(&metric->sub_metrics))
		return;
	if (str_len(labels) > 0)
		str_append_c(labels, ',');
	str_append(labels, metric->group_by->field);
	str_append_c(labels, '=');
	array_foreach(&metric->sub_metrics, sub_metric) {
		size_t label_pos = str_len(labels);
		openmetrics_export_submetric(out, *sub_metric, labels,
					     count, timestamp);
		str_truncate(labels, label_pos);
	}
}

static void
openmetrics_export_metric(string_t *out, const struct metric *metric,
			 int64_t timestamp)
{
	if (!openmetrics_check_metric(metric))
		return;

	string_t *labels = t_str_new(32);
	size_t label_pos;
	openmetrics_export_metric_labels(labels, metric);

	/* Description */
	str_append(out, "# HELP dovecot_");
	str_append(out, metric->name);
	str_append(out, "_count Total number");
	if (*metric->set->description != '\0') {
		str_append(out, " of ");
		str_append(out, metric->set->description);
	}
	str_append_c(out, '\n');
	/* Type */
	str_append(out, "# TYPE dovecot_");
	str_append(out, metric->name);
	str_append(out, "_count counter\n");
	/* Put all sub-metrics before the actual value */
	label_pos = str_len(labels);
	openmetrics_export_submetrics(out, metric, labels, TRUE,
				      timestamp);
	str_truncate(labels, label_pos);
	/* Metric name */
	str_append(out, "dovecot_");
	str_append(out, metric->name);
	str_append(out, "_count");
	/* Labels */
	if (str_len(labels) > 0) {
		str_append_c(out, '{');
		str_append_str(out, labels);
		str_append_c(out, '}');
	}
	/* Value */
	str_printfa(out, " %u %"PRId64"\n\n",
		    stats_dist_get_count(metric->duration_stats), timestamp);
	/* Description */
	str_append(out, "# HELP dovecot_");
	str_append(out, metric->name);
	str_append(out, "_duration_usecs_sum Duration");
	if (*metric->set->description != '\0') {
		str_append(out, " of ");
		str_append(out, metric->set->description);
	}
	str_append_c(out, '\n');
	/* Type */
	str_append(out, "# TYPE dovecot_");
	str_append(out, metric->name);
	str_append(out, "_duration_usecs_sum counter\n");
	/* Put all sub-metrics before the actual value */
	openmetrics_export_submetrics(out, metric, labels, FALSE,
				      timestamp);
	str_truncate(labels, label_pos);
	/* Metric name*/
	str_append(out, "dovecot_");
	str_append(out, metric->name);
	str_append(out, "_duration_usecs_sum");
	/* Labels */
	if (str_len(labels) > 0) {
		str_append_c(out, '{');
		str_append_str(out, labels);
		str_append_c(out, '}');
	}
	/* Value */
	str_printfa(out, " %"PRIu64" %"PRId64"\n",
		    stats_dist_get_sum(metric->duration_stats),
		    timestamp);
}

static void
openmetrics_export(struct http_server_response *resp)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;
	string_t *out = t_str_new(2048);
	int64_t timestamp;

	i_assert(ioloop_timeval.tv_usec < 1000000);
	timestamp = ((int64_t)ioloop_timeval.tv_sec * 1000 +
		     (int64_t)ioloop_timeval.tv_usec / 1000);

	i_assert(stats_startup_time <= ioloop_time);
	str_append(out, "# HELP dovecot_stats_uptime_seconds "
			"Dovecot stats service uptime\n");
	str_append(out, "# TYPE dovecot_stats_uptime_seconds counter\n");
	str_printfa(out, "dovecot_stats_uptime_seconds %"PRId64" %"PRId64"\n\n",
		    (int64_t)(ioloop_time - stats_startup_time), timestamp);

	str_append(out, "# HELP dovecot_build_info "
			"Dovecot build information\n");
	str_append(out, "# TYPE dovecot_build_info untyped\n");
	str_printfa(out, "dovecot_build_info{"OPENMETRICS_BUILD_INFO"} "
			 "1 %"PRId64"\n", timestamp);

	iter = stats_metrics_iterate_init(stats_metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) {
		/* Empty line */
		str_append_c(out, '\n');

		openmetrics_export_metric(out, metric, timestamp);
	}
	stats_metrics_iterate_deinit(&iter);

	http_server_response_set_payload_data(
		resp, str_data(out), str_len(out));
}

static void
stats_service_openmetrics_request(void *context ATTR_UNUSED,
				 struct http_server_request *req,
				 const char *sub_path)
{
	const struct http_request *hreq = http_server_request_get(req);
	struct http_server_response *resp;

	if (strcmp(hreq->method, "OPTIONS") == 0) {
		resp = http_server_response_create(req, 200, "OK");
		http_server_response_add_header(resp, "Allow", "GET");
		http_server_response_submit(resp);
		return;
	}
	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail_bad_method(req, "GET");
		return;
	}
	if (*sub_path != '\0') {
		http_server_request_fail(req, 404, "Not Found");
		return;
	}

	resp = http_server_response_create(req, 200, "OK");
	http_server_response_add_header(
		resp, "Content-Type", "text/plain; "
				      "version="OPENMETRICS_CONTENT_VERSION"; "
				      "charset=utf-8");

	openmetrics_export(resp);

	http_server_response_submit(resp);
}

void stats_service_openmetrics_init(void)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;

	iter = stats_metrics_iterate_init(stats_metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) {
		if (!openmetrics_check_metric(metric)) {
			i_warning(
				"stats: openmetrics: "
				"Metric `%s' is not valid for OpenMetrics"
				"(invalid metric or label name; skipped)",
				metric->name);
		}
	}
	stats_metrics_iterate_deinit(&iter);

	stats_http_resource_add("/metrics", "OpenMetrics",
				stats_service_openmetrics_request, NULL);
}
