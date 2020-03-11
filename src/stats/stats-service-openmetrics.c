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

struct openmetrics_request {
	const struct metric *metric;
	string_t *labels;
};

/* https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels:

   Every time series is uniquely identified by its metric name and optional
   key-value pairs called labels.

   The metric name specifies the general feature of a system that is measured
   (e.g. http_requests_total - the total number of HTTP requests received). It
   may contain ASCII letters and digits, as well as underscores and colons. It
   must match the regex [a-zA-Z_:][a-zA-Z0-9_:]*.
 */

static bool
openmetrics_export_submetrics(struct openmetrics_request *req, string_t *out,
			      const struct metric *metric, bool count,
			      int64_t timestamp);

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

static void openmetrics_export_dovecot(string_t *out, int64_t timestamp)
{
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
openmetrics_export_submetric(struct openmetrics_request *req, string_t *out,
			     const struct metric *metric, bool count,
			     int64_t timestamp)
{
	if (!openmetrics_check_name(metric->sub_name))
		return;
	str_append_c(req->labels, '"');
	openmetrics_escape_string(req->labels, metric->sub_name);
	str_append_c(req->labels, '"');

	str_append(out, "dovecot_");
	str_append(out, req->metric->name);
	if (count) {
		str_append(out, "_count");
		str_append_c(out, '{');
		str_append_str(out, req->labels);
		str_append_c(out, '}');
		str_printfa(out, " %u %"PRId64"\n",
			    stats_dist_get_count(metric->duration_stats),
			    timestamp);
	} else {
		str_append(out, "_duration_usecs_sum");
		str_append_c(out, '{');
		str_append_str(out, req->labels);
		str_append_c(out, '}');
		str_printfa(out, " %"PRIu64" %"PRId64"\n",
			    stats_dist_get_sum(metric->duration_stats),
			    timestamp);
	}
	size_t label_pos = str_len(req->labels);
	(void)openmetrics_export_submetrics(req, out, metric, count, timestamp);
	str_truncate(req->labels, label_pos);
}

static bool
openmetrics_export_submetrics(struct openmetrics_request *req, string_t *out,
			      const struct metric *metric, bool count,
			      int64_t timestamp)
{
	struct metric *const *sub_metric;
	if (!array_is_created(&metric->sub_metrics))
		return FALSE;
	if (str_len(req->labels) > 0)
		str_append_c(req->labels, ',');
	str_append(req->labels, metric->group_by->field);
	str_append_c(req->labels, '=');
	array_foreach(&metric->sub_metrics, sub_metric) {
		size_t label_pos = str_len(req->labels);
		openmetrics_export_submetric(req, out, *sub_metric, count,
					     timestamp);
		str_truncate(req->labels, label_pos);
	}
	return TRUE;
}

static void
openmetrics_export_metric(struct openmetrics_request *req, string_t *out,
			  int64_t timestamp)
{
	const struct metric *metric = req->metric;

	if (!openmetrics_check_metric(metric))
		return;

	req->labels = t_str_new(32);
	size_t label_pos;
	bool has_submetric;
	openmetrics_export_metric_labels(req->labels, metric);

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
	label_pos = str_len(req->labels);
	has_submetric = openmetrics_export_submetrics(req, out, metric, TRUE,
						      timestamp);
	str_truncate(req->labels, label_pos);
	if (!has_submetric) {
		/* Metric name */
		str_append(out, "dovecot_");
		str_append(out, metric->name);
		str_append(out, "_count");
		/* Labels */
		if (str_len(req->labels) > 0) {
			str_append_c(out, '{');
			str_append_str(out, req->labels);
			str_append_c(out, '}');
		}
		/* Value */
		str_printfa(out, " %u %"PRId64"\n",
			    stats_dist_get_count(metric->duration_stats), timestamp);
	}
	str_append_c(out, '\n');
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
	has_submetric = openmetrics_export_submetrics(req, out, metric, FALSE,
						      timestamp);
	str_truncate(req->labels, label_pos);
	if (!has_submetric) {
		/* Metric name*/
		str_append(out, "dovecot_");
		str_append(out, metric->name);
		str_append(out, "_duration_usecs_sum");
		/* Labels */
		if (str_len(req->labels) > 0) {
			str_append_c(out, '{');
			str_append_str(out, req->labels);
			str_append_c(out, '}');
		}
		/* Value */
		str_printfa(out, " %"PRIu64" %"PRId64"\n",
			    stats_dist_get_sum(metric->duration_stats),
			    timestamp);
	}
}

static void
openmetrics_export(struct openmetrics_request *req,
		   struct http_server_response *resp)
{
	struct stats_metrics_iter *iter;
	const struct metric *metric;
	string_t *out = t_str_new(2048);
	int64_t timestamp;

	i_assert(ioloop_timeval.tv_usec < 1000000);
	timestamp = ((int64_t)ioloop_timeval.tv_sec * 1000 +
		     (int64_t)ioloop_timeval.tv_usec / 1000);

	openmetrics_export_dovecot(out, timestamp);
	
	iter = stats_metrics_iterate_init(stats_metrics);
	while ((metric = stats_metrics_iterate(iter)) != NULL) {
		/* Empty line */
		str_append_c(out, '\n');

		req->metric = metric;
		openmetrics_export_metric(req, out, timestamp);
	}
	stats_metrics_iterate_deinit(&iter);

	http_server_response_set_payload_data(
		resp, str_data(out), str_len(out));
}

static void
stats_service_openmetrics_request(void *context ATTR_UNUSED,
				  struct http_server_request *hsreq,
				  const char *sub_path)
{
	const struct http_request *hreq = http_server_request_get(hsreq);
	struct http_server_response *hsresp;
	struct openmetrics_request req;

	if (strcmp(hreq->method, "OPTIONS") == 0) {
		hsresp = http_server_response_create(hsreq, 200, "OK");
		http_server_response_add_header(hsresp, "Allow", "GET");
		http_server_response_submit(hsresp);
		return;
	}
	if (strcmp(hreq->method, "GET") != 0) {
		http_server_request_fail_bad_method(hsreq, "GET");
		return;
	}
	if (*sub_path != '\0') {
		http_server_request_fail(hsreq, 404, "Not Found");
		return;
	}

	hsresp = http_server_response_create(hsreq, 200, "OK");
	http_server_response_add_header(
		hsresp, "Content-Type",
		"text/plain; version="OPENMETRICS_CONTENT_VERSION"; "
		"charset=utf-8");

	i_zero(&req);
	openmetrics_export(&req, hsresp);

	http_server_response_submit(hsresp);
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
