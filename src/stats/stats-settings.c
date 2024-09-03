/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "buffer.h"
#include "settings.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "stats-settings.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"

/* <settings checks> */
#include "event-filter.h"
#include <math.h>
/* </settings checks> */

static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r);
static bool stats_exporter_settings_check(void *_set, pool_t pool, const char **error_r);
static bool stats_settings_ext_check(struct event *event, void *_set, pool_t pool, const char **error_r);

struct service_settings stats_service_settings = {
	.name = "stats",
	.protocol = "",
	.type = "",
	.executable = "stats",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,
};

const struct setting_keyvalue stats_service_settings_defaults[] = {
	{ "unix_listener", "login\\sstats-writer stats-reader stats-writer" },

	{ "unix_listener/login\\sstats-writer/path", "login/stats-writer" },
	{ "unix_listener/login\\sstats-writer/type", "writer" },
	{ "unix_listener/login\\sstats-writer/mode", "0600" },
	{ "unix_listener/login\\sstats-writer/user", "$default_login_user" },

	{ "unix_listener/stats-reader/path", "stats-reader" },
	{ "unix_listener/stats-reader/type", "reader" },
	{ "unix_listener/stats-reader/mode", "0600" },

	{ "unix_listener/stats-writer/path", "stats-writer" },
	{ "unix_listener/stats-writer/type", "writer" },
	{ "unix_listener/stats-writer/mode", "0660" },
	{ "unix_listener/stats-writer/group", "$default_internal_group" },

	{ NULL, NULL }
};

/*
 * event_exporter { } block settings
 */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("event_exporter_"#name, name, struct stats_exporter_settings)

static const struct setting_define stats_exporter_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, transport),
	DEF(STR, transport_args),
	DEF(TIME_MSECS, transport_timeout),
	DEF(STR, format),
	DEF(STR, format_args),
	SETTING_DEFINE_LIST_END
};

static const struct stats_exporter_settings stats_exporter_default_settings = {
	.name = "",
	.transport = "",
	.transport_args = "",
	.transport_timeout = 250, /* ms */
	.format = "",
	.format_args = "",
};

const struct setting_parser_info stats_exporter_setting_parser_info = {
	.name = "stats_exporter",

	.defines = stats_exporter_setting_defines,
	.defaults = &stats_exporter_default_settings,

	.struct_size = sizeof(struct stats_exporter_settings),
	.pool_offset1 = 1 + offsetof(struct stats_exporter_settings, pool),
	.check_func = stats_exporter_settings_check,
};

/*
 * metric { } block settings
 */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("metric_"#name, name, struct stats_metric_settings)

static const struct setting_define stats_metric_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, fields),
	DEF(STR, group_by),
	DEF(STR, filter),
	DEF(STR, exporter),
	DEF(STR, exporter_include),
	DEF(STR, description),
	SETTING_DEFINE_LIST_END
};

static const struct stats_metric_settings stats_metric_default_settings = {
	.name = "",
	.fields = "",
	.filter = "",
	.exporter = "",
	.group_by = "",
	.exporter_include = STATS_METRIC_SETTINGS_DEFAULT_EXPORTER_INCLUDE,
	.description = "",
};

const struct setting_parser_info stats_metric_setting_parser_info = {
	.name = "stats_metric",

	.defines = stats_metric_setting_defines,
	.defaults = &stats_metric_default_settings,

	.struct_size = sizeof(struct stats_metric_settings),
	.pool_offset1 = 1 + offsetof(struct stats_metric_settings, pool),
	.check_func = stats_metric_settings_check,
};

/*
 * top-level settings
 */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct stats_settings)

static const struct setting_define stats_setting_defines[] = {
	DEF(STR, stats_http_rawlog_dir),

	{ .type = SET_FILTER_ARRAY, .key = "metric",
	  .offset = offsetof(struct stats_settings, metrics),
	  .filter_array_field_name = "metric_name",
	  .required_setting = "metric_filter", },
	{ .type = SET_FILTER_ARRAY, .key = "event_exporter",
	  .offset = offsetof(struct stats_settings, exporters),
	  .filter_array_field_name = "event_exporter_name",
	  .required_setting = "event_exporter_transport", },
	SETTING_DEFINE_LIST_END
};

const struct stats_settings stats_default_settings = {
	.stats_http_rawlog_dir = "",

	.metrics = ARRAY_INIT,
	.exporters = ARRAY_INIT,
};

const struct setting_parser_info stats_setting_parser_info = {
	.name = "stats",

	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.struct_size = sizeof(struct stats_settings),
	.pool_offset1 = 1 + offsetof(struct stats_settings, pool),
	.ext_check_func = stats_settings_ext_check,
};

/* <settings checks> */
static bool parse_format_args_set_time(struct stats_exporter_settings *set,
				       enum event_exporter_time_fmt fmt,
				       const char **error_r)
{
	if ((set->parsed_time_format != EVENT_EXPORTER_TIME_FMT_NATIVE) &&
	    (set->parsed_time_format != fmt)) {
		*error_r = t_strdup_printf("Exporter '%s' specifies multiple "
					   "time format args", set->name);
		return FALSE;
	}

	set->parsed_time_format = fmt;

	return TRUE;
}

static bool parse_format_args(struct stats_exporter_settings *set,
			      const char **error_r)
{
	const char *const *tmp;

	/* Defaults */
	set->parsed_time_format = EVENT_EXPORTER_TIME_FMT_NATIVE;

	tmp = t_strsplit_spaces(set->format_args, " ");

	/*
	 * If the config contains multiple types of the same type (e.g.,
	 * both time-rfc3339 and time-unix) we fail the config check.
	 *
	 * Note: At the moment, we have only time-* tokens.  In the future
	 * when we have other tokens, they should be parsed here.
	 */
	for (; *tmp != NULL; tmp++) {
		enum event_exporter_time_fmt fmt;

		if (strcmp(*tmp, "time-rfc3339") == 0) {
			fmt = EVENT_EXPORTER_TIME_FMT_RFC3339;
		} else if (strcmp(*tmp, "time-unix") == 0) {
			fmt = EVENT_EXPORTER_TIME_FMT_UNIX;
		} else {
			*error_r = t_strdup_printf("Unknown exporter format "
						   "arg: %s", *tmp);
			return FALSE;
		}

		if (!parse_format_args_set_time(set, fmt, error_r))
			return FALSE;
	}

	return TRUE;
}

static bool stats_exporter_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					  const char **error_r)
{
	struct stats_exporter_settings *set = _set;
	bool time_fmt_required;

	if (set->name[0] == '\0')
		return TRUE;

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporters_add_set().
	 */
	if (set->format[0] == '\0') {
		*error_r = "Exporter format name can't be empty";
		return FALSE;
	} else if (strcmp(set->format, "none") == 0) {
		time_fmt_required = FALSE;
	} else if (strcmp(set->format, "json") == 0) {
		time_fmt_required = TRUE;
	} else if (strcmp(set->format, "tab-text") == 0) {
		time_fmt_required = TRUE;
	} else {
		*error_r = t_strdup_printf("Unknown exporter format '%s'",
					   set->format);
		return FALSE;
	}

	/* TODO: The following should be plugable.
	 *
	 * Note: Make sure to mirror any changes to the below code in
	 * stats_exporters_add_set().
	 */
	if (set->transport[0] == '\0') {
		*error_r = "Exporter transport name can't be empty";
		return FALSE;
	} else if (strcmp(set->transport, "drop") == 0 ||
		   strcmp(set->transport, "http-post") == 0 ||
		   strcmp(set->transport, "log") == 0 ||
		   strcmp(set->transport, "file") == 0 ||
		   strcmp(set->transport, "unix") == 0) {
		/* no-op */
	} else {
		*error_r = t_strdup_printf("Unknown transport type '%s'",
					   set->transport);
		return FALSE;
	}

	if (!parse_format_args(set, error_r))
		return FALSE;

	/* Some formats don't have a native way of serializing time stamps */
	if (time_fmt_required &&
	    set->parsed_time_format == EVENT_EXPORTER_TIME_FMT_NATIVE) {
		*error_r = t_strdup_printf("%s exporter format requires a "
					   "time-* argument", set->format);
		return FALSE;
	}

	return TRUE;
}

static bool parse_metric_group_by_common(const char *func,
					 const char *const *params,
					 intmax_t *min_r,
					 intmax_t *max_r,
					 intmax_t *other_r,
					 const char **error_r)
{
	intmax_t min, max, other;

	if ((str_array_length(params) != 3) ||
	    (str_to_intmax(params[0], &min) < 0) ||
	    (str_to_intmax(params[1], &max) < 0) ||
	    (str_to_intmax(params[2], &other) < 0)) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function takes "
					   "3 int args", func);
		return FALSE;
	}

	if ((min < 0) || (max < 0) || (other < 0)) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function "
					   "arguments must be >= 0", func);
		return FALSE;
	}

	if (min >= max) {
		*error_r = t_strdup_printf("group_by '%s' aggregate function "
					   "min must be < max (%ju must be < %ju)",
					   func, min, max);
		return FALSE;
	}

	*min_r = min;
	*max_r = max;
	*other_r = other;

	return TRUE;
}

static bool parse_metric_group_by_exp(pool_t pool, struct stats_metric_settings_group_by *group_by,
				      const char *const *params, const char **error_r)
{
	intmax_t min, max, base;

	if (!parse_metric_group_by_common("exponential", params, &min, &max, &base, error_r))
		return FALSE;

	if ((base != 2) && (base != 10)) {
		*error_r = t_strdup_printf("group_by 'exponential' aggregate function "
					   "base must be one of: 2, 10 (base=%ju)",
					   base);
		return FALSE;
	}

	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;

	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'base^min'.  The last bucket is also special - it
	 * contains everything greater than 'base^max'.
	 *
	 * The second bucket begins at 'base^min + 1', the third bucket
	 * begins at 'base^(min + 1) + 1', and so on.
	 */
	group_by->num_ranges = max - min + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = pow(base, min);
	group_by->ranges[group_by->num_ranges - 1].min = pow(base, max);
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = pow(base, min + (i - 1));
		group_by->ranges[i].max = pow(base, min + i);
	}

	return TRUE;
}

static bool parse_metric_group_by_lin(pool_t pool, struct stats_metric_settings_group_by *group_by,
				      const char *const *params, const char **error_r)
{
	intmax_t min, max, step;

	if (!parse_metric_group_by_common("linear", params, &min, &max, &step, error_r))
		return FALSE;

	if ((min + step) > max) {
		*error_r = t_strdup_printf("group_by 'linear' aggregate function "
					   "min+step must be <= max (%ju must be <= %ju)",
					   min + step, max);
		return FALSE;
	}

	group_by->func = STATS_METRIC_GROUPBY_QUANTIZED;

	/*
	 * Allocate the bucket range array and fill it in
	 *
	 * The first bucket is special - it contains everything less than or
	 * equal to 'min'.  The last bucket is also special - it contains
	 * everything greater than 'max'.
	 *
	 * The second bucket begins at 'min + 1', the third bucket begins at
	 * 'min + 1 * step + 1', the fourth at 'min + 2 * step + 1', and so on.
	 */
	group_by->num_ranges = (max - min) / step + 2;
	group_by->ranges = p_new(pool, struct stats_metric_settings_bucket_range,
				 group_by->num_ranges);

	/* set up min & max buckets */
	group_by->ranges[0].min = INTMAX_MIN;
	group_by->ranges[0].max = min;
	group_by->ranges[group_by->num_ranges - 1].min = max;
	group_by->ranges[group_by->num_ranges - 1].max = INTMAX_MAX;

	/* remaining buckets */
	for (unsigned int i = 1; i < group_by->num_ranges - 1; i++) {
		group_by->ranges[i].min = min + (i - 1) * step;
		group_by->ranges[i].max = min + i * step;
	}

	return TRUE;
}

static bool
parse_metric_group_by_mod(pool_t pool,
			  struct stats_metric_settings_group_by *group_by,
			  const char *const *params, const char **error_r)
{
	if (params[0] == NULL)
		return TRUE;
	if (params[1] != NULL) {
		*error_r = "Too many parameters for discrete modifier";
		return FALSE;
	}
	group_by->discrete_modifier = p_strdup(pool, params[0]);

	/* Check that the variables are valid */
	const struct var_expand_table table[] = {
		{ 'v', "", "value" },
		{ 'd', "", "domain" },
		{ '\0', NULL, NULL }
	};
	const char *error;
	string_t *str = t_str_new(128);
	if (var_expand(str, group_by->discrete_modifier, table, &error) <= 0) {
		*error_r = t_strdup_printf(
			"Failed to expand discrete modifier for %s: %s",
			group_by->field, error);
		return FALSE;
	}
	return TRUE;
}

static bool parse_metric_group_by(struct stats_metric_settings *set,
				  pool_t pool, const char **error_r)
{
	const char *const *tmp = t_strsplit_spaces(set->group_by, " ");

	if (tmp[0] == NULL)
		return TRUE;

	p_array_init(&set->parsed_group_by, pool, str_array_length(tmp));

	/* For each group_by field */
	for (; *tmp != NULL; tmp++) {
		struct stats_metric_settings_group_by group_by;
		const char *const *params;

		i_zero(&group_by);

		/* <field name>:<aggregation func>... */
		params = t_strsplit(*tmp, ":");
		group_by.field = p_strdup(pool, params[0]);

		if (params[1] == NULL) {
			/* <field name> - alias for <field>:discrete */
			group_by.func = STATS_METRIC_GROUPBY_DISCRETE;
		} else if (strcmp(params[1], "discrete") == 0) {
			/* <field>:discrete */
			group_by.func = STATS_METRIC_GROUPBY_DISCRETE;
			if (!parse_metric_group_by_mod(pool, &group_by, &params[2], error_r))
				return FALSE;
		} else if (strcmp(params[1], "exponential") == 0) {
			/* <field>:exponential:<min mag>:<max mag>:<base> */
			if (!parse_metric_group_by_exp(pool, &group_by, &params[2], error_r))
				return FALSE;
		} else if (strcmp(params[1], "linear") == 0) {
			/* <field>:linear:<min val>:<max val>:<step> */
			if (!parse_metric_group_by_lin(pool, &group_by, &params[2], error_r))
				return FALSE;
		} else {
			*error_r = t_strdup_printf("unknown aggregation function "
						   "'%s' on field '%s'", params[1], params[0]);
			return FALSE;
		}

		array_push_back(&set->parsed_group_by, &group_by);
	}

	return TRUE;
}

static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct stats_metric_settings *set = _set;

	if (set->name[0] == '\0')
		return TRUE;

	if (set->filter[0] == '\0') {
		*error_r = t_strdup_printf("metric %s { filter } is empty - "
					   "will not match anything", set->name);
		return FALSE;
	}

	set->parsed_filter = event_filter_create_fragment(pool);
	if (event_filter_parse(set->filter, set->parsed_filter, error_r) < 0)
		return FALSE;

	if (!parse_metric_group_by(set, pool, error_r))
		return FALSE;

	return TRUE;
}

static bool
stats_settings_ext_check(struct event *event, void *_set,
			 pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct stats_settings *set = _set;
	const struct stats_exporter_settings *exporter;
	struct stats_metric_settings *metric;
	const char *metric_name, *error;
	int ret;

	if (!array_is_created(&set->metrics))
		return TRUE;

	/* check that all metrics refer to exporters that exist */
	array_foreach_elem(&set->metrics, metric_name) {
		if (settings_get_filter(event, "metric", metric_name,
					&stats_metric_setting_parser_info,
					SETTINGS_GET_FLAG_NO_CHECK |
					SETTINGS_GET_FLAG_NO_EXPAND,
					&metric, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get metric %s: %s",
				metric_name, error);
			return FALSE;
		}

		const char *metric_exporter = t_strdup(metric->exporter);
		settings_free(metric);

		if (metric_exporter[0] == '\0')
			continue; /* metric not exported */

		ret = settings_try_get_filter(event, "event_exporter",
					      metric_exporter,
					      &stats_exporter_setting_parser_info,
					      SETTINGS_GET_FLAG_NO_CHECK |
					      SETTINGS_GET_FLAG_NO_EXPAND,
					      &exporter, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to get event_exporter %s: %s",
				metric_exporter, error);
			return FALSE;
		}
		if (ret == 0) {
			*error_r = t_strdup_printf("metric %s refers to "
						   "non-existent exporter '%s'",
						   metric_name,
						   metric_exporter);
			return FALSE;
		}
		settings_free(exporter);
	}

	return TRUE;
}

/* </settings checks> */
