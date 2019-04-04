/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "stats-settings.h"
#include "array.h"

static bool stats_metric_settings_check(void *_set, pool_t pool, const char **error_r);
static bool stats_exporter_settings_check(void *_set, pool_t pool, const char **error_r);
static bool stats_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings stats_unix_listeners_array[] = {
	{ "stats-reader", 0600, "", "" },
	{ "stats-writer", 0660, "", "$default_internal_group" },
};
static struct file_listener_settings *stats_unix_listeners[] = {
	&stats_unix_listeners_array[0],
	&stats_unix_listeners_array[1],
};
static buffer_t stats_unix_listeners_buf = {
	stats_unix_listeners, sizeof(stats_unix_listeners), { NULL, }
};
/* </settings checks> */

struct service_settings stats_service_settings = {
	.name = "stats",
	.protocol = "",
	.type = "",
	.executable = "stats",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "empty",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = UINT_MAX,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &stats_unix_listeners_buf,
			      sizeof(stats_unix_listeners[0]) } },
	.inet_listeners = ARRAY_INIT,
};

/*
 * event_exporter { } block settings
 */

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct stats_exporter_settings, name), NULL }

static const struct setting_define stats_exporter_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_STR, transport),
	DEF(SET_STR, transport_args),
	DEF(SET_STR, format),
	DEF(SET_STR, format_args),
	SETTING_DEFINE_LIST_END
};

static const struct stats_exporter_settings stats_exporter_default_settings = {
	.name = "",
	.transport = "",
	.transport_args = "",
	.format = "",
	.format_args = "",
};

const struct setting_parser_info stats_exporter_setting_parser_info = {
	.defines = stats_exporter_setting_defines,
	.defaults = &stats_exporter_default_settings,

	.type_offset = offsetof(struct stats_exporter_settings, name),
	.struct_size = sizeof(struct stats_exporter_settings),

	.parent_offset = (size_t)-1,
	.check_func = stats_exporter_settings_check,
};

/*
 * metric { } block settings
 */

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct stats_metric_settings, name), NULL }

static const struct setting_define stats_metric_setting_defines[] = {
	DEF(SET_STR, name),
	DEF(SET_STR, event_name),
	DEF(SET_STR, source_location),
	DEF(SET_STR, categories),
	DEF(SET_STR, fields),
	{ SET_STRLIST, "filter", offsetof(struct stats_metric_settings, filter), NULL },
	DEF(SET_STR, exporter),
	DEF(SET_STR, exporter_include),
	SETTING_DEFINE_LIST_END
};

static const struct stats_metric_settings stats_metric_default_settings = {
	.name = "",
	.event_name = "",
	.source_location = "",
	.categories = "",
	.fields = "",
	.exporter = "",
	.exporter_include = "name hostname timestamps categories fields",
};

const struct setting_parser_info stats_metric_setting_parser_info = {
	.defines = stats_metric_setting_defines,
	.defaults = &stats_metric_default_settings,

	.type_offset = offsetof(struct stats_metric_settings, name),
	.struct_size = sizeof(struct stats_metric_settings),

	.parent_offset = (size_t)-1,
	.check_func = stats_metric_settings_check,
};

/*
 * top-level settings
 */

#undef DEFLIST_UNIQUE
#define DEFLIST_UNIQUE(field, name, defines) \
	{ SET_DEFLIST_UNIQUE, name, \
	  offsetof(struct stats_settings, field), defines }

static const struct setting_define stats_setting_defines[] = {
	DEFLIST_UNIQUE(metrics, "metric", &stats_metric_setting_parser_info),
	DEFLIST_UNIQUE(exporters, "event_exporter", &stats_exporter_setting_parser_info),
	SETTING_DEFINE_LIST_END
};

const struct stats_settings stats_default_settings = {
	.metrics = ARRAY_INIT,
	.exporters = ARRAY_INIT,
};

const struct setting_parser_info stats_setting_parser_info = {
	.module_name = "stats",
	.defines = stats_setting_defines,
	.defaults = &stats_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct stats_settings),

	.parent_offset = (size_t)-1,
	.check_func = stats_settings_check,
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

	if (set->name[0] == '\0') {
		*error_r = "Exporter name can't be empty";
		return FALSE;
	}

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
	} else if (strcmp(set->transport, "drop") == 0) {
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

static bool stats_metric_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					const char **error_r)
{
	struct stats_metric_settings *set = _set;
	const char *p;

	if (set->name[0] == '\0') {
		*error_r = "Metric name can't be empty";
		return FALSE;
	}
	if (set->source_location[0] != '\0') {
		if ((p = strchr(set->source_location, ':')) == NULL) {
			*error_r = "source_location is missing ':'";
			return FALSE;
		}
		if (str_to_uint(p+1, &set->parsed_source_linenum) < 0 ||
		    set->parsed_source_linenum == 0) {
			*error_r = "source_location has invalid line number after ':'";
			return FALSE;
		}
	}

	return TRUE;
}

static bool stats_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct stats_settings *set = _set;
	struct stats_exporter_settings *const *exporter;
	struct stats_metric_settings *const *metric;

	if (!array_is_created(&set->metrics) || !array_is_created(&set->exporters))
		return TRUE;

	/* check that all metrics refer to exporters that exist */
	array_foreach(&set->metrics, metric) {
		bool found = FALSE;

		if ((*metric)->exporter[0] == '\0')
			continue; /* metric not exported */

		array_foreach(&set->exporters, exporter) {
			if (strcmp((*metric)->exporter, (*exporter)->name) == 0) {
				found = TRUE;
				break;
			}
		}

		if (!found) {
			*error_r = t_strdup_printf("metric %s refers to "
						   "non-existent exporter '%s'",
						   (*metric)->name,
						   (*metric)->exporter);
			return FALSE;
		}
	}

	return TRUE;
}
/* </settings checks> */
