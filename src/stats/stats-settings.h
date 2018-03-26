#ifndef STATS_SETTINGS_H
#define STATS_SETTINGS_H

struct stats_metric_settings {
	const char *name;
	const char *event_name;
	const char *source_location;
	const char *categories;
	const char *fields;
	ARRAY(const char *) filter;

	unsigned int parsed_source_linenum;
};

struct stats_settings {
	ARRAY(struct stats_metric_settings *) metrics;
};

extern const struct setting_parser_info stats_setting_parser_info;

#endif
