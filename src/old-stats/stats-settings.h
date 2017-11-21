#ifndef STATS_SETTINGS_H
#define STATS_SETTINGS_H

struct old_stats_settings {
	uoff_t memory_limit;

	unsigned int command_min_time;
	unsigned int session_min_time;
	unsigned int user_min_time;
	unsigned int domain_min_time;
	unsigned int ip_min_time;

	unsigned int carbon_interval;
	const char *carbon_server;
	const char *carbon_name;
};

extern const struct setting_parser_info old_stats_setting_parser_info;
extern const struct old_stats_settings *stats_settings;

#endif

