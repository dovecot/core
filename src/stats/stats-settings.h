#ifndef STATS_SETTINGS_H
#define STATS_SETTINGS_H

struct stats_settings {
	uoff_t memory_limit;

	unsigned int command_min_time;
	unsigned int session_min_time;
	unsigned int user_min_time;
	unsigned int domain_min_time;
	unsigned int ip_min_time;
};

extern const struct setting_parser_info stats_setting_parser_info;
extern const struct stats_settings *stats_settings;

#endif

