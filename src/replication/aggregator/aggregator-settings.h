#ifndef AGGREGATOR_SETTINGS_H
#define AGGREGATOR_SETTINGS_H

struct aggregator_settings {
	const char *replicator_host;
	unsigned int replicator_port;
};

extern const struct setting_parser_info aggregator_setting_parser_info;
extern const struct aggregator_settings *aggregator_settings;

#endif
