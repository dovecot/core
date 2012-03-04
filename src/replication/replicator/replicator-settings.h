#ifndef REPLICATOR_SETTINGS_H
#define REPLICATOR_SETTINGS_H

struct replicator_settings {
	const char *auth_socket_path;
	const char *doveadm_socket_path;

	unsigned int replication_full_sync_interval;
	unsigned int replication_max_conns;
};

extern const struct setting_parser_info replicator_setting_parser_info;
extern const struct replicator_settings *replicator_settings;

#endif
