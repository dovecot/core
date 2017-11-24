#ifndef DIRECTOR_SETTINGS_H
#define DIRECTOR_SETTINGS_H

#include "net.h"

struct director_settings {
	const char *master_user_separator;

	const char *director_servers;
	const char *director_mail_servers;
	const char *director_username_hash;
	const char *director_flush_socket;

	unsigned int director_ping_idle_timeout;
	unsigned int director_ping_max_timeout;
	unsigned int director_user_expire;
	unsigned int director_user_kick_delay;
	in_port_t director_doveadm_port;
	bool director_consistent_hashing;
	unsigned int director_max_parallel_moves;
	unsigned int director_max_parallel_kicks;
	uoff_t director_output_buffer_size;
};

extern const struct setting_parser_info director_setting_parser_info;

#endif
