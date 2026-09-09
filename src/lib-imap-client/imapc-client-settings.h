#ifndef IMAPC_CLIENT_SETTINGS_H
#define IMAPC_CLIENT_SETTINGS_H

#include "net.h"

/* IMAP RFC defines this to be at least 30 minutes. */
#define IMAPC_DEFAULT_MAX_IDLE_TIME (60*29)

/* <settings checks> */
#define IMAPC_SETTINGS_FILTER "imapc"

enum imapc_client_features {
	IMAPC_FEATURE_PROXYAUTH			= 0x80,
};

enum imapc_capability {
	IMAPC_CAPABILITY_SASL_IR	= 0x01,
	IMAPC_CAPABILITY_LITERALPLUS	= 0x02,
	IMAPC_CAPABILITY_QRESYNC	= 0x04,
	IMAPC_CAPABILITY_IDLE		= 0x08,
	IMAPC_CAPABILITY_UIDPLUS	= 0x10,
	IMAPC_CAPABILITY_AUTH_PLAIN	= 0x20,
	IMAPC_CAPABILITY_STARTTLS	= 0x40,
	IMAPC_CAPABILITY_X_GM_EXT_1	= 0x80,
	IMAPC_CAPABILITY_CONDSTORE	= 0x100,
	IMAPC_CAPABILITY_NAMESPACE	= 0x200,
	IMAPC_CAPABILITY_UNSELECT	= 0x400,
	IMAPC_CAPABILITY_ESEARCH	= 0x800,
	IMAPC_CAPABILITY_WITHIN		= 0x1000,
	IMAPC_CAPABILITY_QUOTA		= 0x2000,
	IMAPC_CAPABILITY_ID		= 0x4000,
	IMAPC_CAPABILITY_SAVEDATE	= 0x8000,
	IMAPC_CAPABILITY_METADATA	= 0x10000,
	IMAPC_CAPABILITY_SORT		= 0x20000,
	IMAPC_CAPABILITY_ESORT		= 0x40000,
	IMAPC_CAPABILITY_SORT_DISPLAY	= 0x100000,
	IMAPC_CAPABILITY_SEARCH_MIMEPART= 0x200000,

	IMAPC_CAPABILITY_IMAP4REV2	= 0x20000000,
	IMAPC_CAPABILITY_IMAP4REV1	= 0x40000000,
};

struct imapc_capability_name {
	const char *name;
	enum imapc_capability capability;
};
extern const struct imapc_capability_name imapc_capability_names[];
/* </settings checks> */

struct imapc_client_settings {
	pool_t pool;
	const char *imapc_host;
	in_port_t imapc_port;
	const char *imapc_ssl;

	ARRAY_TYPE(const_string) imapc_features;
	const char *imapc_rawlog_dir;
	unsigned int imapc_cmd_timeout_secs;
	unsigned int imapc_max_idle_time_secs;
	unsigned int imapc_connection_timeout_interval_msecs;
	unsigned int imapc_connection_retry_count;
	unsigned int imapc_connection_retry_interval_msecs;
	uoff_t imapc_max_line_length;

	enum imapc_client_features parsed_features;
	enum imapc_capability parsed_disabled_capabilities;

	unsigned int throttle_init_msecs;
	unsigned int throttle_max_msecs;
	unsigned int throttle_shrink_min_msecs;

	/* deprecated: */
	ARRAY_TYPE(const_string) imapc_sasl_mechanisms;
};

extern const struct setting_parser_info imapc_client_setting_parser_info;

/* <settings checks> */
enum imapc_capability imapc_capability_lookup(const char *str);
bool imapc_client_feature_lookup(const char *name,
				 enum imapc_client_features *features_r);
/* </settings checks> */

#endif
