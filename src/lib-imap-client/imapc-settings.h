#ifndef IMAPC_SETTINGS_H
#define IMAPC_SETTINGS_H

#include "net.h"

/* IMAP RFC defines this to be at least 30 minutes. */
#define IMAPC_DEFAULT_MAX_IDLE_TIME (60*29)

/* <settings checks> */
enum imapc_features {
	IMAPC_FEATURE_NO_FETCH_SIZE		= 0x01,
	IMAPC_FEATURE_GUID_FORCED		= 0x02,
	IMAPC_FEATURE_NO_FETCH_HEADERS		= 0x04,
	IMAPC_FEATURE_GMAIL_MIGRATION		= 0x08,
	IMAPC_FEATURE_NO_SEARCH			= 0x10,
	IMAPC_FEATURE_ZIMBRA_WORKAROUNDS	= 0x20,
	IMAPC_FEATURE_NO_EXAMINE		= 0x40,
	IMAPC_FEATURE_PROXYAUTH			= 0x80,
	IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS	= 0x100,
	IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS	= 0x200,
	IMAPC_FEATURE_NO_MODSEQ			= 0x400,
	IMAPC_FEATURE_NO_DELAY_LOGIN		= 0x800,
	IMAPC_FEATURE_NO_FETCH_BODYSTRUCTURE	= 0x1000,
	IMAPC_FEATURE_SEND_ID			= 0x2000,
	IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED	= 0x4000,
	IMAPC_FEATURE_NO_MSN_UPDATES		= 0x8000,
	IMAPC_FEATURE_NO_ACL 			= 0x10000,
	IMAPC_FEATURE_NO_METADATA		= 0x20000,
	IMAPC_FEATURE_NO_QRESYNC		= 0x40000,
};
/* </settings checks> */

/*
 * NOTE: Any additions here should be reflected in imapc_storage_create's
 * serialization of settings.
 */
struct imapc_settings {
	pool_t pool;
	const char *imapc_host;
	in_port_t imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;
	ARRAY_TYPE(const_string) imapc_sasl_mechanisms;

	const char *imapc_ssl;

	ARRAY_TYPE(const_string) imapc_features;
	const char *imapc_rawlog_dir;
	const char *imapc_list_prefix;
	unsigned int imapc_cmd_timeout_secs;
	unsigned int imapc_max_idle_time_secs;
	unsigned int imapc_connection_timeout_interval_msecs;
	unsigned int imapc_connection_retry_count;
	unsigned int imapc_connection_retry_interval_msecs;
	uoff_t imapc_max_line_length;

	const char *pop3_deleted_flag;

	const char *dns_client_socket_path;

	enum imapc_features parsed_features;
	unsigned int throttle_init_msecs;
	unsigned int throttle_max_msecs;
	unsigned int throttle_shrink_min_msecs;
};

extern const struct setting_parser_info imapc_setting_parser_info;

#endif
