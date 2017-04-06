#ifndef IMAPC_SETTINGS_H
#define IMAPC_SETTINGS_H

#include "net.h"

/* <settings checks> */
enum imapc_features {
	IMAPC_FEATURE_RFC822_SIZE		= 0x01,
	IMAPC_FEATURE_GUID_FORCED		= 0x02,
	IMAPC_FEATURE_FETCH_HEADERS		= 0x04,
	IMAPC_FEATURE_GMAIL_MIGRATION		= 0x08,
	IMAPC_FEATURE_SEARCH			= 0x10,
	IMAPC_FEATURE_ZIMBRA_WORKAROUNDS	= 0x20,
	IMAPC_FEATURE_NO_EXAMINE		= 0x40,
	IMAPC_FEATURE_PROXYAUTH			= 0x80,
	IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS	= 0x100,
	IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS	= 0x200,
	IMAPC_FEATURE_MODSEQ			= 0x400,
	IMAPC_FEATURE_DELAY_LOGIN		= 0x800,
};
/* </settings checks> */

/*
 * NOTE: Any additions here should be reflected in imapc_storage_create's
 * serialization of settings.
 */
struct imapc_settings {
	const char *imapc_host;
	in_port_t imapc_port;

	const char *imapc_user;
	const char *imapc_master_user;
	const char *imapc_password;
	const char *imapc_sasl_mechanisms;

	const char *imapc_ssl;
	bool imapc_ssl_verify;

	const char *imapc_features;
	const char *imapc_rawlog_dir;
	const char *imapc_list_prefix;
	unsigned int imapc_cmd_timeout;
	unsigned int imapc_max_idle_time;
	unsigned int imapc_connection_retry_count;
	unsigned int imapc_connection_retry_interval;
	uoff_t imapc_max_line_length;

	const char *pop3_deleted_flag;

	enum imapc_features parsed_features;
	unsigned int throttle_init_msecs;
	unsigned int throttle_max_msecs;
	unsigned int throttle_shrink_min_msecs;
};

const struct setting_parser_info *imapc_get_setting_parser_info(void);

#endif
