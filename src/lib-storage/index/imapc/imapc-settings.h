#ifndef IMAPC_SETTINGS_H
#define IMAPC_SETTINGS_H

#include "net.h"
#include "imapc-client-settings.h"

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
	IMAPC_FEATURE_FETCH_MSN_WORKAROUNDS	= 0x80,
	IMAPC_FEATURE_FETCH_FIX_BROKEN_MAILS	= 0x100,
	IMAPC_FEATURE_NO_MODSEQ			= 0x200,
	IMAPC_FEATURE_NO_DELAY_LOGIN		= 0x400,
	IMAPC_FEATURE_NO_FETCH_BODYSTRUCTURE	= 0x800,
	IMAPC_FEATURE_SEND_ID			= 0x1000,
	IMAPC_FEATURE_FETCH_EMPTY_IS_EXPUNGED	= 0x2000,
	IMAPC_FEATURE_NO_MSN_UPDATES		= 0x4000,
	IMAPC_FEATURE_NO_ACL 			= 0x8000,
};
/* </settings checks> */

struct imapc_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) imapc_features;
	const char *imapc_list_prefix;
	const char *pop3_deleted_flag;

	enum imapc_features parsed_features;
};

extern const struct setting_parser_info imapc_setting_parser_info;

#endif
