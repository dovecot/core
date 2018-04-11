/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "mail-storage-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool lmtp_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings lmtp_unix_listeners_array[] = {
	{ "lmtp", 0666, "", "" }
};
static struct file_listener_settings *lmtp_unix_listeners[] = {
	&lmtp_unix_listeners_array[0]
};
static buffer_t lmtp_unix_listeners_buf = {
	lmtp_unix_listeners, sizeof(lmtp_unix_listeners), { NULL, }
};
/* </settings checks> */

struct service_settings lmtp_service_settings = {
	.name = "lmtp",
	.protocol = "lmtp",
	.type = "",
	.executable = "lmtp",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = (uoff_t)-1,

	.unix_listeners = { { &lmtp_unix_listeners_buf,
			      sizeof(lmtp_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct lmtp_settings, name), NULL }

static const struct setting_define lmtp_setting_defines[] = {
	DEF(SET_BOOL, lmtp_proxy),
	DEF(SET_BOOL, lmtp_save_to_detail_mailbox),
	DEF(SET_BOOL, lmtp_rcpt_check_quota),
	DEF(SET_BOOL, lmtp_add_received_header),
	DEF(SET_UINT, lmtp_user_concurrency_limit),
	DEF(SET_ENUM, lmtp_hdr_delivery_address),
	DEF(SET_STR_VARS, login_greeting),
	DEF(SET_STR, login_trusted_networks),

	SETTING_DEFINE_LIST_END
};

static const struct lmtp_settings lmtp_default_settings = {
	.lmtp_proxy = FALSE,
	.lmtp_save_to_detail_mailbox = FALSE,
	.lmtp_rcpt_check_quota = FALSE,
	.lmtp_add_received_header = TRUE,
	.lmtp_user_concurrency_limit = 0,
	.lmtp_hdr_delivery_address = "final:none:original",
	.login_greeting = PACKAGE_NAME" ready.",
	.login_trusted_networks = ""
};

static const struct setting_parser_info *lmtp_setting_dependencies[] = {
	&lda_setting_parser_info,
	NULL
};

const struct setting_parser_info lmtp_setting_parser_info = {
	.module_name = "lmtp",
	.defines = lmtp_setting_defines,
	.defaults = &lmtp_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct lmtp_settings),

	.parent_offset = (size_t)-1,

	.check_func = lmtp_settings_check,
	.dependencies = lmtp_setting_dependencies
};

/* <settings checks> */
static bool lmtp_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct lmtp_settings *set = _set;

	if (strcmp(set->lmtp_hdr_delivery_address, "none") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_NONE;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "final") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_FINAL;
	} else if (strcmp(set->lmtp_hdr_delivery_address, "original") == 0) {
		set->parsed_lmtp_hdr_delivery_address =
			LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL;
	} else {
		*error_r = t_strdup_printf("Unknown lmtp_hdr_delivery_address: %s",
					   set->lmtp_hdr_delivery_address);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

void lmtp_settings_dup(const struct setting_parser_context *set_parser,
		       pool_t pool,
		       struct lmtp_settings **lmtp_set_r,
		       struct lda_settings **lda_set_r)
{
	void **sets;

	sets = master_service_settings_parser_get_others(master_service,
							 set_parser);
	*lda_set_r = settings_dup(&lda_setting_parser_info, sets[2], pool);
	*lmtp_set_r = settings_dup(&lmtp_setting_parser_info, sets[3], pool);
}
