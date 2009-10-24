/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service-settings.h"
#include "lda-settings.h"
#include "lmtp-settings.h"

#include <stddef.h>
#include <unistd.h>

/* <settings checks> */
static struct file_listener_settings lmtp_login_unix_listeners_array[] = {
	{ "lmtp", 0666, "", "" }
};
static struct file_listener_settings *lmtp_login_unix_listeners[] = {
	&lmtp_login_unix_listeners_array[0]
};
static buffer_t lmtp_login_unix_listeners_buf = {
	lmtp_login_unix_listeners, sizeof(lmtp_login_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings lmtp_login_service_settings = {
	MEMBER(name) "lmtp",
	MEMBER(protocol) "lmtp",
	MEMBER(type) "",
	MEMBER(executable) "lmtp",
	MEMBER(user) "",
	MEMBER(group) "",
	MEMBER(privileged_group) "",
	MEMBER(extra_groups) "",
	MEMBER(chroot) "",

	MEMBER(drop_priv_before_exec) FALSE,

	MEMBER(process_min_avail) 0,
	MEMBER(process_limit) 0,
	MEMBER(client_limit) 0,
	MEMBER(service_count) 0,
	MEMBER(vsz_limit) 0,

	MEMBER(unix_listeners) { { &lmtp_login_unix_listeners_buf,
				   sizeof(lmtp_login_unix_listeners[0]) } },
	MEMBER(fifo_listeners) ARRAY_INIT,
	MEMBER(inet_listeners) ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct lmtp_settings, name), NULL }

static const struct setting_define lmtp_setting_defines[] = {
	DEF(SET_BOOL, lmtp_proxy),

	SETTING_DEFINE_LIST_END
};

static const struct lmtp_settings lmtp_default_settings = {
	MEMBER(lmtp_proxy) FALSE
};

static const struct setting_parser_info *lmtp_setting_dependencies[] = {
	&lda_setting_parser_info,
	NULL
};

const struct setting_parser_info lmtp_setting_parser_info = {
	MEMBER(module_name) "lmtp",
	MEMBER(defines) lmtp_setting_defines,
	MEMBER(defaults) &lmtp_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct lmtp_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) NULL,
	MEMBER(dependencies) lmtp_setting_dependencies
};
