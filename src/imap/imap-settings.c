/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "smtp-submit-settings.h"
#include "imap-settings.h"

#include <unistd.h>

static bool imap_settings_verify(void *_set, pool_t pool,
				 const char **error_r);

struct service_settings imap_service_settings = {
	.name = "imap",
	.protocol = "imap",
	.type = "",
	.executable = "imap",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_service_settings_defaults[] = {
	{ "unix_listener", "imap-master login\\simap srv.imap\\s%{pid}" },

	{ "unix_listener/imap-master/path", "imap-master" },
	{ "unix_listener/imap-master/type", "master" },
	{ "unix_listener/imap-master/mode", "0600" },

	{ "unix_listener/login\\simap/path", "login/imap" },
	{ "unix_listener/login\\simap/type", "login" },
	{ "unix_listener/login\\simap/mode", "0666" },

	{ "unix_listener/srv.imap\\s%{pid}/path", "srv.imap/%{pid}" },
	{ "unix_listener/srv.imap\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap\\s%{pid}/mode", "0600" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_settings)

static const struct setting_define imap_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR_VARS, rawlog_dir),

	DEF(SIZE, imap_max_line_length),
	DEF(TIME, imap_idle_notify_interval),
	DEF(STR, imap_capability),
	DEF(STR, imap_client_workarounds),
	DEF(STR, imap_logout_format),
	DEF(STR, imap_id_send),
	DEF(ENUM, imap_fetch_failure),
	DEF(BOOL, imap_metadata),
	DEF(BOOL, imap_literal_minus),
	DEF(TIME, imap_hibernate_timeout),

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	SETTING_DEFINE_LIST_END
};

static const struct imap_settings imap_default_settings = {
	.verbose_proctitle = FALSE,
	.rawlog_dir = "",

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	.imap_max_line_length = 64*1024,
	.imap_idle_notify_interval = 2*60,
	.imap_capability = "",
	.imap_client_workarounds = "",
	.imap_logout_format = "in=%i out=%o deleted=%{deleted} "
		"expunged=%{expunged} trashed=%{trashed} "
		"hdr_count=%{fetch_hdr_count} hdr_bytes=%{fetch_hdr_bytes} "
		"body_count=%{fetch_body_count} body_bytes=%{fetch_body_bytes}",
	.imap_id_send = "name *",
	.imap_fetch_failure = "disconnect-immediately:disconnect-after:no-after",
	.imap_metadata = FALSE,
	.imap_literal_minus = FALSE,
	.imap_hibernate_timeout = 0,

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};

const struct setting_parser_info imap_setting_parser_info = {
	.name = "imap",

	.defines = imap_setting_defines,
	.defaults = &imap_default_settings,

	.struct_size = sizeof(struct imap_settings),
	.pool_offset1 = 1 + offsetof(struct imap_settings, pool),
	.check_func = imap_settings_verify,
};

/* <settings checks> */
struct imap_client_workaround_list {
	const char *name;
	enum imap_client_workarounds num;
};

static const struct imap_client_workaround_list imap_client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ "tb-lsub-flags", WORKAROUND_TB_LSUB_FLAGS },
	{ NULL, 0 }
};

static int
imap_settings_parse_workarounds(struct imap_settings *set,
				const char **error_r)
{
        enum imap_client_workarounds client_workarounds = 0;
        const struct imap_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imap_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = imap_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imap_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}


static bool
imap_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct imap_settings *set = _set;

	if (imap_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;

	if (strcmp(set->imap_fetch_failure, "disconnect-immediately") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_IMMEDIATELY;
	else if (strcmp(set->imap_fetch_failure, "disconnect-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_DISCONNECT_AFTER;
	else if (strcmp(set->imap_fetch_failure, "no-after") == 0)
		set->parsed_fetch_failure = IMAP_CLIENT_FETCH_FAILURE_NO_AFTER;
	else {
		*error_r = t_strdup_printf("Unknown imap_fetch_failure: %s",
					   set->imap_fetch_failure);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */
