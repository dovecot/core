/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "service-settings.h"
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
	.chroot = "",

	.drop_priv_before_exec = FALSE,

#ifdef DOVECOT_PRO_EDITION
	.process_limit = 10240,
#else
	.process_limit = 1024,
#endif
	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue imap_service_settings_defaults[] = {
	{ "unix_listener", "imap-master login\\simap srv.imap\\s%{pid}" },

	{ "unix_listener/imap-master/path", "imap-master" },
	{ "unix_listener/imap-master/type", "master" },
	{ "unix_listener/imap-master/mode", "0600" },
#ifdef DOVECOT_PRO_EDITION
	/* Potentially not safe in some setups, so keep it Pro-only */
	{ "unix_listener/imap-master/user", "$SET:default_internal_user" },
#endif

	{ "unix_listener/login\\simap/path", "login/imap" },
	{ "unix_listener/login\\simap/type", "login" },
	{ "unix_listener/login\\simap/mode", "0666" },

	{ "unix_listener/srv.imap\\s%{pid}/path", "srv.imap/%{pid}" },
	{ "unix_listener/srv.imap\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.imap\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct imap_settings)

static const struct setting_define imap_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(BOOL, mailbox_list_index),
	DEF(STR, rawlog_dir),

	DEF(SIZE_HIDDEN, imap_max_line_length),
	DEF(TIME_HIDDEN, imap_idle_notify_interval),
	DEF(BOOLLIST, imap_capability),
	DEF(BOOLLIST, imap_client_workarounds),
	DEF(STR_NOVARS, imap_logout_format),
	DEF(ENUM, imap_fetch_failure),
	DEF(BOOL, imap_metadata),
	DEF(BOOL, imap_literal_minus),
	DEF(BOOL, mail_utf8_extensions),
#ifdef BUILD_IMAP_HIBERNATE
	DEF(TIME, imap_hibernate_timeout),
#endif

	DEF(STR, imap_urlauth_host),
	DEF(IN_PORT, imap_urlauth_port),

	{ .type = SET_STRLIST, .key = "imap_id_send",
	  .offset = offsetof(struct imap_settings, imap_id_send) },

	SETTING_DEFINE_LIST_END
};

static const struct imap_settings imap_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.mailbox_list_index = TRUE,
	.rawlog_dir = "",

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	.imap_max_line_length = 64*1024,
	.imap_idle_notify_interval = 2*60,
	.imap_capability = ARRAY_INIT,
	.imap_client_workarounds = ARRAY_INIT,
	.imap_logout_format = "in=%{input} out=%{output} deleted=%{deleted} "
		"expunged=%{expunged} trashed=%{trashed} "
		"hdr_count=%{fetch_hdr_count} hdr_bytes=%{fetch_hdr_bytes} "
		"body_count=%{fetch_body_count} body_bytes=%{fetch_body_bytes}",
	.imap_id_send = ARRAY_INIT,
	.imap_fetch_failure = "disconnect-immediately:disconnect-after:no-after",
	.imap_metadata = FALSE,
	.imap_literal_minus = FALSE,
	.mail_utf8_extensions = FALSE,
#ifdef DOVECOT_PRO_EDITION
	.imap_hibernate_timeout = 30,
#else
	.imap_hibernate_timeout = 0,
#endif

	.imap_urlauth_host = "",
	.imap_urlauth_port = 143
};

static const struct setting_keyvalue imap_default_settings_keyvalue[] = {
	{ "service/imap/imap_capability/IMAP4rev1", "yes" },
	{ "service/imap/imap_capability/SASL-IR", "yes" },
	{ "service/imap/imap_capability/LOGIN-REFERRALS", "yes" },
	{ "service/imap/imap_capability/ID", "yes" },
	{ "service/imap/imap_capability/ENABLE", "yes" },
	{ "service/imap/imap_capability/IDLE", "yes" },
	{ "service/imap/imap_capability/SORT", "yes" },
	{ "service/imap/imap_capability/SORT=DISPLAY", "yes" },
	{ "service/imap/imap_capability/THREAD=REFERENCES", "yes" },
	{ "service/imap/imap_capability/THREAD=REFS", "yes" },
	{ "service/imap/imap_capability/THREAD=ORDEREDSUBJECT", "yes" },
	{ "service/imap/imap_capability/MULTIAPPEND", "yes" },
	{ "service/imap/imap_capability/URL-PARTIAL", "yes" },
	{ "service/imap/imap_capability/CATENATE", "yes" },
	{ "service/imap/imap_capability/UNSELECT", "yes" },
	{ "service/imap/imap_capability/CHILDREN", "yes" },
	{ "service/imap/imap_capability/NAMESPACE", "yes" },
	{ "service/imap/imap_capability/UIDPLUS", "yes" },
	{ "service/imap/imap_capability/LIST-EXTENDED", "yes" },
	{ "service/imap/imap_capability/I18NLEVEL=1", "yes" },
	{ "service/imap/imap_capability/CONDSTORE", "yes" },
	{ "service/imap/imap_capability/QRESYNC", "yes" },
	{ "service/imap/imap_capability/ESEARCH", "yes" },
	{ "service/imap/imap_capability/ESORT", "yes" },
	{ "service/imap/imap_capability/SEARCHRES", "yes" },
	{ "service/imap/imap_capability/WITHIN", "yes" },
	{ "service/imap/imap_capability/CONTEXT=SEARCH", "yes" },
	{ "service/imap/imap_capability/LIST-STATUS", "yes" },
	{ "service/imap/imap_capability/BINARY", "yes" },
	{ "service/imap/imap_capability/MOVE", "yes" },
	{ "service/imap/imap_capability/REPLACE", "yes" },
	{ "service/imap/imap_capability/SNIPPET=FUZZY", "yes" },
	{ "service/imap/imap_capability/PREVIEW=FUZZY", "yes" },
	{ "service/imap/imap_capability/PREVIEW", "yes" },
	{ "service/imap/imap_capability/SPECIAL-USE", "yes" },
	{ "service/imap/imap_capability/STATUS=SIZE", "yes" },
	{ "service/imap/imap_capability/SAVEDATE", "yes" },
	{ "service/imap/imap_capability/COMPRESS=DEFLATE", "yes" },
	{ "service/imap/imap_capability/INPROGRESS", "yes" },
	{ "service/imap/imap_capability/NOTIFY", "yes" },
	{ "service/imap/imap_capability/METADATA", "yes" },
	{ "service/imap/imap_capability/SPECIAL-USE", "yes" },
	{ "service/imap/imap_capability/LITERAL+", "yes" },
	{ "service/imap/imap_capability/LITERAL-", "yes" },
	{ "service/imap/imap_capability/UTF8=ACCEPT", "yes" },
#ifdef DOVECOT_PRO_EDITION
	{ "service/imap/process_shutdown_filter", "event=mail_user_session_finished AND rss > 20MB" },
#endif
	{ "imap_id_send/name", DOVECOT_NAME },
	{ NULL, NULL },
};

const struct setting_parser_info imap_setting_parser_info = {
	.name = "imap",

	.defines = imap_setting_defines,
	.defaults = &imap_default_settings,
	.default_settings = imap_default_settings_keyvalue,

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

	str = settings_boollist_get(&set->imap_client_workarounds);
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

#ifndef EXPERIMENTAL_MAIL_UTF8
	if (set->mail_utf8_extensions) {
		*error_r = "Dovecot not built with --enable-experimental-mail-utf8";
		return FALSE;
	}
#endif

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
