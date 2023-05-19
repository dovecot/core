/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-parse.h"
#include "settings-parser.h"
#include "config-parser-private.h"
#include "old-set-parser.h"
#include "event-filter.h"
#include "istream.h"
#include "base64.h"
#include <stdio.h>

#define LOG_DEBUG_KEY "log_debug"
#define config_apply_line(ctx, key, value) \
	(void)config_apply_line(ctx, key, value, NULL)

struct old_set_parser {
	const char *base_dir;
	const char *post_log_debug;
	/* 1 when in auth {} section, >1 when inside auth { .. { .. } } */
	unsigned int auth_section;
	bool seen_auth_section:1;
	bool post_auth_debug:1;
};

static const struct config_filter any_filter = {
	.service = NULL
};

static const struct config_filter imap_filter = {
	.service = "imap"
};
static const struct config_filter pop3_filter = {
	.service = "pop3"
};
static const struct config_filter managesieve_filter = {
	.service = "sieve"
};

static const struct {
	const char *key;
	const char *details;
	bool fail_if_set;
} removed_settings[] = {
	{ .key = "login_dir", },
	{ .key = "license_checksum", },
	{ .key = "dbox_rotate_min_size", },
	{ .key = "dbox_rotate_days", },
	{ .key = "director_consistent_hashing", },
	{ .key = "mail_log_max_lines_per_sec", },
	{ .key = "maildir_copy_preserve_filename", },
	{ .key = "ssl_parameters_regenerate", },
	{ .key = "ssl_dh_parameters_length", },
	{ .key = "login_access_sockets", .fail_if_set = TRUE, },
	{ .key = "imap_id_log", .details = "Use event exporter for the 'imap_id_received' event instead.", },
	{ .key = "config_cache_size", },
};

static void ATTR_FORMAT(2, 3)
obsolete(struct config_parser_context *ctx, const char *str, ...)
{
	static bool seen_obsoletes = FALSE;
	va_list args;

	if (ctx->hide_obsolete_warnings)
		return;

	if (!seen_obsoletes) {
		i_warning("NOTE: You can get a new clean config file with: "
			  "doveconf -Pn > dovecot-new.conf");
		seen_obsoletes = TRUE;
	}

	va_start(args, str);
	i_warning("Obsolete setting in %s:%u: %s",
		  ctx->cur_input->path, ctx->cur_input->linenum,
		  t_strdup_vprintf(str, args));
	va_end(args);
}

static void old_set_parser_apply(struct config_parser_context *ctx,
				 enum config_line_type type,
				 const char *key, const char *value)
{
	const struct config_line line = {
		.type = type,
		.key = key,
		.value = value,
	};
	config_parser_apply_line(ctx, &line);
}

static void set_rename(struct config_parser_context *ctx,
		       const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been renamed to %s", old_key, key);
	old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE, key, value);
}

static int ssl_protocols_to_min_protocol(const char *ssl_protocols,
					 const char **min_protocol_r,
					 const char **error_r)
{
	static const char *protocol_versions[] = {
		"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2",
	};
	/* Array where -1 = disable, 0 = not found, 1 = enable */
	int protos[N_ELEMENTS(protocol_versions)];
	memset(protos, 0, sizeof(protos));
	bool explicit_enable = FALSE;

	const char *const *tmp = t_strsplit_spaces(ssl_protocols, ", ");
	for (; *tmp != NULL; tmp++) {
		const char *p = *tmp;
		bool enable = TRUE;
		if (p[0] == '!') {
			enable = FALSE;
			++p;
		}
		for (unsigned int i = 0; i < N_ELEMENTS(protocol_versions); i++) {
			if (strcmp(p, protocol_versions[i]) == 0) {
				if (enable) {
					protos[i] = 1;
					explicit_enable = TRUE;
				} else {
					protos[i] = -1;
				}
				goto found;
			}
		}
		*error_r = t_strdup_printf("Unrecognized protocol '%s'", p);
		return -1;

		found:;
	}

	unsigned int min = N_ELEMENTS(protocol_versions);
	for (unsigned int i = 0; i < N_ELEMENTS(protocol_versions); i++) {
		if (explicit_enable) {
			if (protos[i] > 0)
				min = I_MIN(min, i);
		} else if (protos[i] == 0)
			min = I_MIN(min, i);
	}
	if (min == N_ELEMENTS(protocol_versions)) {
		*error_r = "All protocols disabled";
		return -1;
	}

	*min_protocol_r = protocol_versions[min];
	return 0;
}

static bool
old_settings_handle_root(struct config_parser_context *ctx,
			 const char *key, const char *value)
{
	const char *p, *suffix;
	size_t len;

	if (strcmp(key, "base_dir") == 0) {
		len = strlen(value);
		if (len > 0 && value[len-1] == '/')
			value = t_strndup(value, len-1);
		ctx->old->base_dir = p_strdup(ctx->pool, value);
	}
	if (strcmp(key, "protocols") == 0) {
		char **protos, **s;
		bool have_imap = FALSE, have_imaps = FALSE;
		bool have_pop3 = FALSE, have_pop3s = FALSE;

		protos = p_strsplit_spaces(pool_datastack_create(), value, " ");
		for (s = protos; *s != NULL; s++) {
			if (strcmp(*s, "imap") == 0)
				have_imap = TRUE;
			else if (strcmp(*s, "imaps") == 0) {
				*s = "";
				have_imaps = TRUE;
			} else if (strcmp(*s, "pop3") == 0)
				have_pop3 = TRUE;
			else if (strcmp(*s, "pop3s") == 0) {
				*s = "";
				have_pop3s = TRUE;
			} else if (strcmp(*s, "managesieve") == 0) {
				*s = "sieve";
				obsolete(ctx, "protocols=managesieve has been renamed to protocols=sieve");
			}
		}
		value = t_strarray_join((const char *const *)protos, " ");
		/* ugly way to drop extra spaces.. */
		protos = p_strsplit_spaces(pool_datastack_create(), value, " ");
		value = t_strarray_join((const char *const *)protos, " ");

		if (have_imaps && !have_imap) {
			obsolete(ctx, "'imaps' protocol can no longer be specified (use protocols=imap). to disable non-ssl imap, use service imap-login { inet_listener imap { port=0 } }");
			value = t_strconcat(value, " imap", NULL);
			config_apply_line(ctx,
				"service/imap-login/inet_listener/imap/port", "0");
		} else if (have_imaps)
			obsolete(ctx, "'imaps' protocol is no longer necessary, remove it");
		if (have_pop3s && !have_pop3) {
			obsolete(ctx, "'pop3s' protocol can no longer be specified (use protocols=pop3). to disable non-ssl pop3, use service pop3-login { inet_listener pop3 { port=0 } }");
			value = t_strconcat(value, " pop3", NULL);
			config_apply_line(ctx,
				"service/pop3-login/inet_listener/pop3/port", "0");
		} else if (have_pop3s)
			obsolete(ctx, "'pop3s' protocol is no longer necessary, remove it");

		if (*value == ' ') value++;
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE, key, value);
		return TRUE;
	}
	if (strcmp(key, "ssl_cert_file") == 0 ||
	    strcmp(key, "ssl_key_file") == 0 ||
	    strcmp(key, "ssl_ca_file") == 0) {
		if (*value == '\0')
			return TRUE;
		p = t_strdup_until(key, strrchr(key, '_'));
		obsolete(ctx, "%s has been replaced by %s = <file", key, p);
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYFILE, p, value);
		return TRUE;
	}
	if (strcmp(key, "ssl_disable") == 0) {
		if (strcasecmp(value, "yes") == 0)
			value = "no";
		else if (strcasecmp(value, "no") == 0)
			value = "yes";
		set_rename(ctx, key, "ssl", value);
		return TRUE;
	}
	if (strcmp(key, "ssl_protocols") == 0) {
		obsolete(ctx, "%s has been replaced by ssl_min_protocol", key);
		const char *min_protocol, *error;
		if (ssl_protocols_to_min_protocol(value,  &min_protocol, &error) < 0) {
			i_error("Could not find a minimum ssl_min_protocol "
				"setting from ssl_protocols = %s: %s",
				value, error);
			return TRUE;
		}
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     "ssl_min_protocol", min_protocol);
		return TRUE;
	}
	if (strcmp(key, "sieve") == 0 ||
	    strcmp(key, "sieve_storage") == 0) {
		if (strcmp(key, "sieve_storage") == 0)
			obsolete(ctx, "sieve_storage has been moved into plugin { sieve_dir }");
		else
			obsolete(ctx, "%s has been moved into plugin {} section", key);

		config_apply_line(ctx,
			t_strdup_printf("plugin/%s", key), value);
		return TRUE;
	}
	if (strcmp(key, "fsync_disable") == 0) {
		if (strcasecmp(value, "yes") == 0)
			value = "never";
		else if (strcasecmp(value, "no") == 0)
			value = "optimized";
		set_rename(ctx, key, "mail_fsync", value);
		return TRUE;
	}
	if (strcmp(key, "dbox_rotate_size") == 0) {
		set_rename(ctx, key, "mdbox_rotate_size", value);
		return TRUE;
	}
	if (str_begins(key, "mail_cache_compress_", &suffix)) {
		const char *new_key = t_strconcat("mail_cache_purge_", suffix, NULL);
		set_rename(ctx, key, new_key, value);
		return TRUE;
	}
	if (strcmp(key, "auth_default_realm") == 0) {
		set_rename(ctx, key, "auth_default_domain", value);
		return TRUE;
	}
	if (strcmp(key, "imap_client_workarounds") == 0) {
		char **args, **arg;

		args = p_strsplit_spaces(pool_datastack_create(), value, " ,");
		for (arg = args; *arg != NULL; arg++) {
			if (strcmp(*arg, "outlook-idle") == 0) {
				*arg = "";
				obsolete(ctx, "imap_client_workarounds=outlook-idle is no longer necessary");
			} else if (strcmp(*arg, "netscape-eoh") == 0) {
				*arg = "";
				obsolete(ctx, "imap_client_workarounds=netscape-eoh is no longer supported");
			}
		}
		value = t_strarray_join((void *)args, " ");
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     key, value);
		return TRUE;
	}

	for (unsigned int i = 0; i < N_ELEMENTS(removed_settings); i++) {
		if (strcmp(removed_settings[i].key, key) == 0) {
			if (removed_settings[i].fail_if_set &&
			    value != NULL && *value != '\0')
				i_fatal("%s is no longer supported", key);
			obsolete(ctx, "%s has been removed.%s", key,
				 removed_settings[i].details == NULL ? "" :
				 t_strconcat(" ", removed_settings[i].details, NULL));
			return TRUE;
		}
	}
	if (strcmp(key, "auth_worker_max_count") == 0) {
		obsolete(ctx,
			 "%s has been replaced with service auth-worker { process_limit }",
			 key);
		config_apply_line(ctx, "service/auth-worker/process_limit", value);
		return TRUE;
	}
	if (strcmp(key, "auth_debug") == 0) {
		const char *error ATTR_UNUSED;
		bool auth_debug;
		if (str_parse_get_bool(value, &auth_debug, &error) == 0 &&
		    auth_debug)
			ctx->old->post_auth_debug = auth_debug;
		obsolete(ctx, "%s will be removed in a future version%s",
			 key, ctx->old->post_auth_debug ?
				", consider using log_debug = \"category=auth\" instead" : "");
		return TRUE;
	}
	if (strcmp(key, LOG_DEBUG_KEY) == 0) {
		ctx->old->post_log_debug = p_strdup(ctx->pool, value);
		return FALSE;
	}
	if (strcmp(key, "disable_plaintext_auth") == 0) {
		const char *error;
		bool b;
		if (str_parse_get_bool(value, &b, &error) < 0)
			i_fatal("%s has bad value '%s': %s", key, value, error);
		obsolete(ctx, "%s = %s has been replaced with auth_allow_cleartext = %s",
			 key, value, b ? "no" : "yes");
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     "auth_allow_cleartext", b ? "no" : "yes");
		return TRUE;
	}
	if (ctx->old->auth_section == 1) {
		if (!str_begins_with(key, "auth_"))
			key = t_strconcat("auth_", key, NULL);
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     key, value);
		return TRUE;
	}
	if (strcmp(key, "imapc_features") == 0) {
		char **args = p_strsplit_spaces(
			pool_datastack_create(), value, " ");
		for (char **arg = args; *arg != NULL; arg++) {
			if (strcmp(*arg, "rfc822.size") == 0 ||
			    strcmp(*arg, "fetch-headers") == 0 ||
			    strcmp(*arg, "search") == 0 ||
			    strcmp(*arg, "modseq") == 0 ||
			    strcmp(*arg, "delay-login") == 0 ||
			    strcmp(*arg, "fetch-bodystructure") == 0 ||
			    strcmp(*arg, "acl") == 0) {
				obsolete(ctx,
					 "The imapc feature '%s' is no longer necessary, "
					 "it is enabled by default.",
					 *arg);
				*arg = "";
			}
		}
		value = t_strarray_join((void *)args, " ");
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE, key, value);
		return TRUE;
	}
	return FALSE;
}

static void
config_apply_login_set(struct config_parser_context *ctx,
		       struct config_section_stack *old_section,
		       const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been replaced by service { %s }", old_key, key);

	if (config_filter_match(&old_section->filter, &imap_filter)) {
		config_apply_line(ctx,
			t_strdup_printf("service/imap-login/%s", key), value);
	}
	if (config_filter_match(&old_section->filter, &pop3_filter)) {
		config_apply_line(ctx,
			t_strdup_printf("service/pop3-login/%s", key), value);
	}
	if (config_filter_match(&old_section->filter, &managesieve_filter)) {
		/* if pigeonhole isn't installed, this fails.
		   just ignore it then.. */
		config_apply_line(ctx,
			t_strdup_printf("service/managesieve-login/%s", key), value);
		ctx->error = NULL;
	}
}

static void
config_apply_mail_set(struct config_parser_context *ctx,
		      struct config_section_stack *old_section,
		      const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been replaced by service { %s }", old_key, key);

	if (config_filter_match(&old_section->filter, &imap_filter)) {
		config_apply_line(ctx,
			t_strdup_printf("service/imap/%s", key), value);
	}
	if (config_filter_match(&old_section->filter, &pop3_filter)) {
		config_apply_line(ctx,
			t_strdup_printf("service/pop3/%s", key), value);
	}
	if (config_filter_match(&old_section->filter, &managesieve_filter)) {
		config_apply_line(ctx,
			t_strdup_printf("service/managesieve/%s", key), value);
		ctx->error = NULL;
	}
}

static void
config_apply_auth_set(struct config_parser_context *ctx,
		      const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been replaced by service auth { %s }", old_key, key);
	config_apply_line(ctx,
		t_strdup_printf("service/auth/%s", key), value);
}

static bool listen_has_port(const char *str)
{
	const char *const *addrs;
	const char *host ATTR_UNUSED;
	in_port_t port ATTR_UNUSED;

	if (strchr(str, ':') == NULL)
		return FALSE;

	addrs = t_strsplit_spaces(str, ", ");
	for (; *addrs != NULL; addrs++) {
		if (net_str2hostport(*addrs, 0, &host, &port) == 0 &&
		    port > 0)
			return TRUE;
	}
	return FALSE;
}

static bool
old_settings_handle_proto(struct config_parser_context *ctx,
			  const char *key, const char *value)
{
	struct config_section_stack *old_section = ctx->cur_section;
	const char *p;
	uoff_t size;
	bool root;

	while (ctx->cur_section->prev != NULL)
		ctx->cur_section = ctx->cur_section->prev;

	root = config_filter_match(&old_section->filter, &any_filter);

	if (strcmp(key, "ssl_listen") == 0 ||
	    (strcmp(key, "listen") == 0 &&
	     (listen_has_port(value) || !root))) {
		const char *ssl = strcmp(key, "ssl_listen") == 0 ? "s" : "";

		if (*value == '\0') {
			/* default */
			return TRUE;
		}
		p = strrchr(value, ':');
		if (p != NULL && listen_has_port(value)) {
			obsolete(ctx, "%s=..:port has been replaced by service { inet_listener { port } }", key);
			value = t_strdup_until(value, p++);
			if (config_filter_match(&old_section->filter, &imap_filter)) {
				config_apply_line(ctx, t_strdup_printf(
					"service/imap-login/inet_listener/imap%s/port", ssl), p);
			}
			if (config_filter_match(&old_section->filter, &pop3_filter)) {
				config_apply_line(ctx, t_strdup_printf(
					"service/pop3-login/inet_listener/pop3%s/port", ssl), p);
			}
			if (*ssl == '\0' &&
			    config_filter_match(&old_section->filter, &managesieve_filter)) {
				config_apply_line(ctx,
					"service/managesieve-login/inet_listener/managesieve/port", p);
				ctx->error = NULL;
			}
		}
		if (root && *ssl == '\0') {
			old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
					     key, value);
		} else {
			obsolete(ctx, "protocol { %s } has been replaced by service { inet_listener { address } }", key);
			if (config_filter_match(&old_section->filter, &imap_filter)) {
				config_apply_line(ctx, t_strdup_printf(
					"service/imap-login/inet_listener/imap%s/address", ssl), value);
			}
			if (config_filter_match(&old_section->filter, &pop3_filter)) {
				config_apply_line(ctx, t_strdup_printf(
					"service/pop3-login/inet_listener/pop3%s/address", ssl), value);
			}
			if (*ssl == '\0' &&
			    config_filter_match(&old_section->filter, &managesieve_filter)) {
				config_apply_line(ctx,
					"service/managesieve-login/inet_listener/managesieve/address", value);
				ctx->error = NULL;
			}
		}
		return TRUE;
	}
	if (strcmp(key, "login_chroot") == 0) {
		if (strcmp(value, "no") == 0)
			value = "";
		else
			value = "login";

		config_apply_login_set(ctx, old_section, key, "chroot", value);
		return TRUE;
	}
	if (strcmp(key, "login_user") == 0) {
		config_apply_login_set(ctx, old_section, key, "user", value);
		return TRUE;
	}
	if (strcmp(key, "login_executable") == 0) {
		config_apply_login_set(ctx, old_section, key, "executable", value);
		return TRUE;
	}
	if (strcmp(key, "login_process_size") == 0) {
		config_apply_login_set(ctx, old_section, key, "vsz_limit",
				       t_strconcat(value, " M", NULL));
		return TRUE;
	}
	if (strcmp(key, "login_process_per_connection") == 0) {
		config_apply_login_set(ctx, old_section, key, "service_count",
				       strcmp(value, "no") == 0 ? "0" : "1");
		return TRUE;
	}
	if (strcmp(key, "login_processes_count") == 0) {
		config_apply_login_set(ctx, old_section, key, "process_min_avail", value);
		return TRUE;
	}
	if (strcmp(key, "login_max_processes_count") == 0) {
		config_apply_login_set(ctx, old_section, key, "process_limit", value);
		return TRUE;
	}
	if (strcmp(key, "login_max_connections") == 0) {
		config_apply_login_set(ctx, old_section, key, "client_limit", value);
		return TRUE;
	}
	if (strcmp(key, "login_process_size") == 0) {
		config_apply_login_set(ctx, old_section, key, "vsz_limit",
				       t_strconcat(value, " M", NULL));
		return TRUE;
	}

	if (strcmp(key, "max_mail_processes") == 0) {
		config_apply_mail_set(ctx, old_section, key, "process_limit", value);
		return TRUE;
	}
	if (strcmp(key, "mail_executable") == 0) {
		config_apply_mail_set(ctx, old_section, key, "executable", value);
		return TRUE;
	}
	if (strcmp(key, "mail_process_size") == 0) {
		config_apply_mail_set(ctx, old_section, key, "vsz_limit",
				      t_strconcat(value, " M", NULL));
		return TRUE;
	}
	if (strcmp(key, "mail_drop_priv_before_exec") == 0) {
		config_apply_mail_set(ctx, old_section, key, "drop_priv_before_exec", value);
		return TRUE;
	}

	if (ctx->old->auth_section == 1) {
		if (!str_begins_with(key, "auth_"))
			key = t_strconcat("auth_", key, NULL);
	}

	if (strcmp(key, "auth_executable") == 0) {
		config_apply_auth_set(ctx, key, "executable", value);
		return TRUE;
	}
	if (strcmp(key, "auth_process_size") == 0) {
		config_apply_auth_set(ctx, key, "vsz_limit",
				      t_strconcat(value, " M", NULL));
		return TRUE;
	}
	if (strcmp(key, "auth_user") == 0) {
		config_apply_auth_set(ctx, key, "user", value);
		return TRUE;
	}
	if (strcmp(key, "auth_chroot") == 0) {
		config_apply_auth_set(ctx, key, "chroot", value);
		return TRUE;
	}
	if (strcmp(key, "auth_cache_size") == 0 &&
	    str_to_uoff(value, &size) == 0 && size > 0 && size < 1024) {
		obsolete(ctx, "auth_cache_size value no longer defaults to "
			 "megabytes. Use %sM", value);
		config_apply_line(ctx, key, t_strdup_printf("%sM", value));
		return TRUE;
	}
	if (strcmp(key, "auth_count") == 0) {
		if (strcmp(value, "count") == 0)
			obsolete(ctx, "auth_count has been removed");
		else
			obsolete(ctx, "auth_count has been removed, and its value must be 1");
		return TRUE;
	}
	return FALSE;
}

static bool old_auth_section(struct config_parser_context *ctx,
			     const char *key, const char *value)
{
	if (ctx->old->auth_section == 0 && ctx->old->seen_auth_section) {
		obsolete(ctx, "Multiple auth sections are no longer supported");
		return FALSE;
	}
	ctx->old->seen_auth_section = TRUE;

	ctx->old->auth_section++;
	if ((strcmp(key, "passdb") == 0 || strcmp(key, "userdb") == 0) &&
	    ctx->old->auth_section == 2) {
		obsolete(ctx, "%s %s {} has been replaced by %s { driver=%s }",
			 key, value, key, value);
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN, key, "");
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     "driver", value);
		return TRUE;
	}
	return FALSE;
}

static bool
old_settings_handle_path(struct config_parser_context *ctx,
			 const char *key, const char *value)
{
	if (str_begins_with(str_c(ctx->key_path), "plugin/")) {
		if (strcmp(key, "push_notification_backend") == 0) {
			obsolete(ctx, "%s has been replaced by push_notification_driver", key);
			config_apply_line(ctx,
				"plugin/push_notification_driver", value);
			return TRUE;
		}

		if (strcmp(key, "zlib_save") == 0) {
			obsolete(ctx, "%s has been replaced by mail_compress_save", key);
			config_apply_line(ctx,
				"plugin/mail_compress_save", value);
			return TRUE;
		}
		if (strcmp(key, "zlib_save_level") == 0) {
			obsolete(ctx, "%s has been replaced by mail_compress_save_level", key);
			config_apply_line(ctx,
				"plugin/mail_compress_save_level", value);
			return TRUE;
		}
	}
	if (strcmp(key, "imap_zlib_compress_level") == 0 ||
	    strcmp(key, "imap_compress_deflate_level") == 0) {
		obsolete(ctx, "%s has been removed, the default compression level is now used unconditionally", key);
		return TRUE;
	}
	return FALSE;
}

bool old_settings_handle(struct config_parser_context *ctx,
			 const struct config_line *line)
{
	const char *key = line->key, *value = line->value;

	switch (line->type) {
	case CONFIG_LINE_TYPE_SKIP:
	case CONFIG_LINE_TYPE_CONTINUE:
	case CONFIG_LINE_TYPE_ERROR:
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVALUE:
		if (str_len(ctx->key_path) == 0) {
			struct config_section_stack *old_section =
				ctx->cur_section;
			bool ret;

			ret = old_settings_handle_proto(ctx, key, value);
			ctx->cur_section = old_section;
			if (ret)
				return TRUE;

			return old_settings_handle_root(ctx, key, value);
		}
		return old_settings_handle_path(ctx, key, value);
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
		if (ctx->old->auth_section > 0)
			return old_auth_section(ctx, key, value);
		else if (str_len(ctx->key_path) == 0 && strcmp(key, "auth") == 0) {
			obsolete(ctx, "add auth_ prefix to all settings inside auth {} and remove the auth {} section completely");
			ctx->old->auth_section = 1;
			return TRUE;
		} else if (str_len(ctx->key_path) == 0 && strcmp(key, "protocol") == 0 &&
			 strcmp(value, "managesieve") == 0) {
			obsolete(ctx, "protocol managesieve {} has been replaced by protocol sieve { }");
			old_set_parser_apply(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN,
					     "protocol", "sieve");
			return TRUE;
		} else if (str_len(ctx->key_path) == 0 && strcmp(key, "service") == 0 &&
			   strcmp(value, "dns_client") == 0) {
			obsolete(ctx, "service dns_client {} has been replaced by service dns-client { }");
			old_set_parser_apply(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN,
					     "service", "dns-client");
			return TRUE;
		} else if (str_len(ctx->key_path) == 0 && strcmp(key, "service") == 0 &&
			   strcmp(value, "ipc") == 0) {
			obsolete(ctx, "service ipc {} no longer exists");
			/* continue anyway */
		}
		break;
	case CONFIG_LINE_TYPE_SECTION_END:
		if (ctx->old->auth_section > 0) {
			if (--ctx->old->auth_section == 0)
				return TRUE;
		}
		break;
	}
	return FALSE;
}

static void old_settings_handle_post_log_debug(struct config_parser_context *ctx)
{
	static const char *category_auth = "category=auth";
	const char *error ATTR_UNUSED;
	const char *prev = ctx->old->post_log_debug;

	if (!ctx->old->post_auth_debug)
		return;

	if (prev == NULL || *prev == '\0') {
		old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				     LOG_DEBUG_KEY, category_auth);
		return;
	}

	struct event_filter *filter = event_filter_create();
	if (event_filter_parse(prev, filter, &error) != 0) {
		/* ignore, it will be handled later when actually
		   parsing/applying the configuration */
		event_filter_unref(&filter);
		return;
	}

	struct event_filter *auth_filter = event_filter_create();
	if (event_filter_parse(category_auth, auth_filter, &error) != 0)
		i_unreached();

	string_t *merged = t_str_new(128);
	event_filter_merge(auth_filter, filter);
	event_filter_export(filter, merged);
	event_filter_unref(&auth_filter);
	event_filter_unref(&filter);

	old_set_parser_apply(ctx, CONFIG_LINE_TYPE_KEYVALUE,
			     LOG_DEBUG_KEY, str_c(merged));
}

void old_settings_handle_post(struct config_parser_context *ctx)
{
	old_settings_handle_post_log_debug(ctx);
}

void old_settings_init(struct config_parser_context *ctx)
{
	ctx->old = p_new(ctx->pool, struct old_set_parser, 1);
	ctx->old->base_dir = PKG_RUNDIR;
}

void old_settings_deinit_global(void)
{
}
