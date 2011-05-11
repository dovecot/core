/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "settings-parser.h"
#include "config-parser-private.h"
#include "old-set-parser.h"

struct socket_set {
	const char *path, *mode, *user, *group;
	bool master;
};

struct old_set_parser {
	const char *base_dir;
	/* 1 when in auth {} section, >1 when inside auth { .. { .. } } */
	unsigned int auth_section;
	/* 1 when in socket listen {}, >1 when inside more of its sections */
	unsigned int socket_listen_section;
	bool seen_auth_section;
	struct socket_set socket_set;
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

static void ATTR_FORMAT(2, 3)
obsolete(struct config_parser_context *ctx, const char *str, ...)
{
	static bool seen_obsoletes = FALSE;
	va_list args;

	if (!seen_obsoletes) {
		i_warning("NOTE: You can get a new clean config file with: "
			  "doveconf -n > dovecot-new.conf");
		seen_obsoletes = TRUE;
	}

	va_start(args, str);
	i_warning("Obsolete setting in %s:%u: %s",
		  ctx->cur_input->path, ctx->cur_input->linenum,
		  t_strdup_vprintf(str, args));
	va_end(args);
}

static void set_rename(struct config_parser_context *ctx,
		       const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been renamed to %s", old_key, key);
	config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE, key, value);
}

static bool
old_settings_handle_root(struct config_parser_context *ctx,
			 const char *key, const char *value)
{
	const char *p;
	unsigned int len;

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
			obsolete(ctx, "'imaps' protocol is no longer supported. to disable non-ssl imap, use service imap-login { inet_listener imap { port=0 } }");
			value = t_strconcat(value, " imap", NULL);
			config_apply_line(ctx, "port",
				"service/imap-login/inet_listener/imap/port=0", NULL);
		} else if (have_imaps)
			obsolete(ctx, "'imaps' protocol is no longer necessary, remove it");
		if (have_pop3s && !have_pop3) {
			obsolete(ctx, "'pop3s' protocol is no longer supported. to disable non-ssl pop3, use service pop3-login { inet_listener pop3 { port=0 } }");
			value = t_strconcat(value, " pop3", NULL);
			config_apply_line(ctx, "port",
				"service/pop3-login/inet_listener/pop3/port=0", NULL);
		} else if (have_pop3s)
			obsolete(ctx, "'pop3s' protocol is no longer necessary, remove it");

		if (*value == ' ') value++;
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
					 key, value);
		return TRUE;
	}
	if (strcmp(key, "ssl_cert_file") == 0 ||
	    strcmp(key, "ssl_key_file") == 0 ||
	    strcmp(key, "ssl_ca_file") == 0) {
		if (*value == '\0')
			return TRUE;
		p = t_strdup_until(key, strrchr(key, '_'));
		obsolete(ctx, "%s has been replaced by %s = <file", key, p);
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYFILE,
					 p, value);
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
	if (strcmp(key, "sieve") == 0 ||
	    strcmp(key, "sieve_storage") == 0) {
		if (strcmp(key, "sieve_storage") == 0)
			obsolete(ctx, "sieve_storage has been moved into plugin { sieve_dir }");
		else
			obsolete(ctx, "%s has been moved into plugin {} section", key);

		config_apply_line(ctx, "", "plugin=", NULL);
		config_apply_line(ctx, key,
			t_strdup_printf("plugin/%s=%s", key, value), NULL);
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
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
					 key, value);
		return TRUE;
	}

	if (strcmp(key, "login_dir") == 0 ||
	    strcmp(key, "dbox_rotate_min_size") == 0 ||
	    strcmp(key, "dbox_rotate_days") == 0 ||
	    strcmp(key, "mail_log_max_lines_per_sec") == 0 ||
	    strcmp(key, "maildir_copy_preserve_filename") == 0) {
		obsolete(ctx, "%s has been removed", key);
		return TRUE;
	}
	if (ctx->old->auth_section == 1) {
		if (strncmp(key, "auth_", 5) != 0)
			key = t_strconcat("auth_", key, NULL);
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
					 key, value);
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
		config_apply_line(ctx, key,
			t_strdup_printf("service/imap-login/%s=%s", key, value), NULL);
	}
	if (config_filter_match(&old_section->filter, &pop3_filter)) {
		config_apply_line(ctx, key,
			t_strdup_printf("service/pop3-login/%s=%s", key, value), NULL);
	}
	if (config_filter_match(&old_section->filter, &managesieve_filter)) {
		/* if pigeonhole isn't installed, this fails.
		   just ignore it then.. */
		config_apply_line(ctx, key,
			t_strdup_printf("service/managesieve-login/%s=%s", key, value), NULL);
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
		config_apply_line(ctx, key,
			t_strdup_printf("service/imap/%s=%s", key,value), NULL);
	}
	if (config_filter_match(&old_section->filter, &pop3_filter)) {
		config_apply_line(ctx, key,
			t_strdup_printf("service/pop3/%s=%s", key,value), NULL);
	}
	if (config_filter_match(&old_section->filter, &managesieve_filter)) {
		config_apply_line(ctx, key,
			t_strdup_printf("service/managesieve/%s=%s", key,value), NULL);
		ctx->error = NULL;
	}
}

static void
config_apply_auth_set(struct config_parser_context *ctx,
		      const char *old_key, const char *key, const char *value)
{
	obsolete(ctx, "%s has been replaced by service auth { %s }", old_key, key);
	config_apply_line(ctx, key,
		t_strdup_printf("service/auth/%s=%s", key,value), NULL);
}

static bool listen_has_port(const char *str)
{
	const char *const *addrs;

	if (strchr(str, ':') == NULL)
		return FALSE;

	addrs = t_strsplit_spaces(str, ", ");
	for (; *addrs != NULL; addrs++) {
		if (strcmp(*addrs, "*") != 0 &&
		    strcmp(*addrs, "::") != 0 &&
		    strcmp(*addrs, "[::]") != 0 &&
		    !is_ipv4_address(*addrs) &&
		    !is_ipv6_address(*addrs))
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
		if (p != NULL) {
			obsolete(ctx, "%s=..:port has been replaced by service { inet_listener { port } }", key);
			value = t_strdup_until(value, p++);
			if (config_filter_match(&old_section->filter, &imap_filter)) {
				config_apply_line(ctx, "port",
					t_strdup_printf("service/imap-login/inet_listener/imap%s/port=%s", ssl, p), NULL);
			}
			if (config_filter_match(&old_section->filter, &pop3_filter)) {
				config_apply_line(ctx, "port",
					t_strdup_printf("service/pop3-login/inet_listener/pop3%s/port=%s", ssl, p), NULL);
			}
			if (*ssl == '\0' &&
			    config_filter_match(&old_section->filter, &managesieve_filter)) {
				config_apply_line(ctx, "port",
					t_strdup_printf("service/managesieve-login/inet_listener/managesieve/port=%s", p), NULL);
				ctx->error = NULL;
			}
		}
		if (root && *ssl == '\0') {
			config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
						 key, value);
		} else {
			obsolete(ctx, "protocol { %s } has been replaced by service { inet_listener { address } }", key);
			if (config_filter_match(&old_section->filter, &imap_filter)) {
				config_apply_line(ctx, "address",
					t_strdup_printf("service/imap-login/inet_listener/imap%s/address=%s", ssl, value), NULL);
			}
			if (config_filter_match(&old_section->filter, &pop3_filter)) {
				config_apply_line(ctx, "address",
					t_strdup_printf("service/pop3-login/inet_listener/pop3%s/address=%s", ssl, value), NULL);
			}
			if (*ssl == '\0' &&
			    config_filter_match(&old_section->filter, &managesieve_filter)) {
				config_apply_line(ctx, "address",
					t_strdup_printf("service/managesieve-login/inet_listener/managesieve/address=%s", value), NULL);
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
		if (strncmp(key, "auth_", 5) != 0)
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
		config_apply_line(ctx, key,
				  t_strdup_printf("%s=%sM", key, value), NULL);
		return TRUE;
	}
	if (strcmp(key, "auth_count") == 0) {
		if (strcmp(value, "count") == 0)
			obsolete(ctx, "auth_count has been removed");
		else
			obsolete(ctx, "auth_count has been removed, and its value must be 1");
		return TRUE;
	}
	if (ctx->old->socket_listen_section == 2) {
		const char **p = NULL;

		if (strcmp(key, "path") == 0)
			p = &ctx->old->socket_set.path;
		else if (strcmp(key, "mode") == 0)
			p = &ctx->old->socket_set.mode;
		else if (strcmp(key, "user") == 0)
			p = &ctx->old->socket_set.user;
		else if (strcmp(key, "group") == 0)
			p = &ctx->old->socket_set.group;

		if (p != NULL) {
			*p = p_strdup(ctx->pool, value);
			return TRUE;
		}
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
	memset(&ctx->old->socket_set, 0, sizeof(ctx->old->socket_set));

	ctx->old->auth_section++;
	if ((strcmp(key, "passdb") == 0 || strcmp(key, "userdb") == 0) &&
	    ctx->old->auth_section == 2) {
		obsolete(ctx, "%s %s {} has been replaced by %s { driver=%s }",
			 key, value, key, value);
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN, key, "");
		config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
					 "driver", value);
		return TRUE;
	}
	if (strcmp(key, "socket") == 0 && ctx->old->auth_section == 2) {
		if (strcmp(value, "connect") == 0) {
			obsolete(ctx, "socket connect {} is no longer supported, configure external auth server separately");
			return FALSE;
		}
		if (strcmp(value, "listen") != 0)
			return FALSE;

		/* socket listen { .. } */
		ctx->old->socket_listen_section++;
		return TRUE;
	}

	if (ctx->old->socket_listen_section > 0)
		ctx->old->socket_listen_section++;
	if ((strcmp(key, "master") == 0 || strcmp(key, "client") == 0) &&
	    ctx->old->socket_listen_section == 2) {
		ctx->old->socket_set.master = strcmp(key, "master") == 0;
		return TRUE;
	}
	return FALSE;
}

static bool old_namespace(struct config_parser_context *ctx,
			  const char *value)
{
	if (strcmp(value, "private") != 0 &&
	    strcmp(value, "shared") != 0 &&
	    strcmp(value, "public") != 0)
		return FALSE;

	obsolete(ctx, "namespace %s {} has been replaced by namespace { type=%s }", value, value);
	config_parser_apply_line(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN, "namespace", "");
	config_parser_apply_line(ctx, CONFIG_LINE_TYPE_KEYVALUE,
				 "type", value);
	return TRUE;
}

static void socket_apply(struct config_parser_context *ctx)
{
	const struct socket_set *set = &ctx->old->socket_set;
	const char *path, *prefix;
	unsigned int len;
	bool master_suffix;

	if (set->path == NULL) {
		ctx->error = "socket listen {} is missing path";
		return;
	}
	path = set->path;
	len = strlen(ctx->old->base_dir);
	if (strncmp(path, ctx->old->base_dir, len) == 0 &&
	    path[len] == '/')
		path += len + 1;

	len = strlen(path);
	master_suffix = len >= 7 &&
		(strcmp(path + len - 7, "-master") == 0 ||
		 strcmp(path + len - 7, "-userdb") == 0);

	if (set->master && !master_suffix) {
		ctx->error = "socket listen { master { path=.. } } must end with -master (or -userdb) suffix";
		return;
	} else if (!set->master && master_suffix) {
		ctx->error = "socket listen { client { path=.. } } must end not with -master or -userdb suffix";
		return;
	}

	config_apply_line(ctx, "unix_listener",
		t_strdup_printf("service/auth/unix_listener=%s", settings_section_escape(path)), path);
	prefix = t_strdup_printf("service/auth/unix_listener/%s", settings_section_escape(path));
	if (set->mode != NULL) {
		config_apply_line(ctx, "mode",
			  t_strdup_printf("%s/mode=%s", prefix, set->mode), NULL);
	}
	if (set->user != NULL) {
		config_apply_line(ctx, "user",
			  t_strdup_printf("%s/user=%s", prefix, set->user), NULL);
	}
	if (set->group != NULL) {
		config_apply_line(ctx, "group",
			  t_strdup_printf("%s/group=%s", prefix, set->group), NULL);
	}
	memset(&ctx->old->socket_set, 0, sizeof(ctx->old->socket_set));
}

bool old_settings_handle(struct config_parser_context *ctx,
			 enum config_line_type type,
			 const char *key, const char *value)
{
	switch (type) {
	case CONFIG_LINE_TYPE_SKIP:
	case CONFIG_LINE_TYPE_ERROR:
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		break;
	case CONFIG_LINE_TYPE_KEYVALUE:
		if (ctx->pathlen == 0) {
			struct config_section_stack *old_section =
				ctx->cur_section;
			bool ret;

			ret = old_settings_handle_proto(ctx, key, value);
			ctx->cur_section = old_section;
			if (ret)
				return TRUE;

			return old_settings_handle_root(ctx, key, value);
		}
		break;
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
		if (ctx->old->auth_section > 0)
			return old_auth_section(ctx, key, value);
		else if (ctx->pathlen == 0 && strcmp(key, "auth") == 0) {
			obsolete(ctx, "add auth_ prefix to all settings inside auth {} and remove the auth {} section completely");
			ctx->old->auth_section = 1;
			return TRUE;
		} else if (ctx->pathlen == 0 && strcmp(key, "namespace") == 0)
			return old_namespace(ctx, value);
		else if (ctx->pathlen == 0 && strcmp(key, "protocol") == 0 &&
			 strcmp(value, "managesieve") == 0) {
			obsolete(ctx, "protocol managesieve {} has been replaced by protocol sieve { }");
			config_parser_apply_line(ctx, CONFIG_LINE_TYPE_SECTION_BEGIN,
						 "protocol", "sieve");
			return TRUE;
		}
		break;
	case CONFIG_LINE_TYPE_SECTION_END:
		if (ctx->old->auth_section > 0) {
			if (--ctx->old->auth_section == 0)
				return TRUE;
		}
		if (ctx->old->socket_listen_section > 0) {
			if (ctx->old->socket_listen_section == 2)
				socket_apply(ctx);
			ctx->old->socket_listen_section--;
			return TRUE;
		}
		break;
	}
	return FALSE;
}

void old_settings_init(struct config_parser_context *ctx)
{
	ctx->old = p_new(ctx->pool, struct old_set_parser, 1);
	ctx->old->base_dir = PKG_RUNDIR;
}
