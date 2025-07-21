/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "array.h"
#include "execv-const.h"
#include "child-wait.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "iostream-rawlog.h"
#include "write-full.h"
#include "str.h"
#include "strescape.h"
#include "str-parse.h"
#include "env-util.h"
#include "var-expand.h"
#include "process-title.h"
#include "settings.h"
#include "imap-util.h"
#include "master-interface.h"
#include "master-service.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "doveadm-print.h"
#include "client-connection.h"
#include "doveadm-client.h"
#include "dsync/dsync-brain.h"
#include "dsync/dsync-ibc.h"
#include "doveadm-dsync.h"
#include "module-dir.h"

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/wait.h>

#define DSYNC_REMOTE_CMD_EXIT_WAIT_SECS 30
/* The default vname_escape_char to use unless overridden by
   mailbox_list_visible_escape_char setting. Note that it's only used for
   internal dsync names, so it won't end up in permanent storage names. The
   only requirement for it is that it's not the same as the hierarchy
   separator. */
#define DSYNC_LIST_VNAME_ESCAPE_CHAR '%'
/* In case DSYNC_LIST_VNAME_ESCAPE_CHAR is the hierarchy separator,
   use this instead. */
#define DSYNC_LIST_VNAME_ALT_ESCAPE_CHAR '~'

#define DSYNC_DEFAULT_IO_STREAM_TIMEOUT_SECS (60*10)


struct dsync_module_hooks {
	const struct module *module;
	const struct dsync_hooks *hooks;
};

static ARRAY(struct dsync_module_hooks) module_hooks = ARRAY_INIT;


void dsync_hooks_add(const struct module *module,
                     const struct dsync_hooks *hooks)
{
	struct dsync_module_hooks new_hook;

	i_zero(&new_hook);
	new_hook.module = module;
	new_hook.hooks = hooks;

	/* allow adding hooks before dsync_hooks_init() */
	if (!array_is_created(&module_hooks)) {
		i_array_init(&module_hooks, 8);
        }
	array_push_back(&module_hooks, &new_hook);
}

void dsync_hooks_remove(const struct dsync_hooks *hooks)
{
	const struct dsync_module_hooks *module_hook;
	unsigned int idx = UINT_MAX;

	array_foreach(&module_hooks, module_hook) {
		if (module_hook->hooks == hooks) {
			idx = array_foreach_idx(&module_hooks, module_hook);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&module_hooks, idx, 1);
}

static int
dsync_module_hooks_cmp(const struct dsync_module_hooks *h1,
                       const struct dsync_module_hooks *h2)
{
	const char *s1 = h1->module->path, *s2 = h2->module->path;
	const char *p;

	p = strrchr(s1, '/');
	if (p != NULL) s1 = p+1;
	p = strrchr(s2, '/');
	if (p != NULL) s2 = p+1;

	(void)str_begins(s1, "lib", &s1);
	(void)str_begins(s2, "lib", &s2);

	return strcmp(s1, s2);
}

void dsync_hooks_alloc(struct dsync_cmd_context *ctx);
void dsync_hooks_alloc(struct dsync_cmd_context *ctx) {
	const struct dsync_module_hooks *module_hook;
	ARRAY(const struct dsync_module_hooks) sorted_hooks;
        struct dsync_module_context *hctx;

	/* first get all hooks */
	t_array_init(&sorted_hooks, array_count(&module_hooks));
	array_foreach(&module_hooks, module_hook) {
		array_push_back(&sorted_hooks, module_hook);
	}
	/* next we have to sort them by the modules' priority (based on name) */
	array_sort(&sorted_hooks, dsync_module_hooks_cmp);

	p_array_init(&ctx->hooks, ctx->ctx.pool, array_count(&sorted_hooks));
	array_foreach(&sorted_hooks, module_hook) {
		hctx = p_new(ctx->ctx.pool, struct dsync_module_context, 1);
                i_zero(hctx);
                hctx->module_hooks = module_hook;
                if (module_hook->hooks->alloc != NULL) {
                        hctx->ctx = module_hook->hooks->alloc(ctx);
                }
		array_push_back(&ctx->hooks, &hctx);
	}
}

void dsync_hooks_deinit(struct dsync_cmd_context *ctx);
void dsync_hooks_deinit(struct dsync_cmd_context *ctx)
{
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->deinit == NULL)
                        continue;
                T_BEGIN {
                        hooks->deinit((*hctx)->ctx, ctx);
                        (*hctx)->ctx = NULL;
		} T_END;
	}

	/* allow calling this even if dsync_hooks_add() hasn't been called */
	if (array_is_created(&module_hooks)) {
		array_free(&module_hooks);
        }
}

void hook_init(struct dsync_cmd_context *ctx);
void hook_init(struct dsync_cmd_context *ctx) {
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->init == NULL)
                        continue;
                T_BEGIN {
                        hooks->init((*hctx)->ctx, ctx);
		} T_END;
	}
}

bool hook_connected_callback(struct dsync_cmd_context *ctx,
                             const struct doveadm_server_reply *reply);
bool hook_connected_callback(struct dsync_cmd_context *ctx,
                             const struct doveadm_server_reply *reply)
{
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;
        bool result;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->connected_callback == NULL)
                        continue;
                T_BEGIN {
                        if (hooks->connected_callback((*hctx)->ctx, ctx, reply)) {
                                result = TRUE;
                        }
		} T_END;
	}
        return result;
}

int hook_run_pre(struct dsync_cmd_context *ctx, struct mail_user *user);
int hook_run_pre(struct dsync_cmd_context *ctx, struct mail_user *user)
{
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;
        int ret = 0;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->run_pre == NULL)
                        continue;
                T_BEGIN {
                        ret = hooks->run_pre((*hctx)->ctx, ctx, user);
		} T_END;
                if (ret < 0) {
                        e_info(ctx->ctx.cctx->event,
                               "hook_run_pre(): returning %d for \"%s\"",
                               ret, (*hctx)->module_hooks->module->name);
                        return ret;
                }
	}
        return ret;
}

void hook_server_init(struct dsync_cmd_context *ctx);
void hook_server_init(struct dsync_cmd_context *ctx) {
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->server_init == NULL)
                        continue;
                T_BEGIN {
                        hooks->server_init((*hctx)->ctx, ctx);
		} T_END;
	}
}

int hook_server_run_pre(struct dsync_cmd_context *ctx, struct mail_user *user);
int hook_server_run_pre(struct dsync_cmd_context *ctx, struct mail_user *user)
{
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;
        int ret = 0;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->server_run_pre == NULL)
                        continue;
                T_BEGIN {
                        ret = hooks->server_run_pre((*hctx)->ctx, ctx, user);
		} T_END;
                if (ret < 0) {
                        return ret;
                }
	}
        return ret;
}

void hook_server_run_command(struct dsync_cmd_context *ctx,
                             struct doveadm_client *conn,
                             string_t *cmd);
void hook_server_run_command(struct dsync_cmd_context *ctx,
                             struct doveadm_client *conn,
                             string_t *cmd) {
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->server_run_command == NULL)
                        continue;
                T_BEGIN {
                        hooks->server_run_command((*hctx)->ctx, ctx, conn, cmd);
		} T_END;
	}
}

void hook_server_run_post(struct dsync_cmd_context *ctx,
                          struct mail_user *user,
                          struct dsync_ibc *ibc,
                          struct dsync_brain *brain);
void hook_server_run_post(struct dsync_cmd_context *ctx,
                          struct mail_user *user,
                          struct dsync_ibc *ibc,
                          struct dsync_brain *brain) {
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->server_run_post == NULL)
                        continue;
                T_BEGIN {
                        hooks->server_run_post((*hctx)->ctx, ctx, user, ibc, brain);
		} T_END;
	}
}

void hook_server_run_end(struct dsync_cmd_context *ctx,
                         struct mail_user *user);
void hook_server_run_end(struct dsync_cmd_context *ctx,
                         struct mail_user *user) {
        struct dsync_module_context **hctx;
        const struct dsync_hooks *hooks;

	array_foreach_modifiable(&ctx->hooks, hctx) {
                hooks = (*hctx)->module_hooks->hooks;
		if (hooks->server_run_end == NULL)
                        continue;
                T_BEGIN {
                        hooks->server_run_end((*hctx)->ctx, ctx, user);
		} T_END;
	}
}

static void dsync_cmd_switch_ioloop_to(struct dsync_cmd_context *ctx,
				       struct ioloop *ioloop)
{
	if (ctx->input != NULL)
		i_stream_switch_ioloop_to(ctx->input, ioloop);
	if (ctx->output != NULL)
		o_stream_switch_ioloop_to(ctx->output, ioloop);
}

static void remote_error_input(struct dsync_cmd_context *ctx)
{
	const unsigned char *data;
	size_t size;
	const char *line;

	switch (i_stream_read(ctx->err_stream)) {
	case -2:
		data = i_stream_get_data(ctx->err_stream, &size);
		if (ctx->err_prefix == NULL)
			fprintf(stderr, "%.*s", (int)size, data);
		else {
			if (!ctx->err_line_continues) {
				(void)doveadm_log_type_from_char(data[0],
					&ctx->failure_ctx.type);
				data++; size--;
			}
			i_log_type(&ctx->failure_ctx, "%s%.*s", ctx->err_prefix,
				   (int)size, data);
			ctx->err_line_continues = TRUE;
		}
		i_stream_skip(ctx->err_stream, size);
		break;
	case -1:
		io_remove(&ctx->io_err);
		break;
	default:
		while ((line = i_stream_next_line(ctx->err_stream)) != NULL) {
			if (ctx->err_prefix == NULL) {
				/* forward captured stderr lines */
				fprintf(stderr, "%s\n", line);
			} else {
				/* Input from remote dsync. The first character
				   should be the logging type. */
				if (!ctx->err_line_continues) {
					(void)doveadm_log_type_from_char(line[0],
						&ctx->failure_ctx.type);
					line++;
				}
				i_log_type(&ctx->failure_ctx, "%s%s",
					   ctx->err_prefix, line);
				ctx->err_line_continues = FALSE;
			}
		}
		break;
	}
}

static void
run_cmd(struct dsync_cmd_context *ctx, const char *const *args)
{
	struct doveadm_cmd_context *cctx = ctx->ctx.cctx;
	int fd_in[2], fd_out[2], fd_err[2];

	ctx->remote_cmd_args = p_strarray_dup(ctx->ctx.pool, args);

	if (pipe(fd_in) < 0 || pipe(fd_out) < 0 || pipe(fd_err) < 0)
		i_fatal("pipe() failed: %m");

	ctx->remote_pid = fork();
	switch (ctx->remote_pid) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child, which will execute the proxy server. stdin/stdout
		   goes to pipes which we'll pass to proxy client. */
		if (dup2(fd_in[0], STDIN_FILENO) < 0 ||
		    dup2(fd_out[1], STDOUT_FILENO) < 0 ||
		    dup2(fd_err[1], STDERR_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		/* If doveadm is executed locally, use the already parsed
		   configuration. This also means that the dsync-server will
		   use the same configuration as the main process without
		   having to provide the same -c (etc.) parameters. */
		int config_fd = doveadm_settings_get_config_fd();
		fd_close_on_exec(config_fd, FALSE);
		env_put(DOVECOT_CONFIG_FD_ENV, dec2str(config_fd));

		i_close_fd(&fd_in[0]);
		i_close_fd(&fd_in[1]);
		i_close_fd(&fd_out[0]);
		i_close_fd(&fd_out[1]);
		i_close_fd(&fd_err[0]);
		i_close_fd(&fd_err[1]);

		execvp_const(args[0], args);
	default:
		/* parent */
		break;
	}

	i_close_fd(&fd_in[0]);
	i_close_fd(&fd_out[1]);
	i_close_fd(&fd_err[1]);
	ctx->fd_in = fd_out[0];
	ctx->fd_out = fd_in[1];
	ctx->fd_err = fd_err[0];

	if (ctx->remote_user_prefix) {
		const char *prefix =
			t_strdup_printf("%s\n", cctx->username);
		if (write_full(ctx->fd_out, prefix, strlen(prefix)) < 0)
			i_fatal("write(remote out) failed: %m");
	}

	fd_set_nonblock(ctx->fd_err, TRUE);
	ctx->err_stream = i_stream_create_fd(ctx->fd_err, IO_BLOCK_SIZE);
	i_stream_set_return_partial_line(ctx->err_stream, TRUE);
}

static void
mirror_get_remote_cmd_line(const char *const *argv,
			   const char *const **cmd_args_r)
{
	ARRAY_TYPE(const_string) cmd_args;
	unsigned int i;
	const char *p;

	i_assert(argv[0] != NULL);

	t_array_init(&cmd_args, 16);
	for (i = 0; argv[i] != NULL; i++) {
		p = argv[i];
		array_push_back(&cmd_args, &p);
	}

	if (i > 0 && strcmp(argv[i-1], "dsync-server") == 0) {
		/* Caller already specified dsync-server in parameters.
		   This is a common misconfiguration, so just allow it. */
		p = NULL;
	} else {
		/* we're executing doveadm */
		p = "dsync-server";
	}
	if (p != NULL)
		array_push_back(&cmd_args, &p);
	array_append_zero(&cmd_args);
	*cmd_args_r = array_front(&cmd_args);
}

static const char *const *
get_ssh_cmd_args(const char *host, const char *login, const char *mail_user,
		 struct event *event)
{
	static const struct var_expand_table static_tab[] = {
		{ .key = "user", .value = NULL },
		{ .key = "login", .value = NULL },
		{ .key = "host", .value = NULL },
		VAR_EXPAND_TABLE_END
	};
	static const struct var_expand_params static_params = {
		.table = static_tab
	};
	struct var_expand_table *tab;
	ARRAY_TYPE(const_string) cmd_args;
	string_t *str, *str2;
	const char *value, *const *args, *error;

	tab = t_malloc_no0(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = mail_user;
	tab[1].value = login;
	tab[2].value = host;
	const struct var_expand_params params = {
		.table = tab,
		.event = event,
	};

	t_array_init(&cmd_args, 8);
	str = t_str_new(128);
	str2 = t_str_new(128);
	args = t_strsplit(doveadm_settings->dsync_remote_cmd, " ");
	for (; *args != NULL; args++) {
		if (strchr(*args, '%') == NULL)
			value = *args;
		else {
			/* some automation: if parameter's all %{variables}
			   expand to empty, but the %{variable} isn't the only
			   text in the parameter, skip it. */
			str_truncate(str, 0);
			str_truncate(str2, 0);
			if (var_expand(str, *args, &params, &error) < 0 ||
			    var_expand(str2, *args, &static_params, &error) < 0) {
				e_error(event,
					"Failed to expand dsync_remote_cmd=%s: %s",
					*args, error);
			}
			if (strcmp(str_c(str), str_c(str2)) == 0 &&
			    str_len(str) > 0)
				continue;
			value = t_strdup(str_c(str));
		}
		array_push_back(&cmd_args, &value);
	}
	array_append_zero(&cmd_args);
	return array_front(&cmd_args);
}

static bool mirror_get_remote_cmd(struct dsync_cmd_context *ctx,
				  const char *user,
				  struct event *event,
				  const char *const **cmd_args_r)
{
	const char *p, *host, *const *argv = ctx->destination;

	if (argv[1] != NULL) {
		/* more than one parameter, so it contains a full command
		   (e.g. ssh host dsync) */
		mirror_get_remote_cmd_line(argv, cmd_args_r);
		return TRUE;
	}

	/* if it begins with /[a-z0-9]+:/, it's a mail location
	   (e.g. mdbox:~/mail) */
	for (p = argv[0]; *p != '\0'; p++) {
		if (!i_isalnum(*p)) {
			if (*p == ':')
				return FALSE;
			break;
		}
	}

	if (strchr(argv[0], ' ') != NULL || strchr(argv[0], '/') != NULL) {
		/* a) the whole command is in one string. this is mainly for
		      backwards compatibility.
		   b) script/path */
		mirror_get_remote_cmd_line(t_strsplit(argv[0], " "),
					   cmd_args_r);
		return TRUE;
	}

	/* [user@]host */
	host = strchr(argv[0], '@');
	if (host != NULL)
		user = t_strdup_until(argv[0], host++);
	else
		host = argv[0];

	/* we'll assume virtual users, so in user@host it really means not to
	   give ssh a username, but to give dsync -u user parameter. */
	*cmd_args_r = get_ssh_cmd_args(host, "", user, event);
	return TRUE;
}

static void
doveadm_update_escape_char(struct mail_namespace *ns, char ns_sep)
{
	const struct mail_storage_settings *old_set = ns->list->mail_set;
	struct mail_storage_settings *new_set =
		p_memdup(old_set->pool, old_set, sizeof(*old_set));
	new_set->mailbox_list_visible_escape_char =
		p_strdup_printf(old_set->pool, "%c", ns_sep);
	ns->list->mail_set = new_set;
}

static void doveadm_user_init_dsync(struct mail_user *user)
{
	struct mail_namespace *ns;
	char ns_sep = mail_namespaces_get_root_sep(user->namespaces);

	user->dsyncing = TRUE;
	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		struct dsync_mailbox_list *dlist =
			p_new(ns->list->pool, struct dsync_mailbox_list, 1);
		MODULE_CONTEXT_SET(ns->list, dsync_mailbox_list_module, dlist);

		if (ns->list->mail_set->mailbox_list_visible_escape_char[0] == '\0') {
			doveadm_update_escape_char(ns,
				ns_sep != DSYNC_LIST_VNAME_ESCAPE_CHAR ?
				DSYNC_LIST_VNAME_ESCAPE_CHAR :
				DSYNC_LIST_VNAME_ALT_ESCAPE_CHAR);
		} else {
			dlist->have_orig_escape_char = TRUE;
		}
	}
}

static bool
paths_are_equal(struct mail_namespace *ns1, struct mail_namespace *ns2,
		enum mailbox_list_path_type type)
{
	const char *path1, *path2;

	return mailbox_list_get_root_path(ns1->list, type, &path1) &&
		mailbox_list_get_root_path(ns2->list, type, &path2) &&
		strcmp(path1, path2) == 0;
}

static int
get_dsync_verify_namespace(struct dsync_cmd_context *ctx,
			   struct mail_user *user, struct mail_namespace **ns_r)
{
	struct mail_namespace *ns;

	/* Use the first -n namespace if given */
	if (array_count(&ctx->namespace_prefixes) > 0) {
		const char *prefix =
			array_idx_elem(&ctx->namespace_prefixes, 0);
		ns = mail_namespace_find(user->namespaces, prefix);
		if (ns == NULL) {
			e_error(ctx->ctx.cctx->event,
				"Namespace not found: '%s'", prefix);
			ctx->ctx.exit_code = DOVEADM_EX_NOTFOUND;
			return -1;
		}
		*ns_r = ns;
		return 0;
	}

	/* Prefer prefix="" namespace over inbox=yes namespace. Either it uses
	   the global mail_path, which is good, or it might have
	   overwritten location in case of e.g. using subscriptions file for
	   all namespaces. This isn't necessarily obvious, so lets make it
	   clearer by failing if it happens. */
	if ((user->namespaces->flags & NAMESPACE_FLAG_UNUSABLE) == 0) {
		*ns_r = user->namespaces;
		i_assert((*ns_r)->prefix_len == 0);
	} else {
		/* fallback to inbox=yes */
		*ns_r = mail_namespace_find_inbox(user->namespaces);
	}
	return 0;
}

static int
cmd_dsync_run_local(struct dsync_cmd_context *ctx, struct mail_user *user,
		    struct dsync_brain *brain, struct dsync_ibc *ibc2,
		    const char **changes_during_sync_r,
		    enum mail_error *mail_error_r)
{
	struct dsync_brain *brain2;
	struct mail_user *user2;
	struct mail_namespace *ns, *ns2;
	const char *mail_driver, *mail_path, *error;
	bool brain1_running, brain2_running, changed1, changed2;
	bool remote_only_changes;
	int ret;

	*mail_error_r = 0;

	mail_path = strchr(ctx->destination[0], ':');
	if (mail_path == NULL || strchr(mail_path + 1, ':') != NULL) {
		e_error(ctx->ctx.cctx->event,
			"Destination should be in mail_driver:mail_path syntax");
		ctx->ctx.exit_code = EX_USAGE;
		return -1;
	}
	mail_driver = t_strdup_until(ctx->destination[0], mail_path++);

	i_set_failure_prefix("dsync(%s): ", user->username);

	/* Create another user for the second location with its own
	   storage settings. Override only the defaults, while preserving any
	   namespace-specific settings. The service user needs to be duplicated
	   also to avoid updating the first user's settings. */
	struct mail_storage_service_user *service_user2 =
		mail_storage_service_user_dup(ctx->ctx.cur_service_user);
	struct settings_instance *set_instance =
		mail_storage_service_user_get_settings_instance(service_user2);
	mail_storage_2nd_settings_reset(set_instance, "");
	for (unsigned int i = 0; ctx->destination_options[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(ctx->destination_options[i], &key, &value);
		settings_override(set_instance, key, value,
				  SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM);
	}
	settings_override(set_instance, "mail_driver", mail_driver,
			  SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM);
	settings_override(set_instance, "mail_path", mail_path,
			  SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM);

	ret = mail_storage_service_next(ctx->ctx.storage_service, service_user2,
					&user2, &error);
	mail_storage_service_user_unref(&service_user2);
	if (ret < 0) {
		e_error(ctx->ctx.cctx->event,
			"Failed to initialize user: %s", error);
		ctx->ctx.exit_code = ret == -1 ? EX_TEMPFAIL : EX_CONFIG;
		return -1;
	}
	doveadm_user_init_dsync(user2);

	if (get_dsync_verify_namespace(ctx, user, &ns) < 0 ||
	    get_dsync_verify_namespace(ctx, user2, &ns2) < 0)
		return -1;
	if (mail_namespace_get_sep(ns) != mail_namespace_get_sep(ns2)) {
		e_error(ctx->ctx.cctx->event,
			"Mail locations must use the same hierarchy separator "
			"(specify namespace %s { separator=%c } != "
			"namespace %s { separator=%c })",
			ns->set->name, mail_namespace_get_sep(ns),
			ns2->set->name, mail_namespace_get_sep(ns2));
		ctx->ctx.exit_code = EX_CONFIG;
		mail_user_deinit(&user2);
		return -1;
	}
	if (paths_are_equal(ns, ns2, MAILBOX_LIST_PATH_TYPE_MAILBOX) &&
	    paths_are_equal(ns, ns2, MAILBOX_LIST_PATH_TYPE_INDEX)) {
		e_error(ctx->ctx.cctx->event,
			"Both source and destination mail_path and mail_index_path "
			"point to same directory: %s (namespace %s "
			"{ mail_path } is set explicitly?)",
			mailbox_list_get_root_forced(user->namespaces->list,
						     MAILBOX_LIST_PATH_TYPE_MAILBOX),
			ns->set->name);
		ctx->ctx.exit_code = EX_CONFIG;
		mail_user_deinit(&user2);
		return -1;
	}

	brain2 = dsync_brain_slave_init(user2, ibc2, TRUE, "",
					doveadm_settings->dsync_alt_char[0],
					doveadm_settings->dsync_commit_msgs_interval);
	mail_user_unref(&user2);

	brain1_running = brain2_running = TRUE;
	changed1 = changed2 = TRUE;
	while (brain1_running || brain2_running) {
		if (dsync_brain_has_failed(brain) ||
		    dsync_brain_has_failed(brain2))
			break;
		if (doveadm_is_killed())
			break;

		i_assert(changed1 || changed2);
		brain1_running = dsync_brain_run(brain, &changed1);
		brain2_running = dsync_brain_run(brain2, &changed2);
	}
	*changes_during_sync_r = t_strdup(dsync_brain_get_unexpected_changes_reason(brain2, &remote_only_changes));
	if (dsync_brain_deinit(&brain2, mail_error_r) < 0)
		return -1;
	return doveadm_is_killed() ? -1 : 0;
}

static void cmd_dsync_remote_exited(const struct child_wait_status *status,
				    struct dsync_cmd_context *ctx)
{
	ctx->exited = TRUE;
	ctx->exit_status = status->status;
	io_loop_stop(current_ioloop);
}

static void cmd_dsync_wait_remote(struct dsync_cmd_context *ctx)
{
	struct timeout *to;

	/* wait in ioloop for the remote process to die. while we're running
	   we're also reading and printing all errors that still coming from
	   it. */
	to = timeout_add(DSYNC_REMOTE_CMD_EXIT_WAIT_SECS*1000,
			 io_loop_stop, current_ioloop);
	io_loop_run(current_ioloop);
	timeout_remove(&to);

	/* io_loop_run() deactivates the context - put it back */
	mail_storage_service_io_activate_user(ctx->ctx.cur_service_user);

	if (!ctx->exited) {
		e_error(ctx->ctx.cctx->event,
			"Remote command process isn't dying, killing it");
		if (kill(ctx->remote_pid, SIGKILL) < 0 && errno != ESRCH) {
			e_error(ctx->ctx.cctx->event,
				"kill(%ld, SIGKILL) failed: %m",
				(long)ctx->remote_pid);
		}
	}
}

static void cmd_dsync_log_remote_status(int status, bool remote_errors_logged,
					const char *const *remote_cmd_args,
					struct event *event)
{
	if (status == -1)
		;
	else if (WIFSIGNALED(status)) {
		e_error(event,
			"Remote command died with signal %d: %s",
			WTERMSIG(status),
			t_strarray_join(remote_cmd_args, " "));
	} else if (!WIFEXITED(status)) {
		e_error(event,
			"Remote command failed with status %d: %s", status,
			t_strarray_join(remote_cmd_args, " "));
	} else if (WEXITSTATUS(status) == EX_TEMPFAIL && remote_errors_logged) {
		/* remote most likely already logged the error.
		   don't bother logging another line about it */
	} else if (WEXITSTATUS(status) != 0) {
		e_error(event,
			"Remote command returned error %d: %s",
			WEXITSTATUS(status),
			t_strarray_join(remote_cmd_args, " "));
	}
}

static void cmd_dsync_run_remote(struct mail_user *user)
{
	i_set_failure_prefix("dsync-local(%s)<%s>: ", user->username, user->session_id);
	io_loop_run(current_ioloop);
}

static const char *const *
parse_ssh_location(const char *location, const char *username, struct event *event)
{
	const char *host, *login;

	host = strrchr(location, '@');
	if (host != NULL)
		login = t_strdup_until(location, host++);
	else {
		host = location;
		login = "";
	}
	return get_ssh_cmd_args(host, login, username, event);
}

static struct dsync_ibc *
cmd_dsync_ibc_stream_init(struct dsync_cmd_context *ctx,
			  const char *name, const char *temp_prefix)
{
	if (ctx->input == NULL) {
		fd_set_nonblock(ctx->fd_in, TRUE);
		fd_set_nonblock(ctx->fd_out, TRUE);
		ctx->input = i_stream_create_fd(ctx->fd_in, SIZE_MAX);
		ctx->output = o_stream_create_fd(ctx->fd_out, SIZE_MAX);
	} else {
		i_assert(ctx->fd_in == -1 && ctx->fd_out == -1);
		ctx->fd_in = i_stream_get_fd(ctx->input);
		ctx->fd_out = o_stream_get_fd(ctx->output);
		ctx->input_orig_bufsize = i_stream_get_max_buffer_size(ctx->input);
		ctx->output_orig_bufsize = o_stream_get_max_buffer_size(ctx->output);
		i_stream_set_max_buffer_size(ctx->input, SIZE_MAX);
		o_stream_set_max_buffer_size(ctx->output, SIZE_MAX);
	}
	if (ctx->rawlog_path != NULL) {
		iostream_rawlog_create_path(ctx->rawlog_path,
					    &ctx->input, &ctx->output);
	}
	return dsync_ibc_init_stream(ctx->input, ctx->output,
				     name, temp_prefix, ctx->io_timeout_secs);
}

static void dsync_errors_finish(struct dsync_cmd_context *ctx)
{
	if (ctx->err_stream == NULL)
		return;

	remote_error_input(ctx);
	bool remote_errors_logged = ctx->err_stream->v_offset > 0;
	i_stream_destroy(&ctx->err_stream);
	cmd_dsync_log_remote_status(ctx->exit_status, remote_errors_logged,
				    ctx->remote_cmd_args, ctx->ctx.cctx->event);
	io_remove(&ctx->io_err);
	i_close_fd(&ctx->fd_err);
}

static int
cmd_dsync_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	struct dsync_ibc *ibc, *ibc2 = NULL;
	struct dsync_brain *brain;
	struct dsync_brain_settings set;
	struct mail_namespace *ns;
	const char *const *strp;
	enum dsync_brain_flags brain_flags;
	enum mail_error mail_error = 0, mail_error2;
	const char *changes_during_sync, *changes_during_sync2 = NULL;
	bool remote_only_changes;
	int ret = 0;

        ret = hook_run_pre(ctx, user);
        if (ret < 0) {
                return ret;
        }

	i_zero(&set);
	if (cctx->remote_ip.family != 0) {
		/* include the doveadm client's IP address in the ps output */
		set.process_title_prefix = t_strdup_printf(
			"%s ", net_ip2addr(&cctx->remote_ip));
	}
	set.sync_since_timestamp = ctx->sync_since_timestamp;
	set.sync_until_timestamp = ctx->sync_until_timestamp;

	if (set.sync_since_timestamp > 0 && set.sync_until_timestamp > 0 &&
	    set.sync_since_timestamp > set.sync_until_timestamp) {
		i_fatal("start date is later than end date");
	}

	set.sync_max_size = ctx->sync_max_size;
	set.sync_box = ctx->mailbox;
	set.sync_flag = ctx->sync_flags;
	set.virtual_all_box = ctx->virtual_all_box;
	memcpy(set.sync_box_guid, ctx->mailbox_guid, sizeof(set.sync_box_guid));
	set.lock_timeout_secs = ctx->lock_timeout;
	set.import_commit_msgs_interval = ctx->import_commit_msgs_interval;
	set.state = ctx->state_input;
	set.mailbox_alt_char = doveadm_settings->dsync_alt_char[0];
	if (*doveadm_settings->dsync_hashed_headers == '\0') {
		e_error(cctx->event, "dsync_hashed_headers must not be empty");
		ctx->ctx.exit_code = EX_USAGE;
		return -1;
	}
	set.hashed_headers =
		t_strsplit_spaces(doveadm_settings->dsync_hashed_headers, " ,");
	if (array_count(&ctx->exclude_mailboxes) > 0) {
		/* array is NULL-terminated in init() */
		set.exclude_mailboxes = array_front(&ctx->exclude_mailboxes);
	}
	doveadm_user_init_dsync(user);

	t_array_init(&set.sync_namespaces, array_count(&ctx->namespace_prefixes));
	array_foreach(&ctx->namespace_prefixes, strp) {
		ns = mail_namespace_find(user->namespaces, *strp);
		if (ns == NULL) {
			e_error(cctx->event, "Namespace not found: '%s'", *strp);
			ctx->ctx.exit_code = EX_USAGE;
			return -1;
		}
		array_push_back(&set.sync_namespaces, &ns);
	}

	if (ctx->run_type == DSYNC_RUN_TYPE_LOCAL)
		dsync_ibc_init_pipe(&ibc, &ibc2);
	else {
		string_t *temp_prefix = t_str_new(64);
		mail_user_set_get_temp_prefix(temp_prefix, user->set);
		ibc = cmd_dsync_ibc_stream_init(ctx, ctx->remote_name,
						str_c(temp_prefix));
		if (ctx->err_stream != NULL) {
			ctx->io_err = io_add_istream(ctx->err_stream,
						     remote_error_input, ctx);
		}
	}

	brain_flags = DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS;
	if (ctx->sync_visible_namespaces)
		brain_flags |= DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES;
	if (ctx->purge_remote)
		brain_flags |= DSYNC_BRAIN_FLAG_PURGE_REMOTE;

	if (ctx->backup) {
		if (ctx->reverse_backup)
			brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_RECV;
		else
			brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_SEND;
	}

	if (ctx->no_mail_sync)
		brain_flags |= DSYNC_BRAIN_FLAG_NO_MAIL_SYNC;
	if (ctx->oneway)
		brain_flags |= DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE;
	if (ctx->empty_hdr_workaround)
		brain_flags |= DSYNC_BRAIN_FLAG_EMPTY_HDR_WORKAROUND;
	if (ctx->no_header_hashes)
		brain_flags |= DSYNC_BRAIN_FLAG_NO_HEADER_HASHES;
	if (doveadm_debug)
		brain_flags |= DSYNC_BRAIN_FLAG_DEBUG;

	child_wait_init();
	brain = dsync_brain_master_init(user, ibc, ctx->sync_type,
					brain_flags, &set);

	switch (ctx->run_type) {
	case DSYNC_RUN_TYPE_LOCAL:
		if (cmd_dsync_run_local(ctx, user, brain, ibc2,
					&changes_during_sync2, &mail_error) < 0)
			ret = -1;
		break;
	case DSYNC_RUN_TYPE_CMD:
		ctx->child_wait = child_wait_new_with_pid(ctx->remote_pid,
			cmd_dsync_remote_exited, ctx);
		/* fall through */
	case DSYNC_RUN_TYPE_STREAM:
		cmd_dsync_run_remote(user);
		/* io_loop_run() deactivates the context - put it back */
		mail_storage_service_io_activate_user(ctx->ctx.cur_service_user);
		break;
	}

	if (ctx->state_input != NULL) {
		string_t *state_str = t_str_new(128);
		dsync_brain_get_state(brain, state_str);
		doveadm_print(str_c(state_str));
	}

	changes_during_sync = dsync_brain_get_unexpected_changes_reason(brain, &remote_only_changes);
	if (changes_during_sync != NULL || changes_during_sync2 != NULL) {
		/* don't log a warning when running via doveadm server */
		const char *msg = t_strdup_printf(
			"Mailbox changes caused a desync. "
			"You may want to run dsync again: %s",
			changes_during_sync == NULL ||
			(remote_only_changes && changes_during_sync2 != NULL) ?
			changes_during_sync2 : changes_during_sync);
		if (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI)
			e_warning(cctx->event, "%s", msg);
		else
			e_debug(cctx->event, "%s", msg);
		ctx->ctx.exit_code = DOVEADM_EX_CHANGED;
	}
	if (dsync_brain_deinit(&brain, &mail_error2) < 0)
		ret = -1;
	if (ret < 0) {
		/* tempfail is the default error. prefer to use a non-tempfail
		   if that exists. */
		if (mail_error2 != 0 &&
		    (mail_error == 0 || mail_error == MAIL_ERROR_TEMP))
			mail_error = mail_error2;
		doveadm_mail_failed_error(&ctx->ctx, mail_error);
	}
	dsync_ibc_deinit(&ibc);
	if (ibc2 != NULL)
		dsync_ibc_deinit(&ibc2);
	if (ctx->run_type != DSYNC_RUN_TYPE_CMD)
		dsync_errors_finish(ctx);
	ssl_iostream_destroy(&ctx->ssl_iostream);
	if (ctx->input != NULL) {
		i_stream_set_max_buffer_size(ctx->input, ctx->input_orig_bufsize);
		i_stream_unref(&ctx->input);
	}
	if (ctx->output != NULL) {
		o_stream_set_max_buffer_size(ctx->output, ctx->output_orig_bufsize);
		o_stream_unref(&ctx->output);
	}
	if (ctx->fd_in != -1) {
		if (ctx->fd_out != ctx->fd_in)
			i_close_fd(&ctx->fd_out);
		i_close_fd(&ctx->fd_in);
	}
	/* print any final errors after the process has died. not closing
	   stdin/stdout before wait() may cause the process to hang, but stderr
	   shouldn't (at least with ssh) and we need stderr to be open to be
	   able to print the final errors */
	if (ctx->run_type == DSYNC_RUN_TYPE_CMD)
		cmd_dsync_wait_remote(ctx);
	dsync_errors_finish(ctx);

	if (ctx->child_wait != NULL)
		child_wait_free(&ctx->child_wait);
	child_wait_deinit();
	return ret;
}

static void dsync_connected_callback(const struct doveadm_server_reply *reply,
				     void *context)
{
	struct dsync_cmd_context *ctx = context;

	ctx->ctx.exit_code = reply->exit_code;
	switch (reply->exit_code) {
	case 0:
		doveadm_client_extract(ctx->tcp_conn, &ctx->input,
				       &ctx->err_stream, &ctx->output,
				       &ctx->ssl_iostream);
		ctx->err_prefix = p_strdup_printf(ctx->ctx.pool,
			"dsync-remote(%s): ", ctx->ctx.cctx->username);

		break;
	case DOVEADM_CLIENT_EXIT_CODE_DISCONNECTED:
		ctx->ctx.exit_code = EX_TEMPFAIL;
		ctx->error = p_strdup_printf(ctx->ctx.pool,
			"Disconnected from remote: %s", reply->error);
		break;
	case EX_NOUSER:
		ctx->error = "Unknown user in remote";
		break;
	default:
                if (hook_connected_callback(ctx, reply)) {
                        break;
                }
		ctx->error = p_strdup_printf(ctx->ctx.pool,
			"Failed to start remote dsync-server command: "
			"Remote exit_code=%u %s",
			reply->exit_code, reply->error);
		break;
	}
	io_loop_stop(current_ioloop);
}

static void dsync_server_run_command(struct dsync_cmd_context *ctx,
				     struct doveadm_client *conn)
{
	struct doveadm_cmd_context *cctx = ctx->ctx.cctx;
	/* <flags> <username> <command> [<args>] */
	string_t *cmd = t_str_new(256);
	if (doveadm_debug)
		str_append_c(cmd, DOVEADM_PROTOCOL_CMD_FLAG_DEBUG);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, cctx->username);
	str_append(cmd, "\tdsync-server\t-u");
	str_append_tabescaped(cmd, cctx->username);
        hook_server_run_command(ctx, conn, cmd);
	str_append_c(cmd, '\n');

	ctx->tcp_conn = conn;
	struct doveadm_client_cmd_settings cmd_set = {
		/* dsync command can't be proxied currently, so use TTL 1 */
		.proxy_ttl = 1,
	};
	doveadm_client_cmd(conn, &cmd_set, str_c(cmd), NULL,
			   dsync_connected_callback, ctx);
	io_loop_run(current_ioloop);
	ctx->tcp_conn = NULL;
}

static int
dsync_connect_tcp(struct dsync_cmd_context *ctx,
		  const char *target, bool ssl, const char **error_r)
{
	struct doveadm_client_settings conn_set;
	struct doveadm_client *conn;
	struct ioloop *prev_ioloop, *ioloop;
	const char *p, *error;

	i_zero(&conn_set);
	if (strchr(target, '/') != NULL)
		conn_set.socket_path = target;
	else {
		p = strrchr(target, ':');
		conn_set.hostname = p == NULL ? target :
			p_strdup_until(ctx->ctx.pool, target, p);
		if (p == NULL)
			conn_set.port = doveadm_settings->doveadm_port;
		else if (net_str2port(p+1, &conn_set.port) < 0) {
			*error_r = t_strdup_printf("Invalid port number: %s", p+1);
			return -1;
		}
	}

	if (ssl)
		conn_set.ssl_flags = AUTH_PROXY_SSL_FLAG_YES;
	conn_set.username = ctx->ctx.set->doveadm_username;
	conn_set.password = ctx->ctx.set->doveadm_password;
	conn_set.log_passthrough = TRUE;

	prev_ioloop = current_ioloop;
	ioloop = io_loop_create();
	dsync_cmd_switch_ioloop_to(ctx, ioloop);

	if (doveadm_verbose_proctitle) {
		process_title_set(t_strdup_printf(
			"[dsync - connecting to %s]", target));
	}
	if (doveadm_client_create(&conn_set, &conn, &error) < 0) {
		ctx->error = p_strdup_printf(ctx->ctx.pool,
			"Couldn't create server connection: %s", error);
	} else {
		if (doveadm_verbose_proctitle) {
			process_title_set(t_strdup_printf(
				"[dsync - running dsync-server on %s]", target));
		}

		dsync_server_run_command(ctx, conn);
		doveadm_client_unref(&conn);
	}

	doveadm_clients_destroy_all();

	dsync_cmd_switch_ioloop_to(ctx, prev_ioloop);
	io_loop_destroy(&ioloop);

	if (ctx->error != NULL) {
		*error_r = ctx->error;
		ctx->error = NULL;
		return -1;
	}
	ctx->run_type = DSYNC_RUN_TYPE_STREAM;
	return 0;
}

static int
parse_location(struct dsync_cmd_context *ctx,
	       const char *location,
	       const char *const **remote_cmd_args_r, const char **error_r)
{
	struct doveadm_cmd_context *cctx = ctx->ctx.cctx;

	if (str_begins(location, "tcp:", &ctx->remote_name)) {
		/* TCP connection to remote dsync */
		return dsync_connect_tcp(ctx, ctx->remote_name, FALSE, error_r);
	}
	if (str_begins(location, "tcps:", &ctx->remote_name)) {
		/* TCP+SSL connection to remote dsync */
		return dsync_connect_tcp(ctx, ctx->remote_name, TRUE, error_r);
	}

	if (str_begins(location, "remote:", &ctx->remote_name)) {
		/* this is a remote (ssh) command */
	} else if (str_begins(location, "remoteprefix:", &ctx->remote_name)) {
		/* this is a remote (ssh) command with a "user\n"
		   prefix sent before dsync actually starts */
		ctx->remote_user_prefix = TRUE;
	} else {
		/* local with e.g. maildir:path */
		ctx->remote_name = NULL;
		return 0;
	}
	*remote_cmd_args_r =
		parse_ssh_location(ctx->remote_name, cctx->username, cctx->event);
	return 0;
}

static int
cmd_dsync_prerun(struct doveadm_mail_cmd_context *_ctx,
		 struct mail_storage_service_user *service_user ATTR_UNUSED,
		 const char **error_r)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	const char *const *remote_cmd_args = NULL;
	const char *username = "";

	ctx->fd_in = -1;
	ctx->fd_out = -1;
	ctx->fd_err = -1;
	ctx->run_type = DSYNC_RUN_TYPE_LOCAL;
	ctx->remote_name = "remote";

	/* if we're executing remotely, give -u parameter if we also
	   did a userdb lookup. */
	if ((_ctx->service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0)
		username = cctx->username;

	if (!mirror_get_remote_cmd(ctx, username, cctx->event, &remote_cmd_args)) {
		if (ctx->destination[1] != NULL)
			doveadm_mail_help_name(_ctx->cmd->name);
		if (parse_location(ctx, ctx->destination[0],
				   &remote_cmd_args, error_r) < 0)
			return -1;
	}

	if (remote_cmd_args != NULL) {
		/* do this before mail_storage_service_next() in case it
		   drops process privileges */
		run_cmd(ctx, remote_cmd_args);
		ctx->run_type = DSYNC_RUN_TYPE_CMD;
	}

	if (ctx->sync_visible_namespaces &&
	    ctx->run_type == DSYNC_RUN_TYPE_LOCAL)
		i_fatal("-N parameter requires syncing with remote host");
	return 0;
}

static void cmd_dsync_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	if (*ctx->destination == NULL)
		doveadm_mail_help_name(_ctx->cmd->name);
	if (array_count(&ctx->exclude_mailboxes) > 0)
		array_append_zero(&ctx->exclude_mailboxes);

	lib_signals_ignore(SIGHUP, TRUE);

        hook_init(ctx);
}

static void cmd_dsync_preinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	const char *value_str, *error;
	bool utc ATTR_UNUSED;

	if (doveadm_cmd_param_flag(cctx, "oneway-sync"))
		ctx->oneway = ctx->backup = TRUE;

	(void)doveadm_cmd_param_str(cctx, "all-mailbox", &ctx->virtual_all_box);

	if (doveadm_cmd_param_flag(cctx, "full-sync"))
		ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_FULL;

	if (doveadm_cmd_param_str(cctx, "sync-flags", &ctx->sync_flags)) {
		const char *str = ctx->sync_flags;
		if (*str == '-')
			str++;
		if (*str == '\\' && imap_parse_system_flag(str) == 0)
			i_fatal("Invalid system flag given for -O parameter: '%s'", str);
		if (strchr(str, ' ') != NULL)
			i_fatal("-O parameter doesn't support multiple flags currently");
	}

	if (doveadm_cmd_param_str(cctx, "mailbox-guid", &value_str)) {
		if (*value_str == '\0')
			ctx->no_mail_sync = TRUE;
		else if (guid_128_from_string(
				value_str, ctx->mailbox_guid) < 0 ||
			 guid_128_is_empty(ctx->mailbox_guid))
			i_fatal("Invalid -g parameter: %s", value_str);
	}

	ctx->lock = doveadm_cmd_param_uint32(
		cctx, "lock-timeout", &ctx->lock_timeout);
	if (doveadm_cmd_param_str(cctx, "mailbox", &value_str)) {
		if (*value_str == '\0')
			ctx->no_mail_sync = TRUE;
		else
			ctx->mailbox = value_str;
	}

	(void)doveadm_cmd_param_array_append(
		cctx, "exclude-mailbox", &ctx->exclude_mailboxes);
	(void)doveadm_cmd_param_array_append(
		cctx, "namespace", &ctx->namespace_prefixes);

	ctx->sync_visible_namespaces =
		doveadm_cmd_param_flag(cctx, "all-namespaces");
	ctx->purge_remote = doveadm_cmd_param_flag(cctx, "purge-remote");
	(void)doveadm_cmd_param_str(cctx, "rawlog", &ctx->rawlog_path);
	ctx->reverse_backup = doveadm_cmd_param_flag(cctx, "reverse-sync");

	if (doveadm_cmd_param_str(cctx, "state", &ctx->state_input) &&
	    *ctx->state_input != '\0' &&
	    ctx->sync_type != DSYNC_BRAIN_SYNC_TYPE_FULL)
		ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_STATE;

	if (doveadm_cmd_param_str(cctx, "sync-since-time", &value_str) &&
	    mail_parse_human_timestamp(value_str, &ctx->sync_since_timestamp,
				       &utc) < 0)
		i_fatal("Invalid -t parameter: %s", value_str);
	if (doveadm_cmd_param_str(cctx, "sync-until-time", &value_str) &&
	    mail_parse_human_timestamp(value_str, &ctx->sync_until_timestamp,
				       &utc) < 0)
		i_fatal("Invalid -e parameter: %s", value_str);
	if (doveadm_cmd_param_str(cctx, "sync-max-size", &value_str) &&
	    str_parse_get_size(value_str, &ctx->sync_max_size, &error) < 0)
		i_fatal("Invalid -I parameter '%s': %s", value_str, error);

	(void)doveadm_cmd_param_uint32(cctx, "timeout", &ctx->io_timeout_secs);

	if (!doveadm_cmd_param_array(cctx, "destination-option",
				     &ctx->destination_options))
		ctx->destination_options = empty_str_array;
	if (!doveadm_cmd_param_array(cctx, "destination", &ctx->destination))
		ctx->destination = empty_str_array;

	if ((_ctx->service_flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) == 0)
		_ctx->service_flags |= MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR;
}

static void cmd_dsync_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

        dsync_hooks_deinit(ctx);
}

static struct doveadm_mail_cmd_context *cmd_dsync_alloc(void)
{
	struct dsync_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct dsync_cmd_context);
	ctx->io_timeout_secs = DSYNC_DEFAULT_IO_STREAM_TIMEOUT_SECS;
	ctx->ctx.v.preinit = cmd_dsync_preinit;
	ctx->ctx.v.init = cmd_dsync_init;
	ctx->ctx.v.prerun = cmd_dsync_prerun;
	ctx->ctx.v.run = cmd_dsync_run;
	ctx->ctx.v.deinit = cmd_dsync_deinit;
	ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_CHANGED;
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("state", "state",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	p_array_init(&ctx->exclude_mailboxes, ctx->ctx.pool, 4);
	p_array_init(&ctx->namespace_prefixes, ctx->ctx.pool, 4);
        if ((doveadm_settings->parsed_features & DSYNC_FEATURE_EMPTY_HDR_WORKAROUND) != 0)
                ctx->empty_hdr_workaround = TRUE;
        if ((doveadm_settings->parsed_features & DSYNC_FEATURE_NO_HEADER_HASHES) != 0)
                ctx->no_header_hashes = TRUE;
	ctx->import_commit_msgs_interval = doveadm_settings->dsync_commit_msgs_interval;

        dsync_hooks_alloc(ctx);

	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_dsync_backup_alloc(void)
{
	struct doveadm_mail_cmd_context *_ctx = cmd_dsync_alloc();
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	ctx->backup = TRUE;
	return _ctx;
}

static int
cmd_dsync_server_run(struct doveadm_mail_cmd_context *_ctx,
		     struct mail_user *user)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	bool cli = (cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);
	struct dsync_ibc *ibc;
	struct dsync_brain *brain;
	string_t *temp_prefix;
	const char *name, *process_title_prefix = "";
	enum mail_error mail_error;
	int ret = 0;

        ret = hook_server_run_pre(ctx, user);
        if (ret < 0) {
                return ret;
        }

	if (!cli) {
		/* doveadm-server connection. start with a success reply.
		   after that follows the regular dsync protocol. */
		ctx->fd_in = ctx->fd_out = -1;
		ctx->input = cctx->input;
		ctx->output = cctx->output;
		i_stream_ref(ctx->input);
		o_stream_ref(ctx->output);
		o_stream_set_finish_also_parent(ctx->output, FALSE);
		o_stream_nsend(ctx->output, "\n+\n", 3);
		i_set_failure_prefix("dsync-server(%s): ", user->username);
		name = i_stream_get_name(ctx->input);

		if (cctx->remote_ip.family != 0) {
			/* include the doveadm client's IP address in the ps output */
			process_title_prefix = t_strdup_printf(
				"%s ", net_ip2addr(&cctx->remote_ip));
		}
	} else {
		/* the log messages go via stderr to the remote dsync,
		   so the names are reversed */
		i_set_failure_prefix("dsync-remote(%s)<%s>: ", user->username, user->session_id);
		name = "local";
	}

	doveadm_user_init_dsync(user);

	temp_prefix = t_str_new(64);
	mail_user_set_get_temp_prefix(temp_prefix, user->set);

	ibc = cmd_dsync_ibc_stream_init(ctx, name, str_c(temp_prefix));
	brain = dsync_brain_slave_init(user, ibc, FALSE, process_title_prefix,
				       doveadm_settings->dsync_alt_char[0],
				       doveadm_settings->dsync_commit_msgs_interval);

	io_loop_run(current_ioloop);
	/* io_loop_run() deactivates the context - put it back */
	mail_storage_service_io_activate_user(ctx->ctx.cur_service_user);

        hook_server_run_post(ctx, user, ibc, brain);

	if (dsync_brain_deinit(&brain, &mail_error) < 0)
		doveadm_mail_failed_error(_ctx, mail_error);
	dsync_ibc_deinit(&ibc);

	if (!cli) {
		/* make sure nothing more is written by the generic doveadm
		   connection code */
		o_stream_close(cctx->output);
	}
	i_stream_unref(&ctx->input);
	o_stream_unref(&ctx->output);

        hook_server_run_end(ctx, user);

	return _ctx->exit_code == 0 ? 0 : -1;
}

static void
cmd_dsync_server_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

	(void)doveadm_cmd_param_str(cctx, "rawlog", &ctx->rawlog_path);
	(void)doveadm_cmd_param_uint32(cctx, "timeout", &ctx->io_timeout_secs);

        hook_server_init(ctx);
}

static void cmd_dsync_server_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct dsync_cmd_context *ctx =
		container_of(_ctx, struct dsync_cmd_context, ctx);

        dsync_hooks_deinit(ctx);
}

static struct doveadm_mail_cmd_context *cmd_dsync_server_alloc(void)
{
	struct dsync_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct dsync_cmd_context);
	ctx->io_timeout_secs = DSYNC_DEFAULT_IO_STREAM_TIMEOUT_SECS;
	ctx->ctx.v.init = cmd_dsync_server_init;
	ctx->ctx.v.run = cmd_dsync_server_run;
	ctx->ctx.v.deinit = cmd_dsync_server_deinit;
	ctx->sync_type = DSYNC_BRAIN_SYNC_TYPE_CHANGED;

	ctx->fd_in = STDIN_FILENO;
	ctx->fd_out = STDOUT_FILENO;

        dsync_hooks_alloc(ctx);

	return &ctx->ctx;
}

#define DSYNC_COMMON_PARAMS \
DOVEADM_CMD_MAIL_COMMON \
DOVEADM_CMD_PARAM('f', "full-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('P', "purge-remote", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('R', "reverse-sync", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('l', "lock-timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED) \
DOVEADM_CMD_PARAM('r', "rawlog", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('m', "mailbox", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('g', "mailbox-guid", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('n', "namespace", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('N', "all-namespaces", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('x', "exclude-mailbox", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('a', "all-mailbox", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('s', "state", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('t', "sync-since-time", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('e', "sync-until-time", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('O', "sync-flags", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('I', "sync-max-size", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('T', "timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED) \
DOVEADM_CMD_PARAM('p', "destination-option", CMD_PARAM_ARRAY, 0) \
DOVEADM_CMD_PARAM('\0', "destination", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)

#define DSYNC_COMMON_USAGE \
	"[-l <secs>] [-r <rawlog path>] " \
	"[-m <mailbox>] [-g <mailbox guid>] [-n <namespace> | -N] " \
	"[-x <exclude>] [-a <all mailbox>] [-s <state>] [-T <secs>] " \
	"[-t <start date>] [-e <end date>] [-O <sync flag>] [-I <max size>] " \
	"[-p <dest option> [...]] <destination>"

struct doveadm_cmd_ver2 doveadm_cmd_dsync_mirror = {
	.mail_cmd = cmd_dsync_alloc,
	.name = "sync",
	.usage = "[-1fPR] "DSYNC_COMMON_USAGE,
	.flags = CMD_FLAG_NO_UNORDERED_OPTIONS,
DOVEADM_CMD_PARAMS_START
DSYNC_COMMON_PARAMS
DOVEADM_CMD_PARAM('1', "oneway-sync", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAMS_END
};
struct doveadm_cmd_ver2 doveadm_cmd_dsync_backup = {
	.mail_cmd = cmd_dsync_backup_alloc,
	.name = "backup",
	.usage = "[-fPR] "DSYNC_COMMON_USAGE,
	.flags = CMD_FLAG_NO_UNORDERED_OPTIONS,
DOVEADM_CMD_PARAMS_START
DSYNC_COMMON_PARAMS
DOVEADM_CMD_PARAMS_END
};
struct doveadm_cmd_ver2 doveadm_cmd_dsync_server = {
	.mail_cmd = cmd_dsync_server_alloc,
	.name = "dsync-server",
	.usage = "[-r <rawlog path>] [-T <timeout secs>] [-U]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('r', "rawlog", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('T', "timeout", CMD_PARAM_INT64, CMD_PARAM_FLAG_UNSIGNED)
/* previously dsync-server could have been added twice to the parameters */
DOVEADM_CMD_PARAM('\0', "ignore-arg", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
