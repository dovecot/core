/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "module-dir.h"
#include "restrict-access.h"
#include "eacces-error.h"
#include "ipwd.h"
#include "str.h"
#include "var-expand.h"
#include "dict.h"
#include "settings-parser.h"
#include "auth-master.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-settings-cache.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"

#include <stdlib.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

/* If time moves backwards more than this, kill ourself instead of sleeping. */
#define MAX_TIME_BACKWARDS_SLEEP 5
#define MAX_NOWARN_FORWARD_SECS 10

#define ERRSTR_INVALID_USER_SETTINGS \
	"Invalid user settings. Refer to server log for more information."

struct mail_storage_service_ctx {
	pool_t pool;
	struct master_service *service;
	struct auth_master_connection *conn;
	struct auth_master_user_list_ctx *auth_list;
	const struct setting_parser_info **set_roots;
	enum mail_storage_service_flags flags;

	const char *set_cache_module, *set_cache_service;
	struct master_service_settings_cache *set_cache;

	unsigned int debug:1;
	unsigned int log_initialized:1;
};

struct mail_storage_service_user {
	pool_t pool;
	struct mail_storage_service_input input;
	enum mail_storage_service_flags flags;

	const char *system_groups_user, *uid_source, *gid_source;
	const struct mail_user_settings *user_set;
	const struct setting_parser_info *user_info;
	struct setting_parser_context *set_parser;
};

struct module *mail_storage_service_modules = NULL;

static bool
mail_user_set_get_mail_debug(const struct setting_parser_info *user_info,
			     const struct mail_user_settings *user_set)
{
	const struct mail_storage_settings *mail_set;

	mail_set = mail_user_set_get_driver_settings(user_info, user_set,
						MAIL_STORAGE_SET_DRIVER_NAME);
	return mail_set->mail_debug;
}

static void set_keyval(struct mail_storage_service_ctx *ctx,
		       struct mail_storage_service_user *user,
		       const char *key, const char *value)
{
	struct setting_parser_context *set_parser = user->set_parser;
	const char *str;

	if (master_service_set_has_config_override(ctx->service, key)) {
		/* this setting was already overridden with -o parameter */
		if (mail_user_set_get_mail_debug(user->user_info,
						 user->user_set)) {
			i_debug("Ignoring overridden (-o) userdb setting: %s",
				key);
		}
		return;
	}

	str = t_strconcat(key, "=", value, NULL);
	if (settings_parse_line(set_parser, str) < 0) {
		i_fatal("Invalid userdb input '%s': %s", str,
			settings_parser_get_error(set_parser));
	}
}

static int set_line(struct mail_storage_service_ctx *ctx,
		    struct mail_storage_service_user *user,
		    const char *line)
{
	struct setting_parser_context *set_parser = user->set_parser;
	bool mail_debug;
	const char *key;
	int ret;

	mail_debug = mail_user_set_get_mail_debug(user->user_info,
						  user->user_set);
	if (strchr(line, '=') == NULL)
		line = t_strconcat(line, "=yes", NULL);
	key = t_strcut(line, '=');

	if (!settings_parse_is_valid_key(set_parser, key)) {
		/* assume it's a plugin setting */
		key = t_strconcat("plugin/", key, NULL);
		line = t_strconcat("plugin/", line, NULL);
	}

	if (master_service_set_has_config_override(ctx->service, key)) {
		/* this setting was already overridden with -o parameter */
		if (mail_debug) {
			i_debug("Ignoring overridden (-o) userdb setting: %s",
				key);
		}
		return 1;
	}

	ret = settings_parse_line(set_parser, line);
	if (mail_debug && ret >= 0) {
		i_debug(ret == 0 ?
			"Unknown userdb setting: %s" :
			"Added userdb setting: %s", line);
	}
	return ret;
}

static bool validate_chroot(const struct mail_user_settings *user_set,
			    const char *dir)
{
	const char *const *chroot_dirs;

	if (*dir == '\0')
		return FALSE;

	if (*user_set->valid_chroot_dirs == '\0')
		return FALSE;

	chroot_dirs = t_strsplit(user_set->valid_chroot_dirs, ":");
	while (*chroot_dirs != NULL) {
		if (**chroot_dirs != '\0' &&
		    strncmp(dir, *chroot_dirs, strlen(*chroot_dirs)) == 0)
			return TRUE;
		chroot_dirs++;
	}
	return FALSE;
}

static int
user_reply_handle(struct mail_storage_service_ctx *ctx,
		  struct mail_storage_service_user *user,
		  const struct auth_user_reply *reply,
		  const char **error_r)
{
	const char *home = reply->home;
	const char *chroot = reply->chroot;
	const char *const *str, *line, *p;
	unsigned int i, count;
	int ret = 0;

	if (reply->uid != (uid_t)-1) {
		if (reply->uid == 0) {
			*error_r = "userdb returned 0 as uid";
			return -1;
		}
		user->uid_source = "userdb lookup";
		set_keyval(ctx, user, "mail_uid", dec2str(reply->uid));
	}
	if (reply->gid != (uid_t)-1) {
		user->gid_source = "userdb lookup";
		set_keyval(ctx, user, "mail_gid", dec2str(reply->gid));
	}

	if (home != NULL && chroot == NULL &&
	    *user->user_set->valid_chroot_dirs != '\0' &&
	    (p = strstr(home, "/./")) != NULL) {
		/* wu-ftpd like <chroot>/./<home> - check only if there's even
		   a possibility of using them (non-empty valid_chroot_dirs) */
		chroot = t_strdup_until(home, p);
		home = p + 2;
	}

	if (home != NULL)
		set_keyval(ctx, user, "mail_home", reply->home);

	if (chroot != NULL) {
		if (!validate_chroot(user->user_set, chroot)) {
			*error_r = t_strdup_printf(
				"userdb returned invalid chroot directory: %s "
				"(see valid_chroot_dirs setting)", chroot);
			return -1;
		}
		set_keyval(ctx, user, "mail_chroot", chroot);
	}

	str = array_get(&reply->extra_fields, &count);
	for (i = 0; i < count && ret >= 0; i++) {
		line = str[i];
		if (strncmp(line, "system_groups_user=", 19) == 0) {
			user->system_groups_user =
				p_strdup(user->pool, line + 19);
		} else if (strncmp(line, "nice=", 5) == 0) {
#ifdef HAVE_SETPRIORITY
			int n = atoi(line + 5);

			if (n != 0) {
				if (setpriority(PRIO_PROCESS, 0, n) < 0)
					i_error("setpriority(%d) failed: %m", n);
			}
#endif
		} else T_BEGIN {
			ret = set_line(ctx, user, line);
		} T_END;
	}

	if (ret < 0) {
		*error_r = t_strdup_printf("Invalid userdb input '%s': %s",
			str[i], settings_parser_get_error(user->set_parser));
	}
	return ret;
}

static int
service_auth_userdb_lookup(struct mail_storage_service_ctx *ctx,
			   const struct mail_storage_service_input *input,
			   pool_t pool, const char **user,
			   const char *const **fields_r,
			   const char **error_r)
{
	struct auth_user_info info;
	const char *new_username;
	int ret;

	memset(&info, 0, sizeof(info));
	info.service = ctx->service->name;
	info.local_ip = input->local_ip;
	info.remote_ip = input->remote_ip;

	ret = auth_master_user_lookup(ctx->conn, *user, &info, pool,
				      &new_username, fields_r);
	if (ret > 0) {
		if (strcmp(*user, new_username) != 0) {
			if (ctx->debug)
				i_debug("changed username to %s", new_username);
			*user = t_strdup(new_username);
		}
		*user = new_username;
	} else if (ret == 0)
		*error_r = "Unknown user";
	else if (**fields_r != NULL) {
		*error_r = t_strdup(**fields_r);
		ret = -2;
	} else {
		*error_r = MAIL_ERRSTR_CRITICAL_MSG;
	}
	return ret;
}

static bool parse_uid(const char *str, uid_t *uid_r, const char **error_r)
{
	struct passwd pw;

	if (str_to_uid(str, uid_r) == 0)
		return TRUE;

	switch (i_getpwnam(str, &pw)) {
	case -1:
		*error_r = t_strdup_printf("getpwnam(%s) failed: %m", str);
		return FALSE;
	case 0:
		*error_r = t_strconcat("Unknown UNIX UID user: ", str, NULL);
		return FALSE;
	default:
		*uid_r = pw.pw_uid;
		return TRUE;
	}
}

static bool parse_gid(const char *str, gid_t *gid_r, const char **error_r)
{
	struct group gr;

	if (str_to_gid(str, gid_r) == 0)
		return TRUE;

	switch (i_getgrnam(str, &gr)) {
	case -1:
		*error_r = t_strdup_printf("getgrnam(%s) failed: %m", str);
		return FALSE;
	case 0:
		*error_r = t_strconcat("Unknown UNIX GID group: ", str, NULL);
		return FALSE;
	default:
		*gid_r = gr.gr_gid;
		return TRUE;
	}
}

static int
service_drop_privileges(struct mail_storage_service_user *user,
			const struct mail_user_settings *set,
			const char *home, const char *chroot,
			bool disallow_root, bool keep_setuid_root,
			bool setenv_only, const char **error_r)
{
	struct restrict_access_settings rset;
	uid_t current_euid, setuid_uid = 0;
	const char *cur_chroot, *error;

	current_euid = geteuid();
	restrict_access_init(&rset);
	restrict_access_get_env(&rset);
	if (*set->mail_uid != '\0') {
		if (!parse_uid(set->mail_uid, &rset.uid, &error)) {
			*error_r = t_strdup_printf("%s (from %s)", error,
						   user->uid_source);
			return -1;
		}
		if (rset.uid < (uid_t)set->first_valid_uid ||
		    (set->last_valid_uid != 0 &&
		     rset.uid > (uid_t)set->last_valid_uid)) {
			*error_r = t_strdup_printf(
				"Mail access for users with UID %s not permitted "
				"(see first_valid_uid in config file, uid from %s).",
				dec2str(rset.uid), user->uid_source);
			return -1;
		}
		rset.uid_source = user->uid_source;
	} else if (rset.uid == (uid_t)-1 &&
		   disallow_root && current_euid == 0) {
		*error_r = "User is missing UID (see mail_uid setting)";
		return -1;
	}
	if (*set->mail_gid != '\0') {
		if (!parse_gid(set->mail_gid, &rset.gid, &error)) {
			*error_r = t_strdup_printf("%s (from %s)", error,
						   user->gid_source);
			return -1;
		}
		if (rset.gid < (gid_t)set->first_valid_gid ||
		    (set->last_valid_gid != 0 &&
		     rset.gid > (gid_t)set->last_valid_gid)) {
			*error_r = t_strdup_printf(
				"Mail access for users with GID %s not permitted "
				"(see first_valid_gid in config file, gid from %s).",
				dec2str(rset.gid), user->gid_source);
			return -1;
		}
		rset.gid_source = user->gid_source;
	} else if (rset.gid == (gid_t)-1 && disallow_root &&
		   set->first_valid_gid > 0 && getegid() == 0) {
		*error_r = "User is missing GID (see mail_gid setting)";
		return -1;
	}
	if (*set->mail_privileged_group != '\0') {
		if (!parse_gid(set->mail_privileged_group, &rset.privileged_gid,
			       &error)) {
			*error_r = t_strdup_printf(
				"%s (in mail_privileged_group setting)", error);
			return -1;
		}
	}
	if (*set->mail_access_groups != '\0') {
		rset.extra_groups = t_strconcat(set->mail_access_groups, ",",
						rset.extra_groups, NULL);
	}

	rset.first_valid_gid = set->first_valid_gid;
	rset.last_valid_gid = set->last_valid_gid;
	/* we can't chroot if we want to switch between users. there's not
	   much point either (from security point of view) */
	rset.chroot_dir = *chroot == '\0' || keep_setuid_root ? NULL : chroot;
	rset.system_groups_user = user->system_groups_user;

	cur_chroot = restrict_access_get_current_chroot();
	if (cur_chroot != NULL) {
		if (rset.chroot_dir == NULL) {
			*error_r = "Process is already chrooted, "
				"can't un-chroot for this user";
			return -1;
		}
		if (strcmp(rset.chroot_dir, cur_chroot) != 0) {
			*error_r = t_strdup_printf(
				"Process is already chrooted to %s, "
				"can't chroot to %s", cur_chroot, chroot);
			return -1;
		}
		/* chrooting to same directory where we're already chrooted */
		rset.chroot_dir = NULL;
	}

	if (disallow_root &&
	    (rset.uid == 0 || (rset.uid == (uid_t)-1 && current_euid == 0))) {
		*error_r = "Mail access not allowed for root";
		return -1;
	}

	if (keep_setuid_root) {
		if (current_euid != rset.uid) {
			if (current_euid != 0) {
				/* we're changing the UID,
				   switch back to root first */
				if (seteuid(0) < 0)
					i_fatal("seteuid(0) failed: %m");
			}
			setuid_uid = rset.uid;
		}
		rset.uid = (uid_t)-1;
		disallow_root = FALSE;
	}
	if (!setenv_only) {
		restrict_access(&rset, *home == '\0' ? NULL : home,
				disallow_root);
	} else {
		restrict_access_set_env(&rset);
	}
	if (setuid_uid != 0 && !setenv_only) {
		if (seteuid(setuid_uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(setuid_uid));
	}
	return 0;
}

static int
mail_storage_service_init_post(struct mail_storage_service_ctx *ctx,
			       struct mail_storage_service_user *user,
			       const char *home, struct mail_user **mail_user_r,
			       const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	struct mail_user *mail_user;

	mail_user = mail_user_alloc(user->input.username, user->user_info,
				    user->user_set);
	mail_user_set_home(mail_user, *home == '\0' ? NULL : home);
	mail_user_set_vars(mail_user, geteuid(), ctx->service->name,
			   &user->input.local_ip, &user->input.remote_ip);

	mail_set = mail_user_set_get_storage_set(mail_user);

	if (mail_set->mail_debug) {
		i_debug("Effective uid=%s, gid=%s, home=%s",
			dec2str(geteuid()), dec2str(getegid()), home);
	}

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0 &&
	    (user->flags & MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS) == 0) {
		/* we don't want to write core files to any users' home
		   directories since they could contain information about other
		   users' mails as well. so do no chdiring to home. */
	} else if (*home != '\0' &&
		   (user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR) == 0) {
		/* If possible chdir to home directory, so that core file
		   could be written in case we crash. */
		if (chdir(home) < 0) {
			if (errno == EACCES) {
				i_error("%s", eacces_error_get("chdir",
						t_strconcat(home, "/", NULL)));
			} if (errno != ENOENT)
				i_error("chdir(%s) failed: %m", home);
			else if (mail_set->mail_debug)
				i_debug("Home dir not found: %s", home);
		}
	}

	if (mail_user_init(mail_user, error_r) < 0) {
		mail_user_unref(&mail_user);
		return -1;
	}
	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES) == 0) {
		if (mail_namespaces_init(mail_user, error_r) < 0) {
			mail_user_unref(&mail_user);
			return -1;
		}
	}
	*mail_user_r = mail_user;
	return 0;
}

static const struct var_expand_table *
get_var_expand_table(struct master_service *service,
		     struct mail_storage_service_input *input)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 's', NULL, "service" },
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 'i', NULL, "uid" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = input->username;
	tab[1].value = t_strcut(input->username, '@');
	tab[2].value = strchr(input->username, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = service->name;
	tab[4].value = net_ip2addr(&input->local_ip);
	tab[5].value = net_ip2addr(&input->remote_ip);
	tab[6].value = my_pid;
	tab[7].value = dec2str(geteuid());
	return tab;
}

static const char *
user_expand_varstr(struct master_service *service,
		   struct mail_storage_service_input *input, const char *str)
{
	string_t *ret;

	if (*str == SETTING_STRVAR_EXPANDED[0])
		return str + 1;

	i_assert(*str == SETTING_STRVAR_UNEXPANDED[0]);

	ret = t_str_new(256);
	var_expand(ret, str + 1, get_var_expand_table(service, input));
	return str_c(ret);
}

static void
mail_storage_service_init_log(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user)
{
	ctx->log_initialized = TRUE;
	T_BEGIN {
		string_t *str;
		struct ioloop_log *log;

		str = t_str_new(256);
		var_expand(str, user->user_set->mail_log_prefix,
			   get_var_expand_table(ctx->service, &user->input));
		master_service_init_log(ctx->service, str_c(str));

		log = io_loop_log_new(current_ioloop);
		io_loop_log_set_prefix(log, str_c(str));
		io_loop_log_unref(&log);
	} T_END;
}

static void mail_storage_service_time_moved(time_t old_time, time_t new_time)
{
	long diff = new_time - old_time;

	if (diff > 0) {
		if (diff > MAX_NOWARN_FORWARD_SECS)
			i_warning("Time jumped forwards %ld seconds", diff);
		return;
	}
	diff = -diff;

	if (diff > MAX_TIME_BACKWARDS_SLEEP) {
		i_fatal("Time just moved backwards by %ld seconds. "
			"This might cause a lot of problems, "
			"so I'll just kill myself now. "
			"http://wiki2.dovecot.org/TimeMovedBackwards", diff);
	} else {
		i_error("Time just moved backwards by %ld seconds. "
			"I'll sleep now until we're back in present. "
			"http://wiki2.dovecot.org/TimeMovedBackwards", diff);
		/* Sleep extra second to make sure usecs also grows. */
		diff++;

		while (diff > 0 && sleep(diff) != 0) {
			/* don't use sleep()'s return value, because
			   it could get us to a long loop in case
			   interrupts just keep coming */
			diff = old_time - time(NULL) + 1;
		}
	}
}

struct mail_storage_service_ctx *
mail_storage_service_init(struct master_service *service,
			  const struct setting_parser_info *set_roots[],
			  enum mail_storage_service_flags flags)
{
	struct mail_storage_service_ctx *ctx;
	pool_t pool;
	unsigned int count;

	(void)umask(0077);
	io_loop_set_time_moved_callback(current_ioloop,
					mail_storage_service_time_moved);

        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	pool = pool_alloconly_create("mail storage service", 2048);
	ctx = p_new(pool, struct mail_storage_service_ctx, 1);
	ctx->pool = pool;
	ctx->service = service;
	ctx->flags = flags;

	/* @UNSAFE */
	if (set_roots == NULL)
		count = 0;
	else
		for (count = 0; set_roots[count] != NULL; count++) ;
	ctx->set_roots =
		p_new(pool, const struct setting_parser_info *, count + 2);
	ctx->set_roots[0] = &mail_user_setting_parser_info;
	if (set_roots != NULL) {
		memcpy(ctx->set_roots + 1, set_roots,
		       sizeof(*ctx->set_roots) * count);
	}

	/* do all the global initialization. delay initializing plugins until
	   we drop privileges the first time. */
	if ((flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) == 0) {
		/* note: we may not have read any settings yet, so this logging
		   may still be going to wrong location */
		const char *log_prefix = t_strconcat(service->name, ": ", NULL);

		master_service_init_log(service, log_prefix);
		io_loop_set_default_log_prefix(current_ioloop, log_prefix);
	}
	dict_drivers_register_builtin();
	return ctx;
}

struct auth_master_connection *
mail_storage_service_get_auth_conn(struct mail_storage_service_ctx *ctx)
{
	i_assert(ctx->conn != NULL);
	return ctx->conn;
}

static enum mail_storage_service_flags
mail_storage_service_input_get_flags(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input)
{
	enum mail_storage_service_flags flags;

	flags = (ctx->flags & ~input->flags_override_remove) |
		input->flags_override_add;
	if (input->no_userdb_lookup) {
		/* FIXME: for API backwards compatibility only */
		flags &= ~MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
	}
	return flags;
}

int mail_storage_service_read_settings(struct mail_storage_service_ctx *ctx,
				       const struct mail_storage_service_input *input,
				       pool_t pool,
				       const struct setting_parser_info **user_info_r,
				       const struct setting_parser_context **parser_r,
				       const char **error_r)
{
	struct master_service_settings_input set_input;
	const struct setting_parser_info *const *roots;
	struct master_service_settings_output set_output;
	const struct dynamic_settings_parser *dyn_parsers;
	enum mail_storage_service_flags flags;
	unsigned int i;

	flags = input == NULL ? ctx->flags :
		mail_storage_service_input_get_flags(ctx, input);

	memset(&set_input, 0, sizeof(set_input));
	set_input.roots = ctx->set_roots;
	set_input.preserve_user = TRUE;
	/* settings reader may exec doveconf, which is going to clear
	   environment, and if we're not doing a userdb lookup we want to
	   use $HOME */
	set_input.preserve_home =
		(flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) == 0;
	set_input.use_sysexits =
		(flags & MAIL_STORAGE_SERVICE_FLAG_USE_SYSEXITS) != 0;

	if (input != NULL) {
		set_input.module = input->module;
		set_input.service = input->service;
		set_input.username = input->username;
		set_input.local_ip = input->local_ip;
		set_input.remote_ip = input->remote_ip;
	}
	if (ctx->set_cache == NULL) {
		ctx->set_cache_module = p_strdup(ctx->pool, set_input.module);
		ctx->set_cache_service = p_strdup(ctx->pool, set_input.service);
		ctx->set_cache = master_service_settings_cache_init(
			ctx->service, set_input.module, set_input.service);
	} else {
		/* already looked up settings at least once.
		   we really shouldn't be execing anymore. */
		set_input.never_exec = TRUE;
	}

	dyn_parsers = mail_storage_get_dynamic_parsers(pool);
	if (null_strcmp(set_input.module, ctx->set_cache_module) == 0 &&
	    null_strcmp(set_input.service, ctx->set_cache_service) == 0) {
		if (master_service_settings_cache_read(ctx->set_cache,
						       &set_input, dyn_parsers,
						       parser_r, error_r) < 0) {
			*error_r = t_strdup_printf(
				"Error reading configuration: %s", *error_r);
			return -1;
		}
	} else {
		settings_parser_dyn_update(pool, &set_input.roots, dyn_parsers);
		if (master_service_settings_read(ctx->service, &set_input,
						 &set_output, error_r) < 0) {
			*error_r = t_strdup_printf(
				"Error reading configuration: %s", *error_r);
			return -1;
		}
		*parser_r = ctx->service->set_parser;
	}

	roots = settings_parser_get_roots(*parser_r);
	for (i = 0; roots[i] != NULL; i++) {
		if (strcmp(roots[i]->module_name,
			   mail_user_setting_parser_info.module_name) == 0) {
			*user_info_r = roots[i];
			return 0;
		}
	}
	i_unreached();
	return -1;
}

static void
mail_storage_service_first_init(struct mail_storage_service_ctx *ctx,
				const struct setting_parser_info *user_info,
				const struct mail_user_settings *user_set)
{
	enum auth_master_flags flags = 0;

	i_assert(ctx->conn == NULL);

	ctx->debug = mail_user_set_get_mail_debug(user_info, user_set);
	if (ctx->debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;
	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT) != 0)
		flags |= AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT;
	ctx->conn = auth_master_init(user_set->auth_socket_path, flags);

	i_assert(mail_user_auth_master_conn == NULL);
	mail_user_auth_master_conn = ctx->conn;
}

static void
mail_storage_service_load_modules(struct mail_storage_service_ctx *ctx,
				  const struct setting_parser_info *user_info,
				  const struct mail_user_settings *user_set)
{
	struct module_dir_load_settings mod_set;

	if (*user_set->mail_plugins == '\0')
		return;
	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS) != 0)
		return;

	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(ctx->service);
	mod_set.binary_name = master_service_get_name(ctx->service);
	mod_set.setting_name = "mail_plugins";
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = mail_user_set_get_mail_debug(user_info, user_set);

	mail_storage_service_modules =
		module_dir_load_missing(mail_storage_service_modules,
					user_set->mail_plugin_dir,
					user_set->mail_plugins, &mod_set);
}

int mail_storage_service_lookup(struct mail_storage_service_ctx *ctx,
				const struct mail_storage_service_input *input,
				struct mail_storage_service_user **user_r,
				const char **error_r)
{
	enum mail_storage_service_flags flags;
	struct mail_storage_service_user *user;
	const char *username = input->username;
	const struct setting_parser_info *user_info;
	const struct mail_user_settings *user_set;
	const char *const *userdb_fields, *error;
	struct auth_user_reply reply;
	const struct setting_parser_context *set_parser;
	pool_t user_pool, temp_pool;
	int ret = 1;

	user_pool = pool_alloconly_create("mail storage service user", 1024*5);

	if (mail_storage_service_read_settings(ctx, input, user_pool,
					       &user_info, &set_parser,
					       &error) < 0) {
		i_error("user %s: %s", username, error);
		pool_unref(&user_pool);
		*error_r = MAIL_ERRSTR_CRITICAL_MSG;
		return -1;
	}

	flags = mail_storage_service_input_get_flags(ctx, input);
	if ((flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) == 0 &&
	    !ctx->log_initialized) {
		/* initialize logging again, in case we only read the
		   settings for the first above */
		ctx->log_initialized = TRUE;
		master_service_init_log(ctx->service,
			t_strconcat(ctx->service->name, ": ", NULL));
	}
	user_set = settings_parser_get_list(set_parser)[1];

	if (ctx->conn == NULL)
		mail_storage_service_first_init(ctx, user_info, user_set);
	/* load global plugins */
	mail_storage_service_load_modules(ctx, user_info, user_set);

	temp_pool = pool_alloconly_create("userdb lookup", 2048);
	if ((flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		ret = service_auth_userdb_lookup(ctx, input, temp_pool,
						 &username, &userdb_fields,
						 error_r);
		if (ret <= 0) {
			pool_unref(&temp_pool);
			pool_unref(&user_pool);
			return ret;
		}
	} else {
		userdb_fields = input->userdb_fields;
	}

	user = p_new(user_pool, struct mail_storage_service_user, 1);
	memset(user_r, 0, sizeof(user_r));
	user->pool = user_pool;
	user->input = *input;
	user->input.userdb_fields = NULL;
	user->input.username = p_strdup(user_pool, username);
	user->user_info = user_info;
	user->flags = flags;

	user->set_parser = settings_parser_dup(set_parser, user_pool);
	if (!settings_parser_check(user->set_parser, user_pool, &error))
		i_panic("settings_parser_check() failed: %s", error);

	user->user_set = settings_parser_get_list(user->set_parser)[1];
	user->gid_source = "mail_gid setting";
	user->uid_source = "mail_uid setting";

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0)
		(void)settings_parse_line(user->set_parser, "mail_debug=yes");

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) == 0) {
		const char *home = getenv("HOME");
		if (home != NULL)
			set_keyval(ctx, user, "mail_home", home);
	}

	if (userdb_fields != NULL) {
		auth_user_fields_parse(userdb_fields, temp_pool, &reply);
		if (user_reply_handle(ctx, user, &reply, &error) < 0) {
			i_error("user %s: Invalid settings in userdb: %s",
				username, error);
			*error_r = ERRSTR_INVALID_USER_SETTINGS;
			ret = -2;
		}
	}
	pool_unref(&temp_pool);

	/* load per-user plugins */
	if (ret > 0) {
		mail_storage_service_load_modules(ctx, user_info,
						  user->user_set);
	}

	*user_r = user;
	return ret;
}

int mail_storage_service_next(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user,
			      struct mail_user **mail_user_r)
{
	const struct mail_user_settings *user_set = user->user_set;
	const char *home, *chroot, *error;
	unsigned int len;
	bool disallow_root =
		(user->flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0;
	bool temp_priv_drop =
		(user->flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0;

	/* variable strings are expanded in mail_user_init(),
	   but we need the home and chroot sooner so do them separately here. */
	home = user_expand_varstr(ctx->service, &user->input,
				  user_set->mail_home);
	chroot = user_expand_varstr(ctx->service, &user->input,
				    user_set->mail_chroot);

	if (*home != '/' && *home != '\0') {
		i_error("user %s: "
			"Relative home directory paths not supported: %s",
			user->input.username, home);
		return -2;
	}

	len = strlen(chroot);
	if (len > 2 && strcmp(chroot + len - 2, "/.") == 0 &&
	    strncmp(home, chroot, len - 2) == 0) {
		/* mail_chroot = /chroot/. means that the home dir already
		   contains the chroot dir. remove it from home. */
		if (!temp_priv_drop) {
			home += len - 2;
			if (*home == '\0')
				home = "/";
			chroot = t_strndup(chroot, len - 2);

			set_keyval(ctx, user, "mail_home", home);
			set_keyval(ctx, user, "mail_chroot", chroot);
		}
	} else if (len > 0 && temp_priv_drop) {
		/* we're dropping privileges only temporarily, so we can't
		   chroot. fix home directory so we can access it. */
		if (*home == '\0' || strcmp(home, "/") == 0)
			home = chroot;
		else
			home = t_strconcat(chroot, home, NULL);
		chroot = "";
		set_keyval(ctx, user, "mail_home", home);
	}

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) == 0)
		mail_storage_service_init_log(ctx, user);

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS) == 0) {
		if (service_drop_privileges(user, user_set, home, chroot,
					    disallow_root, temp_priv_drop,
					    FALSE, &error) < 0) {
			i_error("user %s: Couldn't drop privileges: %s",
				user->input.username, error);
			return -1;
		}
		if (!temp_priv_drop ||
		    (user->flags & MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS) != 0)
			restrict_access_allow_coredumps(TRUE);
	}

	/* privileges are dropped. initialize plugins that haven't been
	   initialized yet. */
	module_dir_init(mail_storage_service_modules);

	if (mail_storage_service_init_post(ctx, user, home,
					   mail_user_r, &error) < 0) {
		i_error("user %s: Initialization failed: %s",
			user->input.username, error);
		return -2;
	}
	return 0;
}

void mail_storage_service_restrict_setenv(struct mail_storage_service_ctx *ctx,
					  struct mail_storage_service_user *user)
{
	const struct mail_user_settings *user_set = user->user_set;
	const char *home, *chroot, *error;

	home = user_expand_varstr(ctx->service, &user->input,
				  user_set->mail_home);
	chroot = user_expand_varstr(ctx->service, &user->input,
				    user_set->mail_chroot);

	if (service_drop_privileges(user, user_set, home, chroot,
				    FALSE, FALSE, TRUE,
				    &error) < 0)
		i_fatal("%s", error);
}

int mail_storage_service_lookup_next(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input,
				     struct mail_storage_service_user **user_r,
				     struct mail_user **mail_user_r,
				     const char **error_r)
{
	struct mail_storage_service_user *user;
	int ret;

	ret = mail_storage_service_lookup(ctx, input, &user, error_r);
	if (ret <= 0)
		return ret;

	ret = mail_storage_service_next(ctx, user, mail_user_r);
	if (ret < 0) {
		mail_storage_service_user_free(&user);
		*error_r = ret == -2 ? ERRSTR_INVALID_USER_SETTINGS :
			MAIL_ERRSTR_CRITICAL_MSG;
		return ret;
	}
	*user_r = user;
	return 1;
}

void mail_storage_service_user_free(struct mail_storage_service_user **_user)
{
	struct mail_storage_service_user *user = *_user;

	*_user = NULL;
	settings_parser_deinit(&user->set_parser);
	pool_unref(&user->pool);
}

void mail_storage_service_init_settings(struct mail_storage_service_ctx *ctx,
					const struct mail_storage_service_input *input)
{
	const struct setting_parser_info *user_info;
	const struct mail_user_settings *user_set;
	const struct setting_parser_context *set_parser;
	const char *error;
	pool_t temp_pool;

	if (ctx->conn != NULL)
		return;

	temp_pool = pool_alloconly_create("service all settings", 4096);
	if (mail_storage_service_read_settings(ctx, input, temp_pool,
					       &user_info, &set_parser,
					       &error) < 0)
		i_fatal("%s", error);
	user_set = settings_parser_get_list(set_parser)[1];

	mail_storage_service_first_init(ctx, user_info, user_set);
	pool_unref(&temp_pool);
}

unsigned int
mail_storage_service_all_init(struct mail_storage_service_ctx *ctx)
{
	if (ctx->auth_list != NULL)
		(void)auth_master_user_list_deinit(&ctx->auth_list);
	mail_storage_service_init_settings(ctx, NULL);

	ctx->auth_list = auth_master_user_list_init(ctx->conn);
	return auth_master_user_list_count(ctx->auth_list);
}

int mail_storage_service_all_next(struct mail_storage_service_ctx *ctx,
				  const char **username_r)
{
	i_assert((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0);

	*username_r = auth_master_user_list_next(ctx->auth_list);
	if (*username_r != NULL)
		return 1;
	return auth_master_user_list_deinit(&ctx->auth_list);
}

void mail_storage_service_deinit(struct mail_storage_service_ctx **_ctx)
{
	struct mail_storage_service_ctx *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->auth_list != NULL)
		(void)auth_master_user_list_deinit(&ctx->auth_list);
	if (ctx->conn != NULL) {
		if (mail_user_auth_master_conn == ctx->conn)
			mail_user_auth_master_conn = NULL;
		auth_master_deinit(&ctx->conn);
	}
	if (ctx->set_cache != NULL)
		master_service_settings_cache_deinit(&ctx->set_cache);
	pool_unref(&ctx->pool);

	module_dir_unload(&mail_storage_service_modules);
	mail_storage_deinit();
	dict_drivers_unregister_builtin();
}

void **mail_storage_service_user_get_set(struct mail_storage_service_user *user)
{
	return settings_parser_get_list(user->set_parser) + 1;
}

const struct mail_storage_service_input *
mail_storage_service_user_get_input(struct mail_storage_service_user *user)
{
	return &user->input;
}

struct setting_parser_context *
mail_storage_service_user_get_settings_parser(struct mail_storage_service_user *user)
{
	return user->set_parser;
}

void *mail_storage_service_get_settings(struct master_service *service)
{
	void **sets, *set;

	T_BEGIN {
		sets = master_service_settings_get_others(service);
		set = sets[1];
	} T_END;
	return set;
}
