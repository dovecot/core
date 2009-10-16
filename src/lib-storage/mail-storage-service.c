/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hostpid.h"
#include "module-dir.h"
#include "restrict-access.h"
#include "str.h"
#include "var-expand.h"
#include "dict.h"
#include "settings-parser.h"
#include "auth-master.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

/* If time moves backwards more than this, kill ourself instead of sleeping. */
#define MAX_TIME_BACKWARDS_SLEEP 5
#define MAX_NOWARN_FORWARD_SECS 10

struct mail_storage_service_multi_ctx {
	struct master_service *service;
	struct auth_master_connection *conn;
	struct auth_master_user_list_ctx *auth_list;
	enum mail_storage_service_flags flags;

	unsigned int modules_initialized:1;
};

struct mail_storage_service_multi_user {
	pool_t pool;
	struct mail_storage_service_input input;

	const char *system_groups_user;
	const struct mail_user_settings *user_set;
	struct setting_parser_context *set_parser;
};

static struct module *modules = NULL;

static void set_keyval(struct setting_parser_context *set_parser,
		       const char *key, const char *value)
{
	const char *str;

	str = t_strconcat(key, "=", value, NULL);
	if (settings_parse_line(set_parser, str) < 0) {
		i_fatal("Invalid userdb input '%s': %s", str,
			settings_parser_get_error(set_parser));
	}
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
user_reply_handle(struct setting_parser_context *set_parser,
		  const struct mail_user_settings *user_set,
		  const struct auth_user_reply *reply,
		  const char **system_groups_user_r, const char **error_r)
{
	const char *const *str, *p, *line, *key;
	unsigned int i, count;
	int ret = 0;

	*system_groups_user_r = NULL;

	if (reply->uid != (uid_t)-1) {
		if (reply->uid == 0) {
			*error_r = "userdb returned 0 as uid";
			return -1;
		}
		set_keyval(set_parser, "mail_uid", dec2str(reply->uid));
	}
	if (reply->gid != (uid_t)-1)
		set_keyval(set_parser, "mail_gid", dec2str(reply->gid));

	if (reply->home != NULL)
		set_keyval(set_parser, "mail_home", reply->home);

	if (reply->chroot != NULL) {
		if (!validate_chroot(user_set, reply->chroot)) {
			*error_r = t_strdup_printf(
				"userdb returned invalid chroot directory: %s "
				"(see valid_chroot_dirs setting)",
				reply->chroot);
			return -1;
		}
		set_keyval(set_parser, "mail_chroot", reply->chroot);
	}

	str = array_get(&reply->extra_fields, &count);
	for (i = 0; i < count && ret == 0; i++) {
		line = str[i];
		if (strncmp(line, "system_groups_user=", 19) == 0)
			*system_groups_user_r = line + 19;
		else T_BEGIN {
			if (strncmp(line, "mail=", 5) == 0) {
				line = t_strconcat("mail_location=",
						   line + 5, NULL);
			} else if ((p = strchr(str[i], '=')) == NULL)
				line = t_strconcat(str[i], "=yes", NULL);
			else
				line = str[i];

			key = t_strcut(line, '=');
			if (!settings_parse_is_valid_key(set_parser, key)) {
				/* assume it's a plugin setting */
				line = t_strconcat("plugin/", line, NULL);
			}

			ret = settings_parse_line(set_parser, line);
		} T_END;
	}

	if (ret < 0) {
		*error_r = t_strdup_printf("Invalid userdb input '%s': %s",
			str[i], settings_parser_get_error(set_parser));
	}
	return ret;
}

static int
service_auth_userdb_lookup(struct auth_master_connection *conn,
			   struct setting_parser_context *set_parser,
			   const char *service_name,
			   const struct mail_storage_service_input *input,
			   const struct mail_user_settings *user_set,
			   const char **user, const char **system_groups_user_r,
			   const char **error_r)
{
	struct auth_user_info info;
	struct auth_user_reply reply;
	const char *system_groups_user, *orig_user = *user;
	unsigned int len;
	pool_t pool;
	int ret;

	memset(&info, 0, sizeof(info));
	info.service = service_name;
	info.local_ip = input->local_ip;
	info.remote_ip = input->remote_ip;

	pool = pool_alloconly_create("userdb lookup", 1024);
	ret = auth_master_user_lookup(conn, *user, &info, pool, &reply);
	if (ret > 0) {
		len = reply.chroot == NULL ? 0 : strlen(reply.chroot);

		*user = t_strdup(reply.user);
		if (user_reply_handle(set_parser, user_set, &reply,
				      &system_groups_user, error_r) < 0)
			ret = -1;
		*system_groups_user_r = t_strdup(system_groups_user);
	} else {
		if (ret == 0)
			*error_r = "unknown user";
		else
			*error_r = "userdb lookup failed";
		*system_groups_user_r = NULL;
	}

	if (ret > 0 && strcmp(*user, orig_user) != 0) {
		if (mail_user_set_get_storage_set(user_set)->mail_debug)
			i_debug("changed username to %s", *user);
	}

	pool_unref(&pool);
	return ret;
}

static bool parse_uid(const char *str, uid_t *uid_r)
{
	struct passwd *pw;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*uid_r = (uid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	pw = getpwnam(str);
	if (pw == NULL)
		return FALSE;

	*uid_r = pw->pw_uid;
	return TRUE;
}

static bool parse_gid(const char *str, gid_t *gid_r)
{
	struct group *gr;
	char *p;

	if (*str >= '0' && *str <= '9') {
		*gid_r = (gid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return TRUE;
	}

	gr = getgrnam(str);
	if (gr == NULL)
		return FALSE;

	*gid_r = gr->gr_gid;
	return TRUE;
}

static void
service_drop_privileges(const struct mail_user_settings *set,
			const char *system_groups_user, const char *home,
			bool disallow_root, bool keep_setuid_root)
{
	struct restrict_access_settings rset;
	uid_t current_euid, setuid_uid = 0;

	current_euid = geteuid();
	restrict_access_init(&rset);
	if (*set->mail_uid != '\0') {
		if (!parse_uid(set->mail_uid, &rset.uid))
			i_fatal("Unknown mail_uid user: %s", set->mail_uid);
		if (rset.uid < (uid_t)set->first_valid_uid ||
		    (set->last_valid_uid != 0 &&
		     rset.uid > (uid_t)set->last_valid_uid)) {
			i_fatal("Mail access for users with UID %s "
				"not permitted (see first_valid_uid in config file).",
				dec2str(rset.uid));
		}
	}
	if (*set->mail_gid != '\0') {
		if (!parse_gid(set->mail_gid, &rset.gid))
			i_fatal("Unknown mail_gid group: %s", set->mail_gid);
		if (rset.gid < (gid_t)set->first_valid_gid ||
		    (set->last_valid_gid != 0 &&
		     rset.gid > (gid_t)set->last_valid_gid)) {
			i_fatal("Mail access for users with GID %s "
				"not permitted (see first_valid_gid in config file).",
				dec2str(rset.gid));
		}
	}
	if (*set->mail_privileged_group != '\0') {
		if (!parse_uid(set->mail_privileged_group, &rset.privileged_gid))
			i_fatal("Unknown mail_gid group: %s", set->mail_gid);
	}
	if (*set->mail_access_groups != '\0')
		rset.extra_groups = set->mail_access_groups;

	rset.first_valid_gid = set->first_valid_gid;
	rset.last_valid_gid = set->last_valid_gid;
	/* we can't chroot if we want to switch between users. there's not
	   much point either (from security point of view) */
	rset.chroot_dir = *set->mail_chroot == '\0' || keep_setuid_root ?
		NULL : set->mail_chroot;
	rset.system_groups_user = system_groups_user;

	if (disallow_root &&
	    (rset.uid == 0 || (rset.uid == (uid_t)-1 && current_euid == 0)))
		i_fatal("Mail access not allowed for root");

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
	restrict_access(&rset, *home == '\0' ? NULL : home, disallow_root);
	if (setuid_uid != 0) {
		if (seteuid(setuid_uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(setuid_uid));
	}
}

static void
mail_storage_service_init_settings(struct master_service *service,
				   const struct mail_storage_service_input *input,
				   const struct setting_parser_info *set_roots[],
				   bool preserve_home)
{
	ARRAY_DEFINE(all_set_roots, const struct setting_parser_info *);
	const struct setting_parser_info *info = &mail_user_setting_parser_info;
	struct master_service_settings_input set_input;
	const char *error;
	unsigned int i;

	(void)umask(0077);

        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	t_array_init(&all_set_roots, 5);
	array_append(&all_set_roots, &info, 1);
	if (set_roots != NULL) {
		for (i = 0; set_roots[i] != NULL; i++)
			array_append(&all_set_roots, &set_roots[i], 1);
	}
	(void)array_append_space(&all_set_roots);

	/* read settings after registering storages so they can have their
	   own setting definitions too */
	memset(&set_input, 0, sizeof(set_input));
	set_input.roots = array_idx_modifiable(&all_set_roots, 0);
	set_input.dyn_parsers = mail_storage_get_dynamic_parsers();
	set_input.preserve_home = preserve_home;
	if (input != NULL) {
		set_input.module = input->module;
		set_input.service = input->service;
		set_input.username = input->username;
		set_input.local_ip = input->local_ip;
		set_input.remote_ip = input->remote_ip;
	}
	if (master_service_settings_read(service, &set_input, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
}

static int
mail_storage_service_init_post(struct master_service *service,
			       const struct mail_storage_service_input *input,
			       const char *home,
			       const struct mail_user_settings *user_set,
			       bool setuid_root,
			       enum mail_storage_service_flags flags,
			       struct mail_user **mail_user_r,
			       const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	struct mail_user *mail_user;

	mail_set = mail_user_set_get_storage_set(user_set);

	if (mail_set->mail_debug) {
		i_debug("Effective uid=%s, gid=%s, home=%s",
			dec2str(geteuid()), dec2str(getegid()),
			home != NULL ? home : "(none)");
	}

	if (setuid_root) {
		/* we don't want to write core files to any users' home
		   directories since they could contain information about other
		   users' mails as well. so do no chdiring to home. */
	} else if (*home != '\0' &&
		   (flags & MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR) == 0) {
		/* If possible chdir to home directory, so that core file
		   could be written in case we crash. */
		if (chdir(home) < 0) {
			if (errno != ENOENT)
				i_error("chdir(%s) failed: %m", home);
			else if (mail_set->mail_debug)
				i_debug("Home dir not found: %s", home);
		}
	}

	mail_user = mail_user_alloc(input->username, user_set);
	mail_user_set_home(mail_user, *home == '\0' ? NULL : home);
	mail_user_set_vars(mail_user, geteuid(), service->name,
			   &input->local_ip, &input->remote_ip);
	if (mail_user_init(mail_user, error_r) < 0) {
		mail_user_unref(&mail_user);
		return -1;
	}
	if (mail_namespaces_init(mail_user, error_r) < 0) {
		mail_user_unref(&mail_user);
		return -1;
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
mail_storage_service_init_log(struct master_service *service,
			      struct mail_storage_service_input *input)
{
	const struct mail_user_settings *user_set;
	void **sets;

	sets = master_service_settings_get_others(service);
	user_set = sets[0];

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		var_expand(str, user_set->mail_log_prefix,
			   get_var_expand_table(service, input));
		master_service_init_log(service, str_c(str));
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
			"http://wiki.dovecot.org/TimeMovedBackwards", diff);
	} else {
		i_error("Time just moved backwards by %ld seconds. "
			"I'll sleep now until we're back in present. "
			"http://wiki.dovecot.org/TimeMovedBackwards", diff);
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
static struct mail_user *
init_user_real(struct master_service *service,
	       const struct mail_storage_service_input *_input,
	       const struct setting_parser_info *set_roots[],
	       enum mail_storage_service_flags flags)
{
	struct mail_storage_service_input input = *_input;
	const struct master_service_settings *set;
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	struct mail_user *mail_user;
	struct auth_master_connection *conn;
	void **sets;
	const char *user, *orig_user, *home, *system_groups_user, *error;
	unsigned int len;
	bool userdb_lookup;

	io_loop_set_time_moved_callback(current_ioloop,
					mail_storage_service_time_moved);
	master_service_init_finish(service);

	userdb_lookup = (flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0;
	mail_storage_service_init_settings(service, &input, set_roots,
					   !userdb_lookup);

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0)
		set_keyval(service->set_parser, "mail_debug", "yes");

	mail_storage_service_init_log(service, &input);
	set = master_service_settings_get(service);
	sets = master_service_settings_get_others(service);
	user_set = sets[0];
	mail_set = mail_user_set_get_storage_set(user_set);

	if (userdb_lookup) {
		/* userdb lookup may change settings, do it as soon as
		   possible. */
		orig_user = user = input.username;
		conn = auth_master_init(user_set->auth_socket_path,
					mail_set->mail_debug);
		if (service_auth_userdb_lookup(conn, service->set_parser,
					       service->name, &input,
					       user_set, &user,
					       &system_groups_user,
					       &error) <= 0)
			i_fatal("%s", error);
		auth_master_deinit(&conn);
		input.username = user;

		/* set up logging again in case username changed */
		mail_storage_service_init_log(service, &input);
	}

	/* variable strings are expanded in mail_user_init(),
	   but we need the home sooner so do it separately here. */
	home = user_expand_varstr(service, &input, user_set->mail_home);

	if (!userdb_lookup) {
		system_groups_user = NULL;
		if (*home == '\0' && getenv("HOME") != NULL) {
			home = getenv("HOME");
			set_keyval(service->set_parser, "mail_home", home);
		}
	}

	len = strlen(user_set->mail_chroot);
	if (len > 2 && strcmp(user_set->mail_chroot + len - 2, "/.") == 0 &&
	    strncmp(home, user_set->mail_chroot, len - 2) == 0) {
		/* If chroot ends with "/.", strip chroot dir from home dir */
		home += len - 2;
		set_keyval(service->set_parser, "mail_home", home);
	}

	modules = *user_set->mail_plugins == '\0' ? NULL :
		module_dir_load(user_set->mail_plugin_dir,
				user_set->mail_plugins, TRUE,
				master_service_get_version_string(service));

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS) != 0) {
		/* no changes */
	} else if ((flags & MAIL_STORAGE_SERVICE_FLAG_RESTRICT_BY_ENV) != 0) {
		restrict_access_by_env(home,
			(flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0);
	} else {
		service_drop_privileges(user_set, system_groups_user, home,
			(flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0,
			FALSE);
	}
	/* privileges are now dropped */
	restrict_access_allow_coredumps(TRUE);

	dict_drivers_register_builtin();
	module_dir_init(modules);
	mail_users_init(user_set->auth_socket_path, mail_set->mail_debug);
	if (mail_storage_service_init_post(service, &input, home, user_set,
					   FALSE, flags,
					   &mail_user, &error) < 0)
		i_fatal("%s", error);
	return mail_user;
}

struct mail_user *
mail_storage_service_init_user(struct master_service *service,
			       const struct mail_storage_service_input *_input,
			       const struct setting_parser_info *set_roots[],
			       enum mail_storage_service_flags flags)
{
	struct mail_user *user;

	T_BEGIN {
		user = init_user_real(service, _input, set_roots, flags);
	} T_END;
	return user;
}

void mail_storage_service_deinit_user(void)
{
	module_dir_unload(&modules);
	mail_storage_deinit();
	mail_users_deinit();
	dict_drivers_unregister_builtin();
}

struct mail_storage_service_multi_ctx *
mail_storage_service_multi_init(struct master_service *service,
				const struct setting_parser_info *set_roots[],
				enum mail_storage_service_flags flags)
{
	struct mail_storage_service_multi_ctx *ctx;
	const struct master_service_settings *set;
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	void **sets;

	io_loop_set_time_moved_callback(current_ioloop,
					mail_storage_service_time_moved);
	master_service_init_finish(service);

	ctx = i_new(struct mail_storage_service_multi_ctx, 1);
	ctx->service = service;
	ctx->flags = flags;

	mail_storage_service_init_settings(service, NULL, set_roots, FALSE);

	set = master_service_settings_get(service);
	sets = master_service_settings_get_others(service);
	user_set = sets[0];
	mail_set = mail_user_set_get_storage_set(user_set);

	/* do all the global initialization. delay initializing plugins until
	   we drop privileges the first time. */
	master_service_init_log(service, t_strconcat(service->name, ": ", NULL));

	modules = *user_set->mail_plugins == '\0' ? NULL :
		module_dir_load(user_set->mail_plugin_dir,
				user_set->mail_plugins, TRUE,
				master_service_get_version_string(service));

	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		ctx->conn = auth_master_init(user_set->auth_socket_path,
					     mail_set->mail_debug);
	}

	dict_drivers_register_builtin();
	mail_users_init(user_set->auth_socket_path, mail_set->mail_debug);
	return ctx;
}

struct auth_master_connection *
mail_storage_service_multi_get_auth_conn(struct mail_storage_service_multi_ctx *ctx)
{
	return ctx->conn;
}

int mail_storage_service_multi_lookup(struct mail_storage_service_multi_ctx *ctx,
				      const struct mail_storage_service_input *input,
				      pool_t pool,
				      struct mail_storage_service_multi_user **user_r,
				      const char **error_r)
{
	struct mail_storage_service_multi_user *user;
	const char *orig_user, *username;
	void **sets;
	int ret;

	user = p_new(pool, struct mail_storage_service_multi_user, 1);
	memset(user_r, 0, sizeof(user_r));
	user->pool = pool;
	user->input = *input;
	user->input.username = p_strdup(pool, input->username);

	user->set_parser = settings_parser_dup(ctx->service->set_parser, pool);
	sets = settings_parser_get_list(user->set_parser);
	user->user_set = sets[1];

	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		orig_user = username = user->input.username;
		ret = service_auth_userdb_lookup(ctx->conn, user->set_parser,
						 ctx->service->name, input,
						 user->user_set, &username,
						 &user->system_groups_user,
						 error_r);
		if (ret <= 0)
			return ret;
		user->input.username = p_strdup(pool, username);
	}
	*user_r = user;
	return 1;
}

int mail_storage_service_multi_next(struct mail_storage_service_multi_ctx *ctx,
				    struct mail_storage_service_multi_user *user,
				    struct mail_user **mail_user_r,
				    const char **error_r)
{
	const struct mail_user_settings *user_set = user->user_set;
	const char *home;
	unsigned int len;

	/* variable strings are expanded in mail_user_init(),
	   but we need the home sooner so do it separately here. */
	home = user_expand_varstr(ctx->service, &user->input,
				  user_set->mail_home);

	mail_storage_service_init_log(ctx->service, &user->input);

	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS) == 0) {
		service_drop_privileges(user_set, user->system_groups_user, home,
			(ctx->flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0,
			TRUE);
	}
	if (!ctx->modules_initialized) {
		/* privileges dropped for the first time. initialize the
		   modules now to avoid code running as root. */
		module_dir_init(modules);
		ctx->modules_initialized = TRUE;
	}

	/* we couldn't do chrooting, so if chrooting was enabled fix
	   the home directory */
	len = strlen(user_set->mail_chroot);
	if (len > 2 && strcmp(user_set->mail_chroot + len - 2, "/.") == 0 &&
	    strncmp(home, user_set->mail_chroot, len - 2) == 0) {
		/* home dir already contains the chroot dir */
	} else if (len > 0) {
		set_keyval(user->set_parser, "mail_home",
			t_strconcat(user_set->mail_chroot, "/", home, NULL));
	}
	if (mail_storage_service_init_post(ctx->service, &user->input,
					   home, user_set, TRUE, ctx->flags,
					   mail_user_r, error_r) < 0)
		return -1;
	return 0;
}

void mail_storage_service_multi_user_free(struct mail_storage_service_multi_user *user)
{
	settings_parser_deinit(&user->set_parser);
}

unsigned int
mail_storage_service_multi_all_init(struct mail_storage_service_multi_ctx *ctx)
{
	if (ctx->auth_list != NULL)
		(void)auth_master_user_list_deinit(&ctx->auth_list);
	ctx->auth_list = auth_master_user_list_init(ctx->conn);
	return auth_master_user_list_count(ctx->auth_list);
}

int mail_storage_service_multi_all_next(struct mail_storage_service_multi_ctx *ctx,
					const char **username_r)
{
	i_assert((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0);

	*username_r = auth_master_user_list_next(ctx->auth_list);
	if (*username_r != NULL)
		return 1;
	return auth_master_user_list_deinit(&ctx->auth_list);
}

void mail_storage_service_multi_deinit(struct mail_storage_service_multi_ctx **_ctx)
{
	struct mail_storage_service_multi_ctx *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->auth_list != NULL)
		(void)auth_master_user_list_deinit(&ctx->auth_list);
	if (ctx->conn != NULL)
		auth_master_deinit(&ctx->conn);
	i_free(ctx);
	mail_storage_service_deinit_user();
}

void *mail_storage_service_multi_user_get_set(struct mail_storage_service_multi_user *user)
{
	return settings_parser_get_list(user->set_parser) + 1;
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
