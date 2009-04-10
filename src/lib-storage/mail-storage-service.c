/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dict.h"
#include "module-dir.h"
#include "restrict-access.h"
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

struct mail_storage_service_multi_ctx {
	struct master_service *service;
	enum mail_storage_service_flags flags;

	unsigned int modules_initialized:1;
};

static struct module *modules = NULL;

static void
master_service_set(struct master_service *service,
		   const char *key, const char *value)
{
	const char *str;

	str = t_strconcat(key, "=", value, NULL);
	if (settings_parse_line(service->set_parser, str) < 0) {
		i_fatal("Invalid userdb input '%s': %s", str,
			settings_parser_get_error(service->set_parser));
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
user_reply_handle(struct master_service *service,
		  const struct mail_user_settings *user_set,
		  const struct auth_user_reply *reply,
		  const char **system_groups_user_r, const char **error_r)
{
	const char *const *str, *p, *line;
	unsigned int i, count;
	int ret = 0;

	*system_groups_user_r = NULL;

	if (reply->uid != (uid_t)-1) {
		if (reply->uid == 0) {
			*error_r = "userdb returned 0 as uid";
			return -1;
		}
		master_service_set(service, "mail_uid", dec2str(reply->uid));
	}
	if (reply->gid != (uid_t)-1)
		master_service_set(service, "mail_gid", dec2str(reply->gid));

	if (reply->home != NULL)
		master_service_set(service, "mail_home", reply->home);

	if (reply->chroot != NULL) {
		if (!validate_chroot(user_set, reply->chroot)) {
			*error_r = t_strdup_printf(
				"userdb returned invalid chroot directory: %s "
				"(see valid_chroot_dirs setting)",
				reply->chroot);
			return -1;
		}
		master_service_set(service, "mail_chroot", reply->chroot);
	}

	str = array_get(&reply->extra_fields, &count);
	for (i = 0; i < count && ret == 0; i++) T_BEGIN {
		line = str[i];
		if (strncmp(line, "system_groups_user=", 19) == 0) {
			*system_groups_user_r = line + 19;
			continue;
		}
		if (strncmp(line, "mail=", 5) == 0)
			line = t_strconcat("mail_location=", line + 5, NULL);
		else if ((p = strchr(str[i], '=')) == NULL)
			line = t_strconcat(str[i], "=yes", NULL);
		else
			line = str[i];
		ret = settings_parse_line(service->set_parser, line);
	} T_END;

	if (ret < 0) {
		*error_r = t_strdup_printf("Invalid userdb input '%s': %s",
			str[i], settings_parser_get_error(service->set_parser));
	}
	return ret;
}

static int
service_auth_userdb_lookup(struct master_service *service, bool debug,
			   const struct mail_user_settings *user_set,
			   const char **user, const char **system_groups_user_r,
			   const char **error_r)
{
        struct auth_master_connection *conn;
	struct auth_user_reply reply;
	const char *system_groups_user, *orig_user = *user;
	unsigned int len;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("userdb lookup", 1024);
	conn = auth_master_init(user_set->auth_socket_path, debug);
	ret = auth_master_user_lookup(conn, *user, service->name,
				      pool, &reply);
	if (ret > 0) {
		len = reply.chroot == NULL ? 0 : strlen(reply.chroot);

		*user = t_strdup(reply.user);
		if (user_reply_handle(service, user_set, &reply,
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
			i_info("changed username to %s", *user);
		i_set_failure_prefix(t_strdup_printf("%s(%s): ", service->name,
						     *user));
	}

	auth_master_deinit(&conn);
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
			const char *system_groups_user,
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

	if (keep_setuid_root && current_euid != rset.uid) {
		if (current_euid != 0) {
			/* we're changing the UID, switch back to root first */
			if (seteuid(0) < 0)
				i_fatal("seteuid(0) failed: %m");
		}
		setuid_uid = rset.uid;
		rset.uid = (uid_t)-1;
	}
	restrict_access(&rset, *set->mail_home == '\0' ? NULL : set->mail_home,
			disallow_root);
	if (keep_setuid_root) {
		if (seteuid(setuid_uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(setuid_uid));
	}
}

static void
mail_storage_service_init_settings(struct master_service *service,
				   const struct setting_parser_info *set_root,
				   bool preserve_home)
{
	const struct setting_parser_info *set_roots[3];
	const char *error;

	(void)umask(0077);

        mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	set_roots[0] = &mail_user_setting_parser_info;
	set_roots[1] = set_root;
	set_roots[2] = NULL;

	/* read settings after registering storages so they can have their
	   own setting definitions too */
	if (master_service_settings_read(service, set_roots,
					 mail_storage_get_dynamic_parsers(),
					 preserve_home, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
}

static int
mail_storage_service_init_post(struct master_service *service, const char *user,
			       const struct mail_user_settings *user_set,
			       struct mail_user **mail_user_r,
			       const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	struct mail_user *mail_user;
	const char *home;

	mail_set = mail_user_set_get_storage_set(user_set);

	/* If possible chdir to home directory, so that core file
	   could be written in case we crash. */
	home = user_set->mail_home;
	if (*home != '\0') {
		if (chdir(home) < 0) {
			if (errno != ENOENT)
				i_error("chdir(%s) failed: %m", home);
			else if (mail_set->mail_debug)
				i_info("Home dir not found: %s", home);
		}
	}

	mail_user = mail_user_alloc(user, user_set);
	if (*home != '\0')
		mail_user_set_home(mail_user, home);
	mail_user_set_vars(mail_user, geteuid(), service->name, NULL, NULL);
	if (mail_user_init(mail_user, error_r) < 0 ||
	    mail_namespaces_init(mail_user, error_r) < 0) {
		*error_r = t_strdup(*error_r);
		mail_user_unref(&mail_user);
		return -1;
	}
	*mail_user_r = mail_user;
	return 0;
}

struct mail_user *
mail_storage_service_init_user(struct master_service *service, const char *user,
			       const struct setting_parser_info *set_root,
			       enum mail_storage_service_flags flags)
{
	const struct master_service_settings *set;
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	struct mail_user *mail_user;
	void **sets;
	const char *orig_user, *home, *system_groups_user, *error;
	unsigned int len;
	bool userdb_lookup;

	userdb_lookup = (flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0;
	mail_storage_service_init_settings(service, set_root, !userdb_lookup);

	/* now that we've read settings, we can set up logging */
	master_service_init_log(service,
		t_strdup_printf("%s(%s): ", service->name, user));

	set = master_service_settings_get(service);
	sets = master_service_settings_get_others(service);
	user_set = sets[0];
	mail_set = mail_user_set_get_storage_set(user_set);

	if (userdb_lookup) {
		/* userdb lookup may change settings, do it as soon as
		   possible. */
		orig_user = user;
		if (service_auth_userdb_lookup(service, mail_set->mail_debug,
					       user_set, &user,
					       &system_groups_user,
					       &error) <= 0) {
			i_fatal("%s", error);
		}
	} else {
		home = getenv("HOME");
		system_groups_user = NULL;
		if (*user_set->mail_home == '\0' && home != NULL)
			master_service_set(service, "mail_home", home);
	}
	home = user_set->mail_home;

	len = strlen(user_set->mail_chroot);
	if (len > 2 && strcmp(user_set->mail_chroot + len - 2, "/.") == 0 &&
	    strncmp(home, user_set->mail_chroot, len - 2) == 0) {
		/* If chroot ends with "/.", strip chroot dir from home dir */
		home += len - 2;
		master_service_set(service, "mail_home", home);
	}

	modules = *user_set->mail_plugins == '\0' ? NULL :
		module_dir_load(user_set->mail_plugin_dir,
				user_set->mail_plugins, TRUE,
				master_service_get_version_string(service));

	service_drop_privileges(user_set, system_groups_user,
		(flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0, FALSE);
	/* privileges are now dropped */

	dict_drivers_register_builtin();
	module_dir_init(modules);
	mail_users_init(user_set->auth_socket_path, mail_set->mail_debug);
	if (mail_storage_service_init_post(service, user, user_set,
					   &mail_user, &error) < 0)
		i_fatal("%s", error);
	return mail_user;
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
				const struct setting_parser_info *set_root,
				enum mail_storage_service_flags flags)
{
	struct mail_storage_service_multi_ctx *ctx;
	const struct master_service_settings *set;
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	void **sets;

	ctx = i_new(struct mail_storage_service_multi_ctx, 1);
	ctx->service = service;
	ctx->flags = flags;

	mail_storage_service_init_settings(service, set_root, FALSE);

	/* do all the global initialization. delay initializing plugins until
	   we drop privileges the first time. */
	master_service_init_log(service,
				t_strdup_printf("%s: ", service->name));

	set = master_service_settings_get(service);
	sets = master_service_settings_get_others(service);
	user_set = sets[0];
	mail_set = mail_user_set_get_storage_set(user_set);

	modules = *user_set->mail_plugins == '\0' ? NULL :
		module_dir_load(user_set->mail_plugin_dir,
				user_set->mail_plugins, TRUE,
				master_service_get_version_string(service));

	dict_drivers_register_builtin();
	mail_users_init(user_set->auth_socket_path, mail_set->mail_debug);
	return ctx;
}

int mail_storage_service_multi_next(struct mail_storage_service_multi_ctx *ctx,
				    const char *user,
				    struct mail_user **mail_user_r,
				    const char **error_r)
{
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	const char *orig_user, *system_groups_user;
	void **sets;
	unsigned int len;
	int ret;

	sets = master_service_settings_get_others(ctx->service);
	user_set = sets[0];
	mail_set = mail_user_set_get_storage_set(user_set);

	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		orig_user = user;
		ret = service_auth_userdb_lookup(ctx->service,
						 mail_set->mail_debug,
						 user_set, &user,
						 &system_groups_user,
						 error_r);
		if (ret <= 0)
			return ret;
	} else {
		system_groups_user = NULL;
	}

	service_drop_privileges(user_set, system_groups_user,
		(ctx->flags & MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT) != 0, TRUE);

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
	    strncmp(user_set->mail_home, user_set->mail_chroot, len - 2) == 0) {
		/* home dir already contains the chroot dir */
	} else if (len > 0) {
		master_service_set(ctx->service, "mail_home",
				   t_strconcat(user_set->mail_chroot, "/",
					       user_set->mail_home, NULL));
	}
	if (mail_storage_service_init_post(ctx->service, user,
					   user_set, mail_user_r, error_r) < 0)
		return -1;
	return 1;
}

void mail_storage_service_multi_deinit(struct mail_storage_service_multi_ctx **_ctx)
{
	struct mail_storage_service_multi_ctx *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx);
	mail_storage_service_deinit_user();
}

void *mail_storage_service_get_settings(struct master_service *service)
{
	void **sets;

	sets = master_service_settings_get_others(service);
	return sets[1];
}
