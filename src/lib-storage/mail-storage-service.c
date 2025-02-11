/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "base64.h"
#include "hostpid.h"
#include "module-dir.h"
#include "restrict-access.h"
#include "eacces-error.h"
#include "ipwd.h"
#include "str.h"
#include "time-util.h"
#include "sleep.h"
#include "dict.h"
#include "settings.h"
#include "auth-master.h"
#include "master-service-private.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "doc.h"

#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

/* If time moves backwards more than this, kill ourself instead of sleeping. */
#define MAX_TIME_BACKWARDS_SLEEP_MSECS  (5*1000)
#define MAX_NOWARN_FORWARD_MSECS        (10*1000)

struct mail_storage_service_privileges {
	uid_t uid;
	gid_t gid;
	const char *uid_source, *gid_source;
};

struct mail_storage_service_ctx {
	pool_t pool;
	struct master_service *service;
	const char *default_log_prefix;

	struct auth_master_connection *conn, *iter_conn;
	struct auth_master_user_list_ctx *auth_list;
	enum mail_storage_service_flags flags;

	bool debug:1;
	bool log_initialized:1;
};

struct mail_storage_service_init_var_expand_ctx {
	struct mail_storage_service_ctx *ctx;
	const struct mail_storage_service_input *input;
	struct mail_storage_service_user *user;
};

struct mail_storage_service_user_module_register
	mail_storage_service_user_module_register = { 0 };
struct module *mail_storage_service_modules = NULL;

struct metacache_service_user_module metacache_service_user_module =
	MODULE_CONTEXT_INIT(&mail_storage_service_user_module_register);

static void set_keyvalue(struct mail_storage_service_user *user,
			 const char *key, const char *value)
{
	/* Ignore empty keys rather than prepend 'plugin/=' to them. */
	if (*key == '\0')
		return;

	settings_override(user->set_instance, key, value,
			  SETTINGS_OVERRIDE_TYPE_USERDB);
	if (strstr(key, "pass") != NULL) {
		/* possibly a password field (e.g. imapc_password).
		   hide the value. */
		value = "<hidden>";
	}
	e_debug(user->event, "Added userdb setting: %s=%s", key, value);
}

static bool validate_chroot(const struct mail_user_settings *user_set,
			    const char *dir)
{
	const char *const *chroot_dirs;

	if (*dir == '\0')
		return FALSE;

	if (array_is_empty(&user_set->valid_chroot_dirs))
		return FALSE;

	chroot_dirs = settings_boollist_get(&user_set->valid_chroot_dirs);
	while (*chroot_dirs != NULL) {
		if (**chroot_dirs != '\0' &&
		    str_begins_with(dir, *chroot_dirs))
			return TRUE;
		chroot_dirs++;
	}
	return FALSE;
}

static int
user_reply_handle(struct mail_storage_service_user *user,
		  const struct auth_user_reply *reply,
		  const char **error_r)
{
	const char *home = reply->home;
	const char *chroot = reply->chroot;
	const char *const *str, *p;
	unsigned int i, count;

	if (reply->uid != (uid_t)-1) {
		if (reply->uid == 0) {
			*error_r = "userdb returned 0 as uid";
			return -1;
		}
		user->uid_source = "userdb lookup";
		settings_override(user->set_instance,
				  "mail_uid", dec2str(reply->uid),
				  SETTINGS_OVERRIDE_TYPE_USERDB);
	}
	if (reply->gid != (uid_t)-1) {
		user->gid_source = "userdb lookup";
		settings_override(user->set_instance,
				  "mail_gid", dec2str(reply->gid),
				  SETTINGS_OVERRIDE_TYPE_USERDB);
	}

	if (home != NULL && chroot == NULL &&
	    array_not_empty(&user->user_set->valid_chroot_dirs) &&
	    (p = strstr(home, "/./")) != NULL) {
		/* wu-ftpd like <chroot>/./<home> - check only if there's even
		   a possibility of using them (non-empty valid_chroot_dirs) */
		chroot = t_strdup_until(home, p);
		home = p + 2;
	}

	if (home != NULL) {
		settings_override(user->set_instance, "mail_home", home,
				  SETTINGS_OVERRIDE_TYPE_USERDB);
		user->home_from_userdb = TRUE;
	}

	if (chroot != NULL) {
		if (!validate_chroot(user->user_set, chroot)) {
			*error_r = t_strdup_printf(
				"userdb returned invalid chroot directory: %s "
				"(see valid_chroot_dirs setting)", chroot);
			return -1;
		}
		settings_override(user->set_instance, "mail_chroot", chroot,
				  SETTINGS_OVERRIDE_TYPE_USERDB);
	}

	user->anonymous = reply->anonymous;

	str = array_get(&reply->extra_fields, &count);
	for (i = 0; i < count; i++) {
		const char *key, *value, *line = str[i];
		t_split_key_value_eq(line, &key, &value);

		if (strcmp(key, "system_groups_user") == 0) {
			user->system_groups_user = p_strdup(user->pool, value);
		} else if (strcmp(key, "chdir") == 0) {
			user->chdir_path = p_strdup(user->pool, value);
		} else if (strcmp(key, "nice") == 0) {
#ifdef HAVE_SETPRIORITY
			int n;
			if (str_to_int(value, &n) < 0) {
				e_error(user->event,
					"userdb returned invalid nice value %s",
					value);
			} else if (n != 0) {
				if (setpriority(PRIO_PROCESS, 0, n) < 0)
					e_error(user->event,
						"setpriority(%d) failed: %m", n);
			}
#endif
		} else if (strcmp(key, "auth_mech") == 0) {
			user->auth_mech = p_strdup(user->pool, value);
		} else if (strcmp(key, "auth_token") == 0) {
			user->auth_token = p_strdup(user->pool, value);
		} else if (strcmp(key, "auth_user") == 0) {
			user->auth_user = p_strdup(user->pool, value);
		} else if (strcmp(key, "admin") == 0) {
			user->admin = strchr("1Yy", value[0]) != NULL;
		} else if (strcmp(key, "local_name") == 0) {
			user->local_name = p_strdup(user->pool, value);
		} else {
			set_keyvalue(user, key, value);
		}
	}
	return 0;
}

static void
mail_storage_service_add_code_overrides(struct mail_storage_service_user *user,
					const char *const *code_override_fields)
{
	for (unsigned int i = 0; code_override_fields[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(code_override_fields[i], &key, &value);

		if (strcmp(key, "mail_home") == 0)
			user->home_from_userdb = TRUE;
		settings_override(user->set_instance, key, value,
				  SETTINGS_OVERRIDE_TYPE_CODE);
	}
}

static int
service_auth_userdb_lookup(struct mail_storage_service_ctx *ctx,
			   const struct mail_storage_service_input *input,
			   pool_t pool, struct event *event, const char **user,
			   const char *const **fields_r, const char **error_r)
{
	struct auth_user_info info;
	const char *new_username;
	int ret;

	i_zero(&info);
	/* If protocol was explicitly provided, use it. Otherwise, fallback to
	   using service name as the protocol. Outside a few special cases
	   (e.g. imap-urlauth-worker) the service and protocol are the same. */
	if (input->protocol != NULL)
		info.protocol = input->protocol;
	else if (input->service != NULL)
		info.protocol = input->service;
	else
		info.protocol = ctx->service->name;
	info.local_ip = input->local_ip;
	info.remote_ip = input->remote_ip;
	info.local_port = input->local_port;
	info.remote_port = input->remote_port;
	info.forward_fields = input->forward_fields;
	info.local_name = input->local_name;
	info.debug = input->debug;

	ret = auth_master_user_lookup(ctx->conn, *user, &info, pool,
				      &new_username, fields_r);
	if (ret > 0) {
		if (strcmp(*user, new_username) != 0) {
			e_debug(event, "changed username to %s", new_username);
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

static const char *get_master_user(const char *const *fields)
{
	const char *value;
	for (; *fields != NULL; fields++)
		if (str_begins(*fields, "master=", &value))
			return value;
	return NULL;
}

static const struct var_expand_table *
get_var_expand_table(struct master_service *service,
		     struct mail_storage_service_user *user,
		     const struct mail_storage_service_input *input)
{
	const char *local_name = NULL;
	const char *master_user;
	const char *auth_user;

	if (user == NULL || user->auth_user == NULL) {
		auth_user = input->username;
		if (input->userdb_fields != NULL)
			master_user = get_master_user(input->userdb_fields);
		else
			master_user = NULL;
	} else {
		auth_user = user->auth_user;
		local_name = user->local_name;
		master_user = user->master_user;
	}

	const char *service_name = input->service != NULL ?
				   input->service : service->name;
	const char *protocol = input->protocol != NULL ?
		input->protocol : service_name;
	const char *hostname = user != NULL ?
		user->user_set->hostname : my_hostname;
	const char *local_port = "";
	const char *remote_port = "";

	if (input->local_port != 0)
		local_port = dec2str(input->local_port);
	if (input->remote_port != 0)
		remote_port = dec2str(input->remote_port);

	const struct var_expand_table stack_tab[] = {
		{ .key = "user", .value = input->username },
		{ .key = "service", .value = service_name },
		{ .key = "local_ip", .value = net_ip2addr(&input->local_ip) },
		{ .key = "remote_ip", .value = net_ip2addr(&input->remote_ip) },
		{ .key = "session", .value = input->session_id },
		{ .key = "auth_user", .value = auth_user },
		{ .key = "hostname", .value = hostname },
		{ .key = "local_name", .value = local_name },
		{ .key = "protocol", .value = protocol },
		{ .key = "master_user", .value = master_user },
		{ .key = "local_port", .value = local_port },
		{ .key = "remote_port", .value = remote_port },
		VAR_EXPAND_TABLE_END
	};
	struct var_expand_table *tab;

	tab = t_malloc_no0(sizeof(stack_tab));
	memcpy(tab, stack_tab, sizeof(stack_tab));
	return tab;
}


static int
mail_storage_service_var_userdb(const char *key, const char **value_r,
			       void *context, const char **error_r ATTR_UNUSED)
{
	const struct mail_storage_service_input *input = context;

	*value_r = mail_storage_service_fields_var_expand(key, input->userdb_fields);
	return 0;
}

const struct var_expand_provider mail_storage_service_providers[] = {
	{ .key = "userdb", .func = mail_storage_service_var_userdb },
	VAR_EXPAND_TABLE_END
};

const struct var_expand_params *
mail_storage_service_get_var_expand_params(struct mail_storage_service_ctx *ctx,
					   struct mail_storage_service_input *input)
{
	struct var_expand_params *params = t_new(struct var_expand_params, 1);

	params->table = get_var_expand_table(ctx->service, NULL, input);
	params->providers = mail_storage_service_providers;
	params->context = input;
	return params;
}

static int
service_parse_privileges(struct mail_storage_service_user *user,
			 struct mail_storage_service_privileges *priv_r,
			 const char **error_r)
{
	const struct mail_user_settings *set = user->user_set;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	i_zero(priv_r);
	if (*set->mail_uid != '\0') {
		if (!parse_uid(set->mail_uid, &uid, error_r)) {
			*error_r = t_strdup_printf("%s (from %s)", *error_r,
						   user->uid_source);
			return -1;
		}
		if (uid < (uid_t)set->first_valid_uid ||
		    (set->last_valid_uid != 0 &&
		     uid > (uid_t)set->last_valid_uid)) {
			*error_r = t_strdup_printf(
				"Mail access for users with UID %s not permitted "
				"(see first_valid_uid in config file, uid from %s).",
				dec2str(uid), user->uid_source);
			return -1;
		}
	}
	priv_r->uid = uid;
	priv_r->uid_source = user->uid_source;

	if (*set->mail_gid != '\0') {
		if (!parse_gid(set->mail_gid, &gid, error_r)) {
			*error_r = t_strdup_printf("%s (from %s)", *error_r,
						   user->gid_source);
			return -1;
		}
		if (gid < (gid_t)set->first_valid_gid ||
		    (set->last_valid_gid != 0 &&
		     gid > (gid_t)set->last_valid_gid)) {
			*error_r = t_strdup_printf(
				"Mail access for users with GID %s not permitted "
				"(see first_valid_gid in config file, gid from %s).",
				dec2str(gid), user->gid_source);
			return -1;
		}
	}
	priv_r->gid = gid;
	priv_r->gid_source = user->gid_source;
	return 0;
}

static void mail_storage_service_seteuid(uid_t uid)
{
	if (seteuid(uid) < 0) {
		i_fatal("mail-storage-service: "
			"Failed to restore temporarily dropped root privileges: "
			"seteuid(%d) failed: %m", uid);
	}
}

static void mail_storage_service_seteuid_root(void)
{
	mail_storage_service_seteuid(0);
}

void mail_storage_service_restore_privileges(uid_t old_uid, const char *old_cwd,
					     struct event *event)
{
	if (old_uid != geteuid()) {
		mail_storage_service_seteuid_root();
		restrict_access_allow_coredumps(TRUE);
		if (old_uid != 0)
			mail_storage_service_seteuid(old_uid);
	}

	/* we need also to chdir to root-owned directory to get core dumps. */
	if (old_cwd != NULL && chdir(old_cwd) < 0)
		e_error(event, "chdir(%s) failed: %m", old_cwd);
}

static int
service_drop_privileges(struct mail_storage_service_user *user,
			struct mail_storage_service_privileges *priv,
			bool allow_root, bool keep_setuid_root,
			bool setenv_only, const char **error_r)
{
	const struct mail_user_settings *set = user->user_set;
	struct restrict_access_settings rset;
	uid_t current_euid, setuid_uid = 0;
	const char *cur_chroot, *error;

	current_euid = geteuid();
	restrict_access_init(&rset);
	restrict_access_get_env(&rset);
	rset.allow_setuid_root = keep_setuid_root;
	if (priv->uid != (uid_t)-1) {
		rset.uid = priv->uid;
		rset.uid_source = priv->uid_source;
	} else if (rset.uid == (uid_t)-1 &&
		   !allow_root && current_euid == 0) {
		*error_r = "User is missing UID (see mail_uid setting)";
		return -1;
	}
	if (priv->gid != (gid_t)-1) {
		rset.gid = priv->gid;
		rset.gid_source = priv->gid_source;
	} else if (rset.gid == (gid_t)-1 && !allow_root &&
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
	if (array_not_empty(&set->mail_access_groups)) {
		rset.extra_groups = t_strconcat(t_array_const_string_join(&set->mail_access_groups, ","), ",",
						rset.extra_groups, NULL);
	}

	rset.first_valid_gid = set->first_valid_gid;
	rset.last_valid_gid = set->last_valid_gid;
	rset.chroot_dir = *set->mail_chroot == '\0' ? NULL : set->mail_chroot;
	rset.system_groups_user = user->system_groups_user;

	cur_chroot = restrict_access_get_current_chroot();
	if (cur_chroot != NULL) {
		/* we're already chrooted. make sure the chroots are equal. */
		if (rset.chroot_dir == NULL) {
			*error_r = "Process is already chrooted, "
				"can't un-chroot for this user";
			return -1;
		}
		if (strcmp(rset.chroot_dir, cur_chroot) != 0) {
			*error_r = t_strdup_printf(
				"Process is already chrooted to %s, "
				"can't chroot to %s", cur_chroot, set->mail_chroot);
			return -1;
		}
		/* chrooting to same directory where we're already chrooted */
		rset.chroot_dir = NULL;
	}

	if (!allow_root &&
	    (rset.uid == 0 || (rset.uid == (uid_t)-1 && current_euid == 0))) {
		*error_r = "Mail access not allowed for root";
		return -1;
	}

	if (keep_setuid_root) {
		if (current_euid != rset.uid && rset.uid != (uid_t)-1) {
			if (current_euid != 0) {
				/* we're changing the UID,
				   switch back to root first */
				mail_storage_service_seteuid_root();
			}
			setuid_uid = rset.uid;
		}
		rset.uid = (uid_t)-1;
		allow_root = TRUE;
	}
	if (!setenv_only) {
		restrict_access(&rset, allow_root ? RESTRICT_ACCESS_FLAG_ALLOW_ROOT : 0,
				*set->mail_home == '\0' ? NULL : set->mail_home);
	} else {
		restrict_access_set_env(&rset);
	}
	if (setuid_uid != 0 && !setenv_only) {
		if (seteuid(setuid_uid) < 0)
			i_fatal("mail-storage-service: seteuid(%s) failed: %m",
				dec2str(setuid_uid));
	}
	return 0;
}

static int
mail_storage_service_init_post(struct mail_storage_service_ctx *ctx,
			       struct mail_storage_service_user *user,
			       struct mail_storage_service_privileges *priv,
			       const char *session_id_suffix,
			       struct mail_user **mail_user_r,
			       const char **error_r)
{
	const char *home = user->user_set->mail_home;
	struct mail_user_connection_data conn_data;
	struct mail_user *mail_user;
	int ret;

	const char *service_name = user->input.service != NULL ?
				   user->input.service : ctx->service->name;

	i_zero(&conn_data);
	conn_data.local_ip = &user->input.local_ip;
	conn_data.remote_ip = &user->input.remote_ip;
	conn_data.local_port = user->input.local_port;
	conn_data.remote_port = user->input.remote_port;
	conn_data.end_client_tls_secured =
		user->input.end_client_tls_secured;

	/* NOTE: if more user initialization is added, add it also to
	   mail_user_dup() */
	mail_user = mail_user_alloc(user);
	*mail_user_r = mail_user;
	if (user->input.autocreated)
		mail_user->autocreated = TRUE;
	if (!user->input.no_userdb_lookup || user->home_from_userdb) {
		/* userdb lookup is done. The (lack of) home directory is now
		   known. */
		mail_user_set_home(mail_user, *home == '\0' ? NULL : home);
	}
	conn_data.local_name = p_strdup(mail_user->pool, user->local_name);
	mail_user_set_vars(mail_user, service_name, &conn_data);
	mail_user->uid = priv->uid == (uid_t)-1 ? geteuid() : priv->uid;
	mail_user->gid = priv->gid == (gid_t)-1 ? getegid() : priv->gid;
	mail_user->anonymous = user->anonymous;
	mail_user->admin = user->admin;
	mail_user->protocol = user->input.protocol != NULL ?
		p_strdup(mail_user->pool, user->input.protocol) :
		mail_user->service;
	mail_user->auth_mech = p_strdup(mail_user->pool, user->auth_mech);
	mail_user->auth_token = p_strdup(mail_user->pool, user->auth_token);
	mail_user->auth_user = p_strdup(mail_user->pool, user->auth_user);
	if (user->input.session_create_time != 0) {
		mail_user->session_create_time =
			user->input.session_create_time;
		mail_user->session_restored = TRUE;
	}

	if (session_id_suffix == NULL) {
		if (user->session_id_counter++ == 0) {
			mail_user->session_id =
				p_strdup(mail_user->pool, user->input.session_id);
		} else {
			mail_user->session_id =
				p_strdup_printf(mail_user->pool, "%s:%u",
						user->input.session_id,
						user->session_id_counter);
		}
	} else
		mail_user->session_id =
			p_strdup_printf(mail_user->pool, "%s:%s",
					user->input.session_id,
					session_id_suffix);
	event_add_str(user->event, "session", mail_user->session_id);
	event_add_str(user->event, "service", service_name);
	settings_event_add_list_filter_name(user->event, "service",
					    service_name);

	mail_user->userdb_fields = user->input.userdb_fields == NULL ? NULL :
		p_strarray_dup(mail_user->pool, user->input.userdb_fields);
	if (mail_user->userdb_fields != NULL)
		mail_user->master_user = get_master_user(mail_user->userdb_fields);
	mail_user_add_event_fields(mail_user);

	string_t *str = t_str_new(64);

	str_printfa(str, "Effective uid=%s, gid=%s, home=%s",
		    dec2str(geteuid()), dec2str(getegid()), home);
	if (*user->user_set->mail_chroot != '\0')
		str_printfa(str, ", chroot=%s", user->user_set->mail_chroot);
	e_debug(mail_user->event, "%s", str_c(str));

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0 &&
	    (user->flags & MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS) == 0) {
		/* we don't want to write core files to any users' home
		   directories since they could contain information about other
		   users' mails as well. so do no chdiring to home. */
	} else if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR) == 0) {
		/* If possible chdir to home directory, so that core file
		   could be written in case we crash.

		   fallback to chdir()ing to root directory. this is needed
		   because the current directory may not be accessible after
		   dropping privileges, and for example unlink_directory()
		   requires ability to open the current directory. */
		const char *chdir_path = user->chdir_path != NULL ?
			user->chdir_path : home;

		if (chdir_path[0] == '\0') {
			if (chdir("/") < 0)
				e_error(user->event, "chdir(/) failed: %m");
		} else if (chdir(chdir_path) < 0) {
			if (ENOACCESS(errno)) {
				e_error(user->event, "%s",
					eacces_error_get("chdir",
						t_strconcat(chdir_path, "/", NULL)));
			} else if (errno != ENOENT)
				e_error(user->event, "chdir(%s) failed: %m",
					chdir_path);
			else
				e_debug(mail_user->event, "Home dir not found: %s", chdir_path);

			if (chdir("/") < 0)
				e_error(user->event, "chdir(/) failed: %m");
		}
	}

	T_BEGIN {
		ret = mail_user_init(mail_user, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0)
		return -1;

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES) == 0) {
		if (mail_namespaces_init(mail_user, error_r) < 0)
			return -1;
	}
	return 0;
}

void mail_storage_service_io_activate_user(struct mail_storage_service_user *user)
{
	io_loop_context_activate(user->ioloop_ctx);
}

void mail_storage_service_io_deactivate_user(struct mail_storage_service_user *user)
{
	io_loop_context_deactivate(user->ioloop_ctx);
}

static void
mail_storage_service_io_activate_user_cb(struct mail_storage_service_user *user)
{
	if (user->service_ctx->log_initialized && user->log_prefix != NULL)
		i_set_failure_prefix("%s", user->log_prefix);
}

static void
mail_storage_service_io_deactivate_user_cb(struct mail_storage_service_user *user)
{
	if (user->service_ctx->log_initialized && user->log_prefix != NULL)
		i_set_failure_prefix("%s", user->service_ctx->default_log_prefix);
}

const char *mail_storage_service_fields_var_expand(const char *data,
						   const char *const *fields)
{
	const char *field_name = t_strcut(data, ':');
	unsigned int i;
	size_t field_name_len;

	if (fields == NULL)
		return "";

	field_name_len = strlen(field_name);
	for (i = 0; fields[i] != NULL; i++) {
		if (strncmp(fields[i], field_name, field_name_len) == 0 &&
		    fields[i][field_name_len] == '=')
			return fields[i] + field_name_len+1;
	}

	return "";
}

static void
mail_storage_service_var_expand_callback(void *context,
					 struct var_expand_params *params_r)
{
	struct mail_storage_service_init_var_expand_ctx *var_expand_ctx = context;

	params_r->table = get_var_expand_table(var_expand_ctx->ctx->service,
					       var_expand_ctx->user,
					       var_expand_ctx->input);
	params_r->providers = mail_storage_service_providers;
	params_r->context = (void*)var_expand_ctx->input;
}

const char *
mail_storage_service_user_get_log_prefix(struct mail_storage_service_user *user)
{
	i_assert(user->log_prefix != NULL);
	return user->log_prefix;
}

struct event *
mail_storage_service_user_get_event(const struct mail_storage_service_user *user)
{
	return user->event;
}

const char *
mail_storage_service_user_get_username(const struct mail_storage_service_user *user)
{
	return user->input.username;
}

static void
mail_storage_service_init_log(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user)
{
	user->log_prefix = user->user_set->mail_log_prefix;
	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) != 0)
		return;

	ctx->log_initialized = TRUE;
	master_service_init_log_with_prefix(ctx->service, user->log_prefix);
	/* replace the whole log prefix with mail_log_prefix */
	event_replace_log_prefix(user->event, user->log_prefix);

	if (master_service_get_client_limit(master_service) == 1)
		i_set_failure_send_prefix(user->log_prefix);
}

static void
mail_storage_service_time_moved(const struct timeval *old_time,
				const struct timeval *new_time)
{
	long long diff = timeval_diff_usecs(new_time, old_time);

	if (diff > 0) {
		if ((diff / 1000) > MAX_NOWARN_FORWARD_MSECS)
			i_warning("Time moved forward %lld.%06lld seconds",
				  diff / 1000000, diff % 1000000);
		return;
	}
	diff = -diff;

	const char *doc_ref = DOC_LINK("core/admin/errors.html#time-moved-backwards-error");
	if ((diff / 1000) > MAX_TIME_BACKWARDS_SLEEP_MSECS) {
		i_fatal("Time just moved backwards by %lld.%06lld seconds. "
			"This might cause a lot of problems, "
			"so I'll just kill myself now. %s",
			diff / 1000000, diff % 1000000, doc_ref);
	} else {
		i_error("Time just moved backwards by %lld.%06lld seconds. "
			"I'll sleep now until we're back in present. %s",
			diff / 1000000, diff % 1000000, doc_ref);

		i_sleep_usecs(diff);
	}
}

struct mail_storage_service_ctx *
mail_storage_service_init(struct master_service *service,
			  enum mail_storage_service_flags flags)
{
	struct mail_storage_service_ctx *ctx;
	const char *version;
	pool_t pool;

	version = master_service_get_version_string(service);
	if (version != NULL && strcmp(version, PACKAGE_VERSION) != 0) {
		i_fatal("Version mismatch: libdovecot-storage.so is '%s', "
			"while the running Dovecot binary is '%s'",
			PACKAGE_VERSION, version);
	}

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0 &&
	    getuid() != 0) {
		/* service { user } isn't root. the permission drop can't be
		   temporary. */
		flags &= ENUM_NEGATE(MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP);
	}

	(void)umask(0077);
	io_loop_set_time_moved_callback(current_ioloop,
					mail_storage_service_time_moved);

        mail_storage_init();

	pool = pool_alloconly_create("mail storage service", 2048);
	ctx = p_new(pool, struct mail_storage_service_ctx, 1);
	ctx->pool = pool;
	ctx->service = service;
	ctx->flags = flags;

	/* note: we may not have read any settings yet, so this logging
	   may still be going to wrong location */
	const char *configured_name =
		master_service_get_configured_name(service);
	ctx->default_log_prefix =
		p_strdup_printf(pool, "%s(%s): ", configured_name, my_pid);

	/* do all the global initialization. delay initializing plugins until
	   we drop privileges the first time. */
	if ((flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) == 0)
		master_service_init_log_with_prefix(service, ctx->default_log_prefix);
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

	flags = (ctx->flags & ENUM_NEGATE(input->flags_override_remove)) |
		input->flags_override_add;
	if (input->no_userdb_lookup) {
		/* FIXME: for API backwards compatibility only */
		flags &= ENUM_NEGATE(MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP);
	}
	return flags;
}

void mail_storage_service_set_auth_conn(struct mail_storage_service_ctx *ctx,
					struct auth_master_connection *conn)
{
	i_assert(ctx->conn == NULL);
	i_assert(mail_user_auth_master_conn == NULL);

	ctx->conn = conn;
	mail_user_auth_master_conn = conn;
}

static void
mail_storage_service_first_init(struct mail_storage_service_ctx *ctx,
				const struct mail_user_settings *user_set,
				enum mail_storage_service_flags service_flags)
{
	enum auth_master_flags flags = 0;

	ctx->debug = user_set->mail_debug ||
		     (service_flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0;
	if (ctx->debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;
	if ((service_flags & MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT) != 0)
		flags |= AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT;
	mail_storage_service_set_auth_conn(ctx,
		auth_master_init(user_set->auth_socket_path, flags));
}

static int
mail_storage_service_load_modules(struct mail_storage_service_ctx *ctx,
				  const struct mail_user_settings *user_set,
				  const char **error_r)
{
	struct module_dir_load_settings mod_set;

	if (!array_is_created(&user_set->mail_plugins) ||
	    array_is_empty(&user_set->mail_plugins))
		return 0;
	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS) != 0)
		return 0;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.binary_name = master_service_get_name(ctx->service);
	mod_set.setting_name = "mail_plugins";
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = user_set->mail_debug;

	return module_dir_try_load_missing(&mail_storage_service_modules,
					   user_set->mail_plugin_dir,
					   settings_boollist_get(&user_set->mail_plugins),
					   &mod_set, error_r);
}

static int extra_field_key_cmp_p(const char *const *s1, const char *const *s2)
{
	const char *p1 = *s1, *p2 = *s2;

	for (; *p1 == *p2; p1++, p2++) {
		if (*p1 == '\0')
			return 0;
	}
	if (*p1 == '=')
		return -1;
	if (*p2 == '=')
		return 1;
	return *p1 - *p2;
}

static const char *
mail_storage_service_generate_session_id(pool_t pool, const char *prefix)
{
	guid_128_t guid;
	size_t prefix_len = prefix == NULL ? 0 : strlen(prefix);
	string_t *str = str_new(pool, MAX_BASE64_ENCODED_SIZE(prefix_len + 1 + sizeof(guid)));

	if (prefix != NULL)
		str_printfa(str, "%s:", prefix);

	guid_128_generate(guid);
	base64_encode(guid, sizeof(guid), str);
	/* remove the trailing "==" */
	i_assert(str_data(str)[str_len(str)-2] == '=');
	str_truncate(str, str_len(str)-2);
	return str_c(str);

}

static void
mail_storage_service_update_chroot(struct mail_storage_service_user *user)
{
	bool temp_priv_drop =
		(user->flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0;
	/* we can't chroot if we want to switch between users. there's
	   not much point either (from security point of view). but if we're
	   already chrooted, we'll just have to continue and hope that the
	   current chroot is the same as the wanted chroot */
	bool use_chroot = !temp_priv_drop ||
		restrict_access_get_current_chroot() != NULL;

	const char *chroot = user->user_set->mail_chroot;
	const char *home = user->user_set->mail_home;
	size_t len = strlen(chroot);
	if (len > 2 && strcmp(chroot + len - 2, "/.") == 0 &&
	    strncmp(home, chroot, len - 2) == 0) {
		/* mail_chroot = /chroot/. means that the home dir already
		   contains the chroot dir. remove it from home. */
		if (use_chroot) {
			home += len - 2;
			if (*home == '\0')
				home = "/";
			chroot = t_strndup(chroot, len - 2);

			settings_override(user->set_instance,
					  "mail_home", home,
					  SETTINGS_OVERRIDE_TYPE_USERDB);
			settings_override(user->set_instance,
					  "mail_chroot", chroot,
					  SETTINGS_OVERRIDE_TYPE_USERDB);
		}
	} else if (len > 0 && !use_chroot) {
		/* we're not going to chroot. fix home directory so we can
		   access it. */
		if (*home == '\0' || strcmp(home, "/") == 0)
			home = chroot;
		else
			home = t_strconcat(chroot, home, NULL);
		settings_override(user->set_instance, "mail_home", home,
				  SETTINGS_OVERRIDE_TYPE_USERDB);
		settings_override(user->set_instance, "mail_chroot", "",
				  SETTINGS_OVERRIDE_TYPE_USERDB);
	}
}

static int
mail_storage_service_lookup_real(struct mail_storage_service_ctx *ctx,
				 const struct mail_storage_service_input *input,
				 bool update_log_prefix,
				 struct mail_storage_service_user **user_r,
				 const char **error_r)
{
	enum mail_storage_service_flags flags;
	const char *username = input->username;
	const struct mail_user_settings *user_set;
	const char *const *userdb_fields, *error;
	struct auth_user_reply reply;
	struct settings_instance *set_instance;
	pool_t temp_pool;
	int ret = 1;

	flags = mail_storage_service_input_get_flags(ctx, input);

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0 &&
	    geteuid() != 0 &&
	    (flags & MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS) == 0) {
		/* we dropped privileges only temporarily. switch back to root
		   before reading settings, so we'll definitely have enough
		   permissions to connect to the config socket. */
		mail_storage_service_seteuid_root();
	}

	if (input->set_instance != NULL) {
		/* Start with the specified settings instance and its settings,
		   but allow this instance to set its own settings without
		   affecting the parent instance. */
		set_instance = settings_instance_dup(input->set_instance);
	} else {
		set_instance = settings_instance_new(
			master_service_get_settings_root(ctx->service));
	}

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) == 0 &&
	    !ctx->log_initialized) {
		/* initialize logging again, in case we only read the
		   settings for the first above */
		ctx->log_initialized = TRUE;
		master_service_init_log_with_prefix(ctx->service,
						    ctx->default_log_prefix);
		update_log_prefix = TRUE;
	}

	/* Create an event that will be used as the default event for logging.
	   This event won't be a parent to any other events - mail_user.event
	   will be used for that. */
	struct event *event = event_create(input->event_parent);
	event_set_ptr(event, SETTINGS_EVENT_INSTANCE, set_instance);

	struct mail_storage_service_init_var_expand_ctx var_expand_ctx = {
		.ctx = ctx,
		.input = input,
	};
	/* Set callback to get %variable expansion table for settings expansion.
	   This is used only for settings lookups while inside this function,
	   and it is cleared before we exit this function. Afterwards any
	   settings lookups are expected to be using mail_user.event. */
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK,
		      mail_storage_service_var_expand_callback);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT,
		      &var_expand_ctx);
	if (settings_get(event, &mail_user_setting_parser_info,
			 0, &user_set, error_r) < 0) {
		event_unref(&event);
		settings_instance_free(&set_instance);
		return -1;
	}

	if (update_log_prefix)
		i_set_failure_prefix("%s", user_set->mail_log_prefix);

	if (ctx->conn == NULL)
		mail_storage_service_first_init(ctx, user_set, flags);
	/* load global plugins */
	if (mail_storage_service_load_modules(ctx, user_set, error_r) < 0) {
		settings_free(user_set);
		event_unref(&event);
		settings_instance_free(&set_instance);
		return -1;
	}

	temp_pool = pool_alloconly_create("userdb lookup", 2048);
	/* NOTE: ctx->debug gets set by mail_storage_service_first_init() above,
	   so this can't be before. */
	event_set_forced_debug(event,
		ctx->debug || (flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0);

	pool_t user_pool = pool_alloconly_create(MEMPOOL_GROWING"mail storage service user", 1024*6);
	const char *session_id = input->session_id != NULL ?
		p_strdup(user_pool, input->session_id) :
		mail_storage_service_generate_session_id(
			user_pool, input->session_id_prefix);

	const char *service_name =
		input->service != NULL ? input->service : ctx->service->name;

	event_add_fields(event, (const struct event_add_field []){
		{ .key = "user", .value = input->username },
		{ .key = "session", .value = session_id },
		{ .key = "service", .value = service_name },
		{ .key = NULL }
	});

	if (input->local_name != NULL)
		event_add_str(event, "local_name", input->local_name);

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0) {
		ret = service_auth_userdb_lookup(
			ctx, input, temp_pool, event,
			&username, &userdb_fields, error_r);
		if (ret <= 0) {
			settings_free(user_set);
			event_unref(&event);
			pool_unref(&temp_pool);
			pool_unref(&user_pool);
			settings_instance_free(&set_instance);
			return ret;
		}
		event_add_str(event, "user", username);
	} else {
		userdb_fields = input->userdb_fields;
	}

	struct mail_storage_service_user *user =
		p_new(user_pool, struct mail_storage_service_user, 1);

	user->refcount = 1;
	user->service_ctx = ctx;
	user->pool = user_pool;
	user->input = *input;
	user->input.userdb_fields = userdb_fields == NULL ? NULL :
		p_strarray_dup(user_pool, userdb_fields);
	user->input.username = p_strdup(user_pool, username);
	user->input.session_id = session_id; /* already allocated on user_pool */
	user->input.local_name = p_strdup(user_pool, input->local_name);
	user->event = event;
	user->input.session_create_time = input->session_create_time;
	user->flags = flags;
	p_array_init(&user->module_contexts, user->pool, 5);

	user->set_instance = set_instance;
	user->user_set = user_set;
	user->gid_source = "mail_gid setting";
	user->uid_source = "mail_uid setting";

	var_expand_ctx.input = &user->input;
	var_expand_ctx.user = user;

	if ((flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0) {
		settings_override(user->set_instance, "mail_debug", "yes",
				  SETTINGS_OVERRIDE_TYPE_CODE);
	}

	if (userdb_fields != NULL) {
		int ret2 = auth_user_fields_parse(userdb_fields, temp_pool,
						  &reply, &error);
		if (ret2 == 0) {
			array_sort(&reply.extra_fields, extra_field_key_cmp_p);
			ret2 = user_reply_handle(user, &reply, &error);
			if (user->local_name != NULL) {
				event_add_str(event, "local_name",
					      user->local_name);
			}
		}

		if (ret2 < 0) {
			*error_r = t_strdup_printf(
				"Invalid settings in userdb: %s", error);
			ret = -2;
		}
	}
	if (input->code_override_fields != NULL) {
		mail_storage_service_add_code_overrides(user,
			input->code_override_fields);
	}
	if ((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS) != 0 &&
	    array_is_created(&user_set->mail_plugins) &&
	    array_not_empty(&user_set->mail_plugins)) {
		/* mail_storage_service_load_modules() already avoids loading
		   plugins when the _NO_PLUGINS flag is set. However, it's
		   possible that the plugins are already loaded, because the
		   plugin loading is a global state. This is especially true
		   with doveadm, which loads the mail_plugins immediately at
		   startup so it can find commands registered by plugins. It's
		   fine that extra plugins are loaded - we'll just need to
		   prevent any of their hooks from being called. One easy way
		   to do this is just to clear out the mail_plugins setting: */
		settings_override(user->set_instance, "mail_plugins", "",
				  SETTINGS_OVERRIDE_TYPE_CODE);
	}
	if (ret > 0) {
		mail_storage_service_update_chroot(user);
		/* Settings may have changed in the parser */
		if (settings_get(event, &mail_user_setting_parser_info,
				 0, &user_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"%s (probably caused by userdb)", error);
			ret = -2;
		} else {
			settings_free(user->user_set);
			user->user_set = user_set;
		}
	}
	pool_unref(&temp_pool);

	/* load per-user plugins */
	if (ret > 0) {
		if (mail_storage_service_load_modules(ctx, user->user_set,
						      error_r) < 0) {
			ret = -2;
		}
	}

	if (ret < 0)
		mail_storage_service_user_unref(&user);
	else {
		/* The context points to a variable in stack, so it can't be
		   used anymore. */
		event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK, NULL);
		event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT, NULL);
	}
	*user_r = user;
	return ret;
}

int mail_storage_service_lookup(struct mail_storage_service_ctx *ctx,
				const struct mail_storage_service_input *input,
				struct mail_storage_service_user **user_r,
				const char **error_r)
{
	char *old_log_prefix = i_strdup(i_get_failure_prefix());
	bool update_log_prefix;
	int ret;

	if (io_loop_get_current_context(current_ioloop) == NULL) {
		/* no user yet. log prefix should be just "imap:" or something
		   equally unhelpful. we don't know the proper log format yet,
		   but initialize it to something better until we know it. */
		const char *session_id =
			input->session_id != NULL ? input->session_id :
			(input->session_id_prefix != NULL ?
			 input->session_id_prefix : NULL);
		i_set_failure_prefix("%s(%s%s%s): ",
			master_service_get_name(ctx->service), input->username,
			session_id == NULL ? "" : t_strdup_printf(",%s", session_id),
			input->remote_ip.family == 0 ? "" :
				t_strdup_printf(",%s", net_ip2addr(&input->remote_ip)));
		update_log_prefix = TRUE;
	} else {
		/* we might be here because we're doing a user lookup for a
		   shared user. the log prefix is likely already usable, so
		   just append our own without replacing the whole thing. */
		i_set_failure_prefix("%suser-lookup(%s): ",
				     old_log_prefix, input->username);
		update_log_prefix = FALSE;
	}

	T_BEGIN {
		ret = mail_storage_service_lookup_real(ctx, input,
				update_log_prefix, user_r, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	i_set_failure_prefix("%s", old_log_prefix);
	i_free(old_log_prefix);
	return ret;
}

static int
mail_storage_service_next_real(struct mail_storage_service_ctx *ctx,
			       struct mail_storage_service_user *user,
			       const char *session_id_suffix,
			       struct mail_user **mail_user_r,
			       const char **error_r)
{
	struct mail_storage_service_privileges priv;
	const char *error;
	bool allow_root =
		(user->flags & MAIL_STORAGE_SERVICE_FLAG_ALLOW_ROOT) != 0;
	bool temp_priv_drop =
		(user->flags & MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP) != 0;

	*mail_user_r = NULL;

	if (service_parse_privileges(user, &priv, error_r) < 0)
		return -2;

	if (*user->user_set->mail_home != '/' &&
	    *user->user_set->mail_home != '\0') {
		*error_r = t_strdup_printf(
			"Relative home directory paths not supported: %s",
			user->user_set->mail_home);
		return -2;
	}

	mail_storage_service_init_log(ctx, user);

	/* create ioloop context regardless of logging. it's also used by
	   stats plugin. */
	if (user->ioloop_ctx == NULL) {
		user->ioloop_ctx = io_loop_context_new(current_ioloop);
		io_loop_context_add_callbacks(user->ioloop_ctx,
				      mail_storage_service_io_activate_user_cb,
				      mail_storage_service_io_deactivate_user_cb,
				      user);
	}
	io_loop_context_switch(user->ioloop_ctx);

	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS) == 0) {
		if (service_drop_privileges(user, &priv,
					    allow_root, temp_priv_drop,
					    FALSE, &error) < 0) {
			*error_r = t_strdup_printf(
				"Couldn't drop privileges: %s", error);
			mail_storage_service_io_deactivate_user(user);
			return -1;
		}
		if (!temp_priv_drop ||
		    (user->flags & MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS) != 0)
			restrict_access_allow_coredumps(TRUE);
	}

	/* privileges are dropped. initialize plugins that haven't been
	   initialized yet. */
	module_dir_init(mail_storage_service_modules);

	if (mail_storage_service_init_post(ctx, user, &priv,
					   session_id_suffix,
					   mail_user_r, error_r) < 0) {
		mail_storage_service_io_deactivate_user(user);
		if (*mail_user_r != NULL && !user->input.no_free_init_failure)
			mail_user_unref(mail_user_r);
		return -2;
	}
	if (master_service_get_client_limit(master_service) == 1) {
		master_service_set_current_user(master_service, user->input.username);
		user->master_service_user_set = TRUE;
	}
	return 0;
}

int mail_storage_service_next(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user,
			      struct mail_user **mail_user_r,
			      const char **error_r)
{
	return mail_storage_service_next_with_session_suffix(ctx,
							     user,
							     NULL,
							     mail_user_r,
							     error_r);
}

int mail_storage_service_next_with_session_suffix(struct mail_storage_service_ctx *ctx,
						  struct mail_storage_service_user *user,
						  const char *session_id_suffix,
						  struct mail_user **mail_user_r,
						  const char **error_r)
{
	char *old_log_prefix = i_strdup(i_get_failure_prefix());
	int ret;

	T_BEGIN {
		ret = mail_storage_service_next_real(ctx, user,
						     session_id_suffix,
						     mail_user_r, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if ((user->flags & MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT) != 0)
		i_set_failure_prefix("%s", old_log_prefix);
	i_free(old_log_prefix);
	return ret;
}

void mail_storage_service_restrict_setenv(struct mail_storage_service_user *user)
{
	struct mail_storage_service_privileges priv;
	const char *error;

	if (service_parse_privileges(user, &priv, &error) < 0)
		i_fatal("user %s: %s", user->input.username, error);
	if (service_drop_privileges(user, &priv,
				    TRUE, FALSE, TRUE, &error) < 0)
		i_fatal("user %s: %s", user->input.username, error);
}

int mail_storage_service_lookup_next(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input,
				     struct mail_user **mail_user_r,
				     const char **error_r)
{
	struct mail_storage_service_user *user;
	int ret;

	ret = mail_storage_service_lookup(ctx, input, &user, error_r);
	if (ret <= 0) {
		*mail_user_r = NULL;
		return ret;
	}

	ret = mail_storage_service_next(ctx, user, mail_user_r, error_r);
	mail_storage_service_user_unref(&user);
	return ret < 0 ? -1 : 1;
}

void mail_storage_service_user_ref(struct mail_storage_service_user *user)
{
	i_assert(user->refcount > 0);
	user->refcount++;
}

void mail_storage_service_user_unref(struct mail_storage_service_user **_user)
{
	struct mail_storage_service_user *user = *_user;

	*_user = NULL;

	i_assert(user->refcount > 0);
	if (--user->refcount > 0)
		return;

	if (user->ioloop_ctx != NULL) {
		if (io_loop_get_current_context(current_ioloop) == user->ioloop_ctx)
			mail_storage_service_io_deactivate_user(user);
		io_loop_context_remove_callbacks(user->ioloop_ctx,
			mail_storage_service_io_activate_user_cb,
			mail_storage_service_io_deactivate_user_cb, user);
		io_loop_context_unref(&user->ioloop_ctx);
	}

	if (user->master_service_user_set)
		master_service_set_current_user(master_service, NULL);

	settings_free(user->user_set);
	settings_instance_free(&user->set_instance);
	event_unref(&user->event);
	pool_unref(&user->pool);
}

struct mail_storage_service_user *
mail_storage_service_user_dup(const struct mail_storage_service_user *user)
{
	struct mail_storage_service_user *dest =
		p_memdup(user->pool, user, sizeof(*user));
	pool_ref(dest->pool);
	dest->refcount = 1;

	dest->set_instance = settings_instance_dup(user->set_instance);
	dest->event = event_create(event_get_parent(user->event));
	event_set_ptr(dest->event, SETTINGS_EVENT_INSTANCE, dest->set_instance);

	dest->ioloop_ctx = io_loop_context_new(current_ioloop);
	io_loop_context_add_callbacks(dest->ioloop_ctx,
				      mail_storage_service_io_activate_user_cb,
				      mail_storage_service_io_deactivate_user_cb,
				      dest);
	io_loop_context_switch(dest->ioloop_ctx);
	pool_ref(dest->user_set->pool);
	return dest;
}

const char *const *
mail_storage_service_user_get_userdb_fields(struct mail_storage_service_user *user)
{
	return user->input.userdb_fields;
}

void mail_storage_service_init_settings(struct mail_storage_service_ctx *ctx,
					const struct mail_storage_service_input *input)
{
	const struct mail_user_settings *user_set;
	const char *error;

	if (ctx->conn != NULL)
		return;

	struct event *event = input != NULL && input->event_parent != NULL ?
		input->event_parent : master_service_get_event(ctx->service);
	if (settings_get(event, &mail_user_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_EXPAND, &user_set, &error) < 0)
		i_fatal("%s", error);

	mail_storage_service_first_init(ctx, user_set, ctx->flags);
	settings_free(user_set);
}

static int
mail_storage_service_all_iter_deinit(struct mail_storage_service_ctx *ctx)
{
	int ret = 0;

	if (ctx->auth_list != NULL) {
		ret = auth_master_user_list_deinit(&ctx->auth_list);
		auth_master_deinit(&ctx->iter_conn);
	}
	return ret;
}

void mail_storage_service_all_init_mask(struct mail_storage_service_ctx *ctx,
					const char *user_mask_hint)
{
	enum auth_master_flags flags = 0;

	(void)mail_storage_service_all_iter_deinit(ctx);
	mail_storage_service_init_settings(ctx, NULL);

	/* create a new connection, because the iteration might take a while
	   and we might want to do USER lookups during it, which don't mix
	   well in the same connection. */
	if (ctx->debug)
		flags |= AUTH_MASTER_FLAG_DEBUG;
	ctx->iter_conn = auth_master_init(auth_master_get_socket_path(ctx->conn),
					  flags);
	ctx->auth_list = auth_master_user_list_init(ctx->iter_conn,
						    user_mask_hint, NULL);
}

int mail_storage_service_all_next(struct mail_storage_service_ctx *ctx,
				  const char **username_r)
{
	i_assert((ctx->flags & MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP) != 0);

	*username_r = auth_master_user_list_next(ctx->auth_list);
	if (*username_r != NULL)
		return 1;
	return mail_storage_service_all_iter_deinit(ctx);
}

void mail_storage_service_deinit(struct mail_storage_service_ctx **_ctx)
{
	struct mail_storage_service_ctx *ctx = *_ctx;

	*_ctx = NULL;
	(void)mail_storage_service_all_iter_deinit(ctx);
	if (ctx->conn != NULL) {
		if (mail_user_auth_master_conn == ctx->conn)
			mail_user_auth_master_conn = NULL;
		auth_master_deinit(&ctx->conn);
	}

	pool_unref(&ctx->pool);

	module_dir_unload(&mail_storage_service_modules);
	mail_storage_deinit();
	dict_drivers_unregister_builtin();
}

const struct mail_user_settings *
mail_storage_service_user_get_set(struct mail_storage_service_user *user)
{
	return user->user_set;
}

const struct mail_storage_service_input *
mail_storage_service_user_get_input(struct mail_storage_service_user *user)
{
	return &user->input;
}

struct settings_instance *
mail_storage_service_user_get_settings_instance(struct mail_storage_service_user *user)
{
	return user->set_instance;
}

struct mail_storage_service_ctx *
mail_storage_service_user_get_service_ctx(struct mail_storage_service_user *user)
{
	return user->service_ctx;
}

pool_t mail_storage_service_user_get_pool(struct mail_storage_service_user *user)
{
	return user->pool;
}

const char *
mail_storage_service_get_log_prefix(struct mail_storage_service_ctx *ctx)
{
	return ctx->default_log_prefix;
}

enum mail_storage_service_flags
mail_storage_service_get_flags(struct mail_storage_service_ctx *ctx)
{
	return ctx->flags;
}
