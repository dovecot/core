/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "ioloop.h"
#include "net.h"
#include "module-dir.h"
#include "home-expand.h"
#include "file-create-locked.h"
#include "mkdir-parents.h"
#include "safe-mkstemp.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "fs-api.h"
#include "auth-master.h"
#include "master-service.h"
#include "dict.h"
#include "mail-storage-settings.h"
#include "mail-storage-private.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "mail-autoexpunge.h"
#include "mail-user.h"


struct mail_user_module_register mail_user_module_register = { 0 };
struct auth_master_connection *mail_user_auth_master_conn;

static void mail_user_deinit_base(struct mail_user *user)
{
	if (user->_attr_dict != NULL) {
		dict_wait(user->_attr_dict);
		dict_deinit(&user->_attr_dict);
	}
	mail_namespaces_deinit(&user->namespaces);
	if (user->_service_user != NULL)
		mail_storage_service_user_unref(&user->_service_user);
}

static void mail_user_deinit_pre_base(struct mail_user *user ATTR_UNUSED)
{
}

static void mail_user_stats_fill_base(struct mail_user *user ATTR_UNUSED,
				      struct stats *stats ATTR_UNUSED)
{
}

static struct mail_user *
mail_user_alloc_int(struct event *parent_event,
		    const char *username,
		    const struct setting_parser_info *set_info,
		    const struct mail_user_settings *set, pool_t pool)
{
	struct mail_user *user;
	const char *error;

	i_assert(username != NULL);
	i_assert(*username != '\0');

	user = p_new(pool, struct mail_user, 1);
	user->pool = pool;
	user->refcount = 1;
	user->username = p_strdup(pool, username);
	user->set_info = set_info;
	user->unexpanded_set = set;
	user->set = settings_dup_with_pointers(set_info, user->unexpanded_set, pool);
	user->service = master_service_get_name(master_service);
	user->default_normalizer = uni_utf8_to_decomposed_titlecase;
	user->session_create_time = ioloop_time;
	user->event = event_create(parent_event);
	event_add_category(user->event, &event_category_storage);
	event_add_str(user->event, "user", username);

	/* check settings so that the duplicated structure will again
	   contain the parsed fields */
	if (!settings_check(set_info, pool, user->set, &error))
		i_panic("Settings check unexpectedly failed: %s", error);

	user->v.deinit = mail_user_deinit_base;
	user->v.deinit_pre = mail_user_deinit_pre_base;
	user->v.stats_fill = mail_user_stats_fill_base;
	p_array_init(&user->module_contexts, user->pool, 5);
	return user;
}

struct mail_user *
mail_user_alloc_nodup_set(struct event *parent_event,
			  const char *username,
			  const struct setting_parser_info *set_info,
			  const struct mail_user_settings *set)
{
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"mail user", 16*1024);
	return mail_user_alloc_int(parent_event, username, set_info, set, pool);
}

struct mail_user *mail_user_alloc(struct event *parent_event,
				  const char *username,
				  const struct setting_parser_info *set_info,
				  const struct mail_user_settings *set)
{
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"mail user", 16*1024);
	return mail_user_alloc_int(parent_event, username, set_info,
				   settings_dup(set_info, set, pool), pool);
}

static void
mail_user_expand_plugins_envs(struct mail_user *user)
{
	const char **envs, *home, *error;
	string_t *str;
	unsigned int i, count;

	if (!array_is_created(&user->set->plugin_envs))
		return;

	str = t_str_new(256);
	envs = array_get_modifiable(&user->set->plugin_envs, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (user->_home == NULL &&
		    var_has_key(envs[i+1], 'h', "home") &&
		    mail_user_get_home(user, &home) <= 0) {
			user->error = p_strdup_printf(user->pool,
				"userdb didn't return a home directory, "
				"but plugin setting %s used it (%%h): %s",
				envs[i], envs[i+1]);
			return;
		}
		str_truncate(str, 0);
		if (var_expand_with_funcs(str, envs[i+1],
					  mail_user_var_expand_table(user),
					  mail_user_var_expand_func_table, user,
					  &error) <= 0) {
			user->error = p_strdup_printf(user->pool,
				"Failed to expand plugin setting %s = '%s': %s",
				envs[i], envs[i+1], error);
			return;
		}
		envs[i+1] = p_strdup(user->pool, str_c(str));
	}
}

int mail_user_init(struct mail_user *user, const char **error_r)
{
	const struct mail_storage_settings *mail_set;
	const char *home, *key, *value, *error;
	bool need_home_dir;

	need_home_dir = user->_home == NULL &&
		settings_vars_have_key(user->set_info, user->set,
				       'h', "home", &key, &value);
	if (need_home_dir && mail_user_get_home(user, &home) <= 0) {
		user->error = p_strdup_printf(user->pool,
			"userdb didn't return a home directory, "
			"but %s used it (%%h): %s", key, value);
	}

	/* expand settings after we can expand %h */
	if (settings_var_expand_with_funcs(user->set_info, user->set,
					   user->pool, mail_user_var_expand_table(user),
					   mail_user_var_expand_func_table, user,
					   &error) <= 0) {
		user->error = p_strdup_printf(user->pool,
			"Failed to expand settings: %s", error);
	}
	user->settings_expanded = TRUE;
	mail_user_expand_plugins_envs(user);

	/* autocreated users for shared mailboxes need to be fully initialized
	   if they don't exist, since they're going to be used anyway */
	if (user->error == NULL || user->nonexistent) {
		mail_set = mail_user_set_get_storage_set(user);
		user->mail_debug = mail_set->mail_debug;

		user->initialized = TRUE;
		hook_mail_user_created(user);
	}

	if (user->error != NULL) {
		*error_r = t_strdup(user->error);
		return -1;
	}
	return 0;
}

void mail_user_ref(struct mail_user *user)
{
	i_assert(user->refcount > 0);

	user->refcount++;
}

void mail_user_unref(struct mail_user **_user)
{
	struct mail_user *user = *_user;

	i_assert(user->refcount > 0);

	*_user = NULL;
	if (user->refcount > 1) {
		user->refcount--;
		return;
	}

	user->deinitializing = TRUE;

	/* call deinit() and deinit_pre() with refcount=1, otherwise we may
	   assert-crash in mail_user_ref() that is called by some handlers. */
	user->v.deinit_pre(user);
	user->v.deinit(user);
	event_unref(&user->event);
	i_assert(user->refcount == 1);
	pool_unref(&user->pool);
}

struct mail_user *mail_user_find(struct mail_user *user, const char *name)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->owner != NULL && strcmp(ns->owner->username, name) == 0)
			return ns->owner;
	}
	return NULL;
}

static void
mail_user_connection_init_from(struct mail_user_connection_data *conn,
	pool_t pool, const struct mail_user_connection_data *src)
{
	*conn = *src;

	if (src->local_ip != NULL && src->local_ip->family != 0) {
		conn->local_ip = p_new(pool, struct ip_addr, 1);
		*conn->local_ip = *src->local_ip;
	}
	if (src->remote_ip != NULL && src->remote_ip->family != 0) {
		conn->remote_ip = p_new(pool, struct ip_addr, 1);
		*conn->remote_ip = *src->remote_ip;
	}
}

void mail_user_set_vars(struct mail_user *user, const char *service,
			const struct mail_user_connection_data *conn)
{
	i_assert(service != NULL);

	user->service = p_strdup(user->pool, service);
	event_add_str(user->event, "service", service);

	mail_user_connection_init_from(&user->conn, user->pool, conn);
	if (user->conn.local_ip != NULL)
		event_add_str(user->event, "local_ip",
			      net_ip2addr(user->conn.local_ip));
	if (user->conn.remote_ip != NULL)
		event_add_str(user->event, "remote_ip",
			      net_ip2addr(user->conn.remote_ip));
}

const struct var_expand_table *
mail_user_var_expand_table(struct mail_user *user)
{
	/* use a cached table, unless home directory has been set afterwards */
	if (user->var_expand_table != NULL &&
	    user->var_expand_table[4].value == user->_home)
		return user->var_expand_table;

	const char *username =
		p_strdup(user->pool, t_strcut(user->username, '@'));
	const char *domain = i_strchr_to_next(user->username, '@');
	const char *local_ip = user->conn.local_ip == NULL ? NULL :
		p_strdup(user->pool, net_ip2addr(user->conn.local_ip));
	const char *remote_ip = user->conn.remote_ip == NULL ? NULL :
		p_strdup(user->pool, net_ip2addr(user->conn.remote_ip));

	const char *auth_user, *auth_username, *auth_domain;
	if (user->auth_user == NULL) {
		auth_user = user->username;
		auth_username = username;
		auth_domain = domain;
	} else {
		auth_user = user->auth_user;
		auth_username =
			p_strdup(user->pool, t_strcut(user->auth_user, '@'));
		auth_domain = i_strchr_to_next(user->auth_user, '@');
	}

	const struct var_expand_table stack_tab[] = {
		{ 'u', user->username, "user" },
		{ 'n', username, "username" },
		{ 'd', domain, "domain" },
		{ 's', user->service, "service" },
		{ 'h', user->_home /* don't look it up unless we need it */, "home" },
		{ 'l', local_ip, "lip" },
		{ 'r', remote_ip, "rip" },
		{ 'p', my_pid, "pid" },
		{ 'i', p_strdup(user->pool, dec2str(user->uid)), "uid" },
		{ '\0', p_strdup(user->pool, dec2str(user->gid)), "gid" },
		{ '\0', user->session_id, "session" },
		{ '\0', auth_user, "auth_user" },
		{ '\0', auth_username, "auth_username" },
		{ '\0', auth_domain, "auth_domain" },
		{ '\0', user->set->hostname, "hostname" },
		/* NOTE: keep this synced with imap-hibernate's
		   imap_client_var_expand_table() */
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	tab = p_malloc(user->pool, sizeof(stack_tab));
	memcpy(tab, stack_tab, sizeof(stack_tab));

	user->var_expand_table = tab;
	return user->var_expand_table;
}

static int
mail_user_var_expand_func_userdb(const char *data, void *context,
				 const char **value_r,
				 const char **error_r ATTR_UNUSED)
{
	struct mail_user *user = context;

	*value_r = mail_storage_service_fields_var_expand(data, user->userdb_fields);
	return 1;
}

void mail_user_set_home(struct mail_user *user, const char *home)
{
	user->_home = p_strdup(user->pool, home);
	user->home_looked_up = TRUE;
}

void mail_user_add_namespace(struct mail_user *user,
			     struct mail_namespace **namespaces)
{
	struct mail_namespace **tmp, *next, *ns = *namespaces;

	for (; ns != NULL; ns = next) {
		next = ns->next;

		tmp = &user->namespaces;
		for (; *tmp != NULL; tmp = &(*tmp)->next) {
			i_assert(*tmp != ns);
			if (strlen(ns->prefix) < strlen((*tmp)->prefix))
				break;
		}
		ns->next = *tmp;
		*tmp = ns;
	}
	*namespaces = user->namespaces;

	T_BEGIN {
		hook_mail_namespaces_added(user->namespaces);
	} T_END;
}

void mail_user_drop_useless_namespaces(struct mail_user *user)
{
	struct mail_namespace *ns, *next;

	/* drop all autocreated unusable (typically shared) namespaces.
	   don't drop the autocreated prefix="" namespace that we explicitly
	   created for being the fallback namespace. */
	for (ns = user->namespaces; ns != NULL; ns = next) {
		next = ns->next;

		if ((ns->flags & NAMESPACE_FLAG_USABLE) == 0 &&
		    (ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0 &&
		    ns->prefix_len > 0)
			mail_namespace_destroy(ns);
	}
}

const char *mail_user_home_expand(struct mail_user *user, const char *path)
{
	(void)mail_user_try_home_expand(user, &path);
	return path;
}

static int mail_user_userdb_lookup_home(struct mail_user *user)
{
	struct auth_user_info info;
	struct auth_user_reply reply;
	pool_t userdb_pool;
	const char *username, *const *fields;
	int ret;

	i_assert(!user->home_looked_up);

	i_zero(&info);
	info.service = user->service;
	if (user->conn.local_ip != NULL)
		info.local_ip = *user->conn.local_ip;
	if (user->conn.remote_ip != NULL)
		info.remote_ip = *user->conn.remote_ip;

	userdb_pool = pool_alloconly_create("userdb lookup", 2048);
	ret = auth_master_user_lookup(mail_user_auth_master_conn,
				      user->username, &info, userdb_pool,
				      &username, &fields);
	if (ret > 0) {
		auth_user_fields_parse(fields, userdb_pool, &reply);
		user->_home = p_strdup(user->pool, reply.home);
	}
	pool_unref(&userdb_pool);
	return ret;
}

static bool mail_user_get_mail_home(struct mail_user *user)
{
	const char *error, *home = user->set->mail_home;
	string_t *str;

	if (user->settings_expanded) {
		user->_home = home[0] != '\0' ? home : NULL;
		return TRUE;
	}
	/* we're still initializing user. need to do the expansion ourself. */
	i_assert(home[0] == SETTING_STRVAR_UNEXPANDED[0]);
	home++;
	if (home[0] == '\0')
		return TRUE;

	str = t_str_new(128);
	if (var_expand_with_funcs(str, home,
				  mail_user_var_expand_table(user),
				  mail_user_var_expand_func_table, user,
				  &error) <= 0) {
		i_error("Failed to expand mail_home=%s: %s", home, error);
		return FALSE;
	}
	user->_home = p_strdup(user->pool, str_c(str));
	return TRUE;
}

int mail_user_get_home(struct mail_user *user, const char **home_r)
{
	int ret;

	if (user->home_looked_up) {
		*home_r = user->_home;
		return user->_home != NULL ? 1 : 0;
	}

	if (mail_user_auth_master_conn == NULL) {
		/* no userdb connection. we can only use mail_home setting. */
		if (!mail_user_get_mail_home(user))
			return -1;
	} else if ((ret = mail_user_userdb_lookup_home(user)) < 0) {
		/* userdb lookup failed */
		return -1;
	} else if (ret == 0) {
		/* user doesn't exist */
		user->nonexistent = TRUE;
	} else if (user->_home == NULL) {
		/* no home returned by userdb lookup, fallback to
		   mail_home setting. */
		if (!mail_user_get_mail_home(user))
			return -1;
	}
	user->home_looked_up = TRUE;

	*home_r = user->_home;
	return user->_home != NULL ? 1 : 0;
}

bool mail_user_is_plugin_loaded(struct mail_user *user, struct module *module)
{
	const char *const *plugins;
	bool ret;

	T_BEGIN {
		plugins = t_strsplit_spaces(user->set->mail_plugins, ", ");
		ret = str_array_find(plugins, module_get_plugin_name(module));
	} T_END;
	return ret;
}

bool mail_user_plugin_getenv_bool(struct mail_user *user, const char *name)
{
	return mail_user_set_plugin_getenv_bool(user->set, name);
}

bool mail_user_set_plugin_getenv_bool(const struct mail_user_settings *set,
				      const char *name)
{
	const char *env = mail_user_set_plugin_getenv(set, name);

	if (env == NULL)
		return FALSE;
	switch (env[0]) {
		case 'n':
		case 'N':
		case '0':
		case 'f':
		case 'F':
		return FALSE;
	}

	//any other value including empty string will be treated as TRUE.
	return TRUE;
}

const char *mail_user_plugin_getenv(struct mail_user *user, const char *name)
{
	return mail_user_set_plugin_getenv(user->set, name);
}

const char *mail_user_set_plugin_getenv(const struct mail_user_settings *set,
					const char *name)
{
	const char *const *envs;
	unsigned int i, count;

	if (!array_is_created(&set->plugin_envs))
		return NULL;

	envs = array_get(&set->plugin_envs, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(envs[i], name) == 0)
			return envs[i+1];
	}
	return NULL;
}

int mail_user_try_home_expand(struct mail_user *user, const char **pathp)
{
	const char *home, *path = *pathp;

	if (*path != '~') {
		/* no need to expand home */
		return 0;
	}

	if (mail_user_get_home(user, &home) <= 0)
		return -1;

	path = home_expand_tilde(path, home);
	if (path == NULL)
		return -1;

	*pathp = path;
	return 0;
}

void mail_user_set_get_temp_prefix(string_t *dest,
				   const struct mail_user_settings *set)
{
	str_append(dest, set->mail_temp_dir);
	str_append(dest, "/dovecot.");
	str_append(dest, master_service_get_name(master_service));
	str_append_c(dest, '.');
}

int mail_user_lock_file_create(struct mail_user *user, const char *lock_fname,
			       unsigned int lock_secs,
			       struct file_lock **lock_r, const char **error_r)
{
	const char *home, *path;
	int ret;

	if ((ret = mail_user_get_home(user, &home)) < 0) {
		/* home lookup failed - shouldn't really happen */
		*error_r = "Failed to lookup home directory";
		errno = EINVAL;
		return -1;
	}
	if (ret == 0) {
		*error_r = "User has no home directory";
		errno = EINVAL;
		return -1;
	}

	const struct mail_storage_settings *mail_set =
		mail_user_set_get_storage_set(user);
	struct file_create_settings lock_set = {
		.lock_timeout_secs = lock_secs,
		.lock_method = mail_set->parsed_lock_method,
	};
	struct mailbox_list *inbox_list =
		mail_namespace_find_inbox(user->namespaces)->list;
	if (inbox_list->set.volatile_dir == NULL)
		path = t_strdup_printf("%s/%s", home, lock_fname);
	else {
		path = t_strdup_printf("%s/%s", inbox_list->set.volatile_dir,
				       lock_fname);
		lock_set.mkdir_mode = 0700;
	}
	return mail_storage_lock_create(path, &lock_set, mail_set, lock_r, error_r);
}

const char *mail_user_get_anvil_userip_ident(struct mail_user *user)
{
	if (user->conn.remote_ip == NULL)
		return NULL;
	return t_strconcat(net_ip2addr(user->conn.remote_ip), "/",
			   str_tabescape(user->username), NULL);
}

static void
mail_user_try_load_class_plugin(struct mail_user *user, const char *name)
{
	struct module_dir_load_settings mod_set;
	struct module *module;
	size_t name_len = strlen(name);

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.binary_name = master_service_get_name(master_service);
	mod_set.setting_name = "<built-in storage lookup>";
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = user->mail_debug;

	mail_storage_service_modules =
		module_dir_load_missing(mail_storage_service_modules,
					user->set->mail_plugin_dir,
					name, &mod_set);
	/* initialize the module (and only this module!) immediately so that
	   the class gets registered */
	for (module = mail_storage_service_modules; module != NULL; module = module->next) {
		if (strncmp(module->name, name, name_len) == 0 &&
		    strcmp(module->name + name_len, "_plugin") == 0) {
			if (!module->initialized) {
				module->initialized = TRUE;
				module->init(module);
			}
			break;
		}
	}
}

struct mail_storage *
mail_user_get_storage_class(struct mail_user *user, const char *name)
{
	struct mail_storage *storage;

	storage = mail_storage_find_class(name);
	if (storage == NULL || storage->v.alloc != NULL)
		return storage;

	/* it's implemented by a plugin. load it and check again. */
	mail_user_try_load_class_plugin(user, name);

	storage = mail_storage_find_class(name);
	if (storage != NULL && storage->v.alloc == NULL) {
		i_error("Storage driver '%s' exists as a stub, "
			"but its plugin couldn't be loaded", name);
		return NULL;
	}
	return storage;
}

struct mail_user *mail_user_dup(struct mail_user *user)
{
	struct mail_user *user2;

	user2 = mail_user_alloc(event_get_parent(user->event), user->username,
				user->set_info, user->unexpanded_set);
	if (user2->_service_user != NULL) {
		user2->_service_user = user->_service_user;
		mail_storage_service_user_ref(user2->_service_user);
	}
	if (user->_home != NULL)
		mail_user_set_home(user2, user->_home);
	mail_user_set_vars(user2, user->service, &user->conn);
	user2->uid = user->uid;
	user2->gid = user->gid;
	user2->anonymous = user->anonymous;
	user2->admin = user->admin;
	user2->auth_token = p_strdup(user2->pool, user->auth_token);
	user2->auth_user = p_strdup(user2->pool, user->auth_user);
	user2->session_id = p_strdup(user2->pool, user->session_id);
	user2->session_create_time = user->session_create_time;
	user2->userdb_fields = user->userdb_fields == NULL ? NULL :
		p_strarray_dup(user2->pool, user->userdb_fields);
	return user2;
}

void mail_user_init_ssl_client_settings(struct mail_user *user,
				struct ssl_iostream_settings *ssl_set)
{
	const struct mail_storage_settings *mail_set =
		mail_user_set_get_storage_set(user);

	ssl_set->ca_dir = mail_set->ssl_client_ca_dir;
	ssl_set->ca_file = mail_set->ssl_client_ca_file;
	if (*mail_set->ssl_client_cert != '\0')
		ssl_set->cert.cert = mail_set->ssl_client_cert;
	if (*mail_set->ssl_client_key != '\0')
		ssl_set->cert.key = mail_set->ssl_client_key;
	ssl_set->cipher_list = mail_set->ssl_cipher_list;
	ssl_set->curve_list = mail_set->ssl_curve_list;
	ssl_set->min_protocol = mail_set->ssl_min_protocol;
	ssl_set->crypto_device = mail_set->ssl_crypto_device;
	ssl_set->verify_remote_cert = mail_set->ssl_client_require_valid_cert;
	ssl_set->allow_invalid_cert = !ssl_set->verify_remote_cert;
	ssl_set->verbose = mail_set->verbose_ssl;
}

void mail_user_init_fs_settings(struct mail_user *user,
				struct fs_settings *fs_set,
				struct ssl_iostream_settings *ssl_set)
{
	fs_set->username = user->username;
	fs_set->session_id = user->session_id;
	fs_set->base_dir = user->set->base_dir;
	fs_set->temp_dir = user->set->mail_temp_dir;
	fs_set->debug = user->mail_debug;
	fs_set->enable_timing = user->stats_enabled;

	fs_set->ssl_client_set = ssl_set;
	mail_user_init_ssl_client_settings(user, ssl_set);
}

void mail_user_stats_fill(struct mail_user *user, struct stats *stats)
{
	user->v.stats_fill(user, stats);
}

static int
mail_user_home_mkdir_try_ns(struct mail_namespace *ns, const char *home)
{
	const enum mailbox_list_path_type types[] = {
		MAILBOX_LIST_PATH_TYPE_DIR,
		MAILBOX_LIST_PATH_TYPE_ALT_DIR,
		MAILBOX_LIST_PATH_TYPE_CONTROL,
		MAILBOX_LIST_PATH_TYPE_INDEX,
		MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE,
		MAILBOX_LIST_PATH_TYPE_INDEX_CACHE,
		MAILBOX_LIST_PATH_TYPE_LIST_INDEX,
	};
	size_t home_len = strlen(home);
	const char *path;

	for (unsigned int i = 0; i < N_ELEMENTS(types); i++) {
		if (!mailbox_list_get_root_path(ns->list, types[i], &path))
			continue;
		if (strncmp(path, home, home_len) == 0 &&
		    (path[home_len] == '\0' || path[home_len] == '/')) {
			return mailbox_list_mkdir_root(ns->list, path,
						       types[i]) < 0 ? -1 : 1;
		}
	}
	return 0;
}

int mail_user_home_mkdir(struct mail_user *user)
{
	struct mail_namespace *ns;
	const char *home;
	int ret;

	if (mail_user_get_home(user, &home) < 0)
		return -1;

	/* Try to create the home directory by creating the root directory for
	   a namespace that exists under the home. This way we end up in the
	   special mkdir() code in mailbox_list_try_mkdir_root_parent().
	   Start from INBOX, since that's usually the correct place. */
	ns = mail_namespace_find_inbox(user->namespaces);
	if ((ret = mail_user_home_mkdir_try_ns(ns, home)) != 0)
		return ret < 0 ? -1 : 0;
	/* try other namespaces */
	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
			/* already tried the INBOX namespace */
			continue;
		}
		if ((ret = mail_user_home_mkdir_try_ns(ns, home)) != 0)
			return ret < 0 ? -1 : 0;
	}
	/* fallback to a safe mkdir() with 0700 mode */
	if (mkdir_parents(home, 0700) < 0 && errno != EEXIST) {
		i_error("mkdir_parents(%s) failed: %m", home);
		return -1;
	}
	return 0;
}

static const struct var_expand_func_table mail_user_var_expand_func_table_arr[] = {
	{ "userdb", mail_user_var_expand_func_userdb },
	{ NULL, NULL }
};
const struct var_expand_func_table *mail_user_var_expand_func_table =
	mail_user_var_expand_func_table_arr;
