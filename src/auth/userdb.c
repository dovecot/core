/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "ipwd.h"
#include "auth-worker-server.h"
#include "userdb.h"

static ARRAY(struct userdb_module_interface *) userdb_interfaces;
static ARRAY(struct userdb_module *) userdb_modules;

static const struct userdb_module_interface userdb_iface_deinit = {
	.name = "deinit"
};

static struct userdb_module_interface *userdb_interface_find(const char *name)
{
	struct userdb_module_interface *const *ifaces;

	array_foreach(&userdb_interfaces, ifaces) {
		struct userdb_module_interface *iface = *ifaces;

		if (strcmp(iface->name, name) == 0)
			return iface;
	}
	return NULL;
}

void userdb_register_module(struct userdb_module_interface *iface)
{
	struct userdb_module_interface *old_iface;

	old_iface = userdb_interface_find(iface->name);
	if (old_iface != NULL && old_iface->lookup == NULL) {
		/* replacing a "support not compiled in" userdb */
		userdb_unregister_module(old_iface);
	} else if (old_iface != NULL) {
		i_panic("userdb_register_module(%s): Already registered",
			iface->name);
	}
	array_push_back(&userdb_interfaces, &iface);
}

void userdb_unregister_module(struct userdb_module_interface *iface)
{
	struct userdb_module_interface *const *ifaces;
	unsigned int idx;

	array_foreach(&userdb_interfaces, ifaces) {
		if (*ifaces == iface) {
			idx = array_foreach_idx(&userdb_interfaces, ifaces);
			array_delete(&userdb_interfaces, idx, 1);
			return;
		}
	}
	i_panic("userdb_unregister_module(%s): Not registered", iface->name);
}

uid_t userdb_parse_uid(struct auth_request *request, const char *str)
{
	struct passwd pw;
	uid_t uid;

	if (str == NULL)
		return (uid_t)-1;

	if (str_to_uid(str, &uid) == 0)
		return uid;

	switch (i_getpwnam(str, &pw)) {
	case -1:
		i_error("getpwnam() failed: %m");
		return (uid_t)-1;
	case 0:
		if (request != NULL) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
					       "Invalid UID value '%s'", str);
		}
		return (uid_t)-1;
	default:
		return pw.pw_uid;
	}
}

gid_t userdb_parse_gid(struct auth_request *request, const char *str)
{
	struct group gr;
	gid_t gid;

	if (str == NULL)
		return (gid_t)-1;

	if (str_to_gid(str, &gid) == 0)
		return gid;

	switch (i_getgrnam(str, &gr)) {
	case -1:
		i_error("getgrnam() failed: %m");
		return (gid_t)-1;
	case 0:
		if (request != NULL) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
					       "Invalid GID value '%s'", str);
		}
		return (gid_t)-1;
	default:
		return gr.gr_gid;
	}
}

static struct userdb_module *
userdb_find(const char *driver, const char *args, unsigned int *idx_r)
{
	struct userdb_module *const *userdbs;
	unsigned int i, count;

	userdbs = array_get(&userdb_modules, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(userdbs[i]->iface->name, driver) == 0 &&
		    strcmp(userdbs[i]->args, args) == 0) {
			*idx_r = i;
			return userdbs[i];
		}
	}
	return NULL;
}

struct userdb_module *
userdb_preinit(pool_t pool, const struct auth_userdb_settings *set)
{
	static unsigned int auth_userdb_id = 0;
	struct userdb_module_interface *iface;
	struct userdb_module *userdb;
	unsigned int idx;

	iface = userdb_interface_find(set->driver);
	if (iface == NULL || iface->lookup == NULL) {
		/* maybe it's a plugin. try to load it. */
		auth_module_load(t_strconcat("authdb_", set->driver, NULL));
		iface = userdb_interface_find(set->driver);
	}
	if (iface == NULL)
		i_fatal("Unknown userdb driver '%s'", set->driver);
	if (iface->lookup == NULL) {
		i_fatal("Support not compiled in for userdb driver '%s'",
			set->driver);
	}
	if (iface->preinit == NULL && iface->init == NULL &&
	    *set->args != '\0') {
		i_fatal("userdb %s: No args are supported: %s",
			set->driver, set->args);
	}

	userdb = userdb_find(set->driver, set->args, &idx);
	if (userdb != NULL)
		return userdb;

	if (iface->preinit == NULL)
		userdb = p_new(pool, struct userdb_module, 1);
	else
		userdb = iface->preinit(pool, set->args);
	userdb->id = ++auth_userdb_id;
	userdb->iface = iface;
	userdb->args = p_strdup(pool, set->args);

	array_push_back(&userdb_modules, &userdb);
	return userdb;
}

void userdb_init(struct userdb_module *userdb)
{
	if (userdb->iface->init != NULL && userdb->init_refcount == 0)
		userdb->iface->init(userdb);
	userdb->init_refcount++;
}

void userdb_deinit(struct userdb_module *userdb)
{
	unsigned int idx;

	i_assert(userdb->init_refcount > 0);

	if (--userdb->init_refcount > 0)
		return;

	if (userdb_find(userdb->iface->name, userdb->args, &idx) == NULL)
		i_unreached();
	array_delete(&userdb_modules, idx, 1);

	if (userdb->iface->deinit != NULL)
		userdb->iface->deinit(userdb);

	/* make sure userdb isn't accessed again */
	userdb->iface = &userdb_iface_deinit;
}

void userdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN])
{
	struct md5_context ctx;
	struct userdb_module *const *userdbs;
	unsigned int i, count;

	md5_init(&ctx);
	userdbs = array_get(&userdb_modules, &count);
	for (i = 0; i < count; i++) {
		md5_update(&ctx, &userdbs[i]->id, sizeof(userdbs[i]->id));
		md5_update(&ctx, userdbs[i]->iface->name,
			   strlen(userdbs[i]->iface->name));
		md5_update(&ctx, userdbs[i]->args, strlen(userdbs[i]->args));
	}
	md5_final(&ctx, md5);
}

const char *userdb_result_to_string(enum userdb_result result)
{
	switch (result) {
	case USERDB_RESULT_INTERNAL_FAILURE:
		return "internal_failure";
	case USERDB_RESULT_USER_UNKNOWN:
		return "user_unknown";
	case USERDB_RESULT_OK:
		return "ok";
	}
	i_unreached();
}

extern struct userdb_module_interface userdb_prefetch;
extern struct userdb_module_interface userdb_static;
extern struct userdb_module_interface userdb_passwd;
extern struct userdb_module_interface userdb_passwd_file;
extern struct userdb_module_interface userdb_vpopmail;
extern struct userdb_module_interface userdb_ldap;
extern struct userdb_module_interface userdb_sql;
extern struct userdb_module_interface userdb_checkpassword;
extern struct userdb_module_interface userdb_dict;
#ifdef HAVE_LUA
extern struct userdb_module_interface userdb_lua;
#endif

void userdbs_init(void)
{
	i_array_init(&userdb_interfaces, 16);
	i_array_init(&userdb_modules, 16);
	userdb_register_module(&userdb_passwd);
	userdb_register_module(&userdb_passwd_file);
	userdb_register_module(&userdb_prefetch);
	userdb_register_module(&userdb_static);
	userdb_register_module(&userdb_vpopmail);
	userdb_register_module(&userdb_ldap);
	userdb_register_module(&userdb_sql);
	userdb_register_module(&userdb_checkpassword);
	userdb_register_module(&userdb_dict);
#ifdef HAVE_LUA
	userdb_register_module(&userdb_lua);
#endif
}

void userdbs_deinit(void)
{
	array_free(&userdb_modules);
	array_free(&userdb_interfaces);
}
