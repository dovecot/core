/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "ipwd.h"
#include "auth-worker-connection.h"
#include "userdb.h"

static ARRAY(struct userdb_module_interface *) userdb_interfaces;
static ARRAY(struct userdb_module *) userdb_modules;

static const struct userdb_module_interface userdb_iface_deinit = {
	.name = "deinit"
};

static struct userdb_module_interface *userdb_interface_find(const char *name)
{
	struct userdb_module_interface *iface;

	array_foreach_elem(&userdb_interfaces, iface) {
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
	unsigned int idx;

	if (!array_lsearch_ptr_idx(&userdb_interfaces, iface, &idx))
		i_panic("userdb_unregister_module(%s): Not registered", iface->name);
	array_delete(&userdb_interfaces, idx, 1);
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
		e_error(request == NULL ? auth_event : authdb_event(request),
			"getpwnam() failed: %m");
		return (uid_t)-1;
	case 0:
		e_error(request == NULL ? auth_event : authdb_event(request),
			"Invalid UID value '%s'", str);
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
		e_error(request == NULL ? auth_event : authdb_event(request),
			"getgrnam() failed: %m");
		return (gid_t)-1;
	case 0:
		e_error(request == NULL ? auth_event : authdb_event(request),
			"Invalid GID value '%s'", str);
		return (gid_t)-1;
	default:
		return gr.gr_gid;
	}
}

struct userdb_module *
userdb_preinit(pool_t pool, struct event *event,
	       const struct auth_userdb_settings *set)
{
	static unsigned int auth_userdb_id = 0;
	struct userdb_module_interface *iface;
	struct userdb_module *userdb;
	const char *error;

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

	if (iface->preinit != NULL) {
		if (iface->preinit(pool, event, &userdb, &error) < 0)
			i_fatal("userdb %s: %s", set->name, error);
		userdb->blocking = set->use_worker;
	} else {
		userdb = p_new(pool, struct userdb_module, 1);
	}
	userdb->id = ++auth_userdb_id;
	userdb->iface = iface;
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
	i_assert(userdb->init_refcount > 0);

	if (--userdb->init_refcount > 0)
		return;

	unsigned int i;
	if (!array_lsearch_ptr_idx(&userdb_modules, userdb, &i))
		i_unreached();
	array_delete(&userdb_modules, i, 1);

	if (userdb->iface->deinit != NULL)
		userdb->iface->deinit(userdb);

	/* make sure userdb isn't accessed again */
	userdb->iface = &userdb_iface_deinit;
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
extern struct userdb_module_interface userdb_ldap;
extern struct userdb_module_interface userdb_sql;
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
	userdb_register_module(&userdb_ldap);
	userdb_register_module(&userdb_sql);
#ifdef HAVE_LUA
	userdb_register_module(&userdb_lua);
#endif
}

void userdbs_deinit(void)
{
	array_free(&userdb_modules);
	array_free(&userdb_interfaces);
}
