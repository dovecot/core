/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "auth-worker-server.h"
#include "userdb.h"

#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

static ARRAY_DEFINE(userdb_interfaces, struct userdb_module_interface *);

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
	array_append(&userdb_interfaces, &iface, 1);
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
	struct passwd *pw;
	uid_t uid;
	char *p;

	if (str == NULL)
		return (uid_t)-1;

	if (*str >= '0' && *str <= '9') {
		uid = (uid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return uid;
	}

	pw = getpwnam(str);
	if (pw == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid UID value '%s'", str);
		}
		return (uid_t)-1;
	}
	return pw->pw_uid;
}

gid_t userdb_parse_gid(struct auth_request *request, const char *str)
{
	struct group *gr;
	gid_t gid;
	char *p;

	if (str == NULL)
		return (gid_t)-1;

	if (*str >= '0' && *str <= '9') {
		gid = (gid_t)strtoul(str, &p, 10);
		if (*p == '\0')
			return gid;
	}

	gr = getgrnam(str);
	if (gr == NULL) {
		if (request != NULL) {
			auth_request_log_error(request, "userdb",
					       "Invalid GID value '%s'", str);
		}
		return (gid_t)-1;
	}
	return gr->gr_gid;
}

void userdb_preinit(struct auth *auth, struct auth_userdb_settings *set)
{
	struct userdb_module_interface *iface;
        struct auth_userdb *auth_userdb, **dest;

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->auth = auth;
	auth_userdb->args = set->args == NULL ? "" :
		p_strdup(auth->pool, set->args);

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next)
		auth_userdb->num++;
	*dest = auth_userdb;

	iface = userdb_interface_find(set->driver);
	if (iface == NULL)
		i_fatal("Unknown userdb driver '%s'", set->driver);
	if (iface->lookup == NULL) {
		i_fatal("Support not compiled in for userdb driver '%s'",
			set->driver);
	}

	if (iface->preinit == NULL && iface->init == NULL &&
	    *auth_userdb->args != '\0') {
		i_fatal("userdb %s: No args are supported: %s",
			set->driver, auth_userdb->args);
	}

	if (iface->preinit == NULL) {
		auth_userdb->userdb =
			p_new(auth->pool, struct userdb_module, 1);
	} else {
		auth_userdb->userdb =
			iface->preinit(auth_userdb, auth_userdb->args);
	}
	auth_userdb->userdb->iface = iface;
}

void userdb_init(struct auth_userdb *userdb)
{
	if (userdb->userdb->iface->init != NULL)
		userdb->userdb->iface->init(userdb->userdb, userdb->args);
}

void userdb_deinit(struct auth_userdb *userdb)
{
	if (userdb->userdb->iface->deinit != NULL)
		userdb->userdb->iface->deinit(userdb->userdb);
}

extern struct userdb_module_interface userdb_prefetch;
extern struct userdb_module_interface userdb_static;
extern struct userdb_module_interface userdb_passwd;
extern struct userdb_module_interface userdb_passwd_file;
extern struct userdb_module_interface userdb_vpopmail;
extern struct userdb_module_interface userdb_ldap;
extern struct userdb_module_interface userdb_sql;
extern struct userdb_module_interface userdb_nss;
extern struct userdb_module_interface userdb_checkpassword;

void userdbs_init(void)
{
	i_array_init(&userdb_interfaces, 16);
	userdb_register_module(&userdb_passwd);
	userdb_register_module(&userdb_passwd_file);
	userdb_register_module(&userdb_prefetch);
	userdb_register_module(&userdb_static);
	userdb_register_module(&userdb_vpopmail);
	userdb_register_module(&userdb_ldap);
	userdb_register_module(&userdb_sql);
	userdb_register_module(&userdb_nss);
	userdb_register_module(&userdb_checkpassword);
}

void userdbs_deinit(void)
{
	array_free(&userdb_interfaces);
}
