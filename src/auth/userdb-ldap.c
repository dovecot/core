/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_LDAP

#include "common.h"
#include "db-ldap.h"
#include "userdb.h"

#include <ldap.h>
#include <stdlib.h>

/* using posixAccount */
#define DEFAULT_ATTRIBUTES "uid,homeDirectory,,uid,uidNumber,gidNumber"

enum ldap_user_attr {
	ATTR_VIRTUAL_USER = 0,
	ATTR_HOME,
	ATTR_MAIL,
	ATTR_SYSTEM_USER,
	ATTR_UID_NUMBER,
	ATTR_GID_NUMBER,
	ATTR_CHROOT,

	ATTR_COUNT
};

struct userdb_ldap_connection {
	struct ldap_connection *conn;

        unsigned int *attrs;
	char **attr_names;
};

struct userdb_ldap_request {
	struct ldap_request request;
        userdb_callback_t *userdb_callback;
};

static struct userdb_ldap_connection *userdb_ldap_conn;

static void parse_attr(struct userdb_ldap_connection *conn,
		       struct user_data *user,
		       const char *attr, const char *value)
{
	enum ldap_user_attr i;

	for (i = 0; i < ATTR_COUNT; i++) {
		if (strcasecmp(conn->attr_names[i], attr) == 0)
			break;
	}

	if (i == ATTR_COUNT) {
		i_error("LDAP: Unknown attribute '%s'", attr);
		return;
	}

	switch (conn->attrs[i]) {
	case ATTR_VIRTUAL_USER:
		user->virtual_user = t_strdup(value);
		break;
	case ATTR_HOME:
		user->home = t_strdup(value);
		break;
	case ATTR_MAIL:
		user->mail = t_strdup(value);
		break;
	case ATTR_SYSTEM_USER:
		user->system_user = t_strdup(value);
		break;
	case ATTR_UID_NUMBER:
		user->uid = atoi(value);
		break;
	case ATTR_GID_NUMBER:
		user->gid = atoi(value);
		break;
	case ATTR_CHROOT:
		user->chroot = value[0] == 'Y' || value[0] == 'y';
		break;

	case ATTR_COUNT:
		break;
	}
}

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct userdb_ldap_request *urequest =
		(struct userdb_ldap_request *) request;
	struct user_data user;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr, **vals;

	entry = ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		i_error("LDAP: ldap_first_entry failed()");
		return;
	}

	t_push();
	memset(&user, 0, sizeof(user));

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		vals = ldap_get_values(conn->ld, entry, attr);
		if (vals != NULL && vals[0] != NULL && vals[1] == NULL)
			parse_attr(userdb_ldap_conn, &user, attr, vals[0]);
		ldap_value_free(vals);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	if (user.virtual_user == NULL)
		i_error("LDAP: No username in reply");
	else {
		if (ldap_next_entry(conn->ld, entry) != NULL) {
			i_error("LDAP: Multiple replies found for user %s",
				user.virtual_user);
		} else {
			urequest->userdb_callback(&user, request->context);
		}
	}

	t_pop();
}

static void userdb_ldap_lookup(const char *user, const char *realm,
			       userdb_callback_t *callback, void *context)
{
	struct ldap_connection *conn = userdb_ldap_conn->conn;
	struct userdb_ldap_request *request;
	const char *filter;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);

	if (conn->set.filter == NULL) {
		filter = t_strdup_printf("(&(objectClass=posixAccount)(%s=%s))",
			userdb_ldap_conn->attr_names[ATTR_VIRTUAL_USER], user);
	} else {
		filter = t_strdup_printf("(&%s(%s=%s))", conn->set.filter,
			userdb_ldap_conn->attr_names[ATTR_VIRTUAL_USER], user);
	}

	request = i_new(struct userdb_ldap_request, 1);
	request->request.callback = handle_request;
	request->request.context = context;
	request->userdb_callback = callback;

	db_ldap_search(conn, conn->set.base, LDAP_SCOPE_SUBTREE,
		       filter, userdb_ldap_conn->attr_names,
		       &request->request);
}

static void userdb_ldap_init(const char *args)
{
	struct ldap_connection *conn;

	userdb_ldap_conn = i_new(struct userdb_ldap_connection, 1);
	userdb_ldap_conn->conn = conn = db_ldap_init(args);

	db_ldap_set_attrs(conn, conn->set.attrs ?
			  conn->set.attrs : DEFAULT_ATTRIBUTES,
			  &userdb_ldap_conn->attrs,
			  &userdb_ldap_conn->attr_names);
}

static void userdb_ldap_deinit(void)
{
	db_ldap_unref(userdb_ldap_conn->conn);
	i_free(userdb_ldap_conn);
}

struct userdb_module userdb_ldap = {
	userdb_ldap_init,
	userdb_ldap_deinit,

	userdb_ldap_lookup
};

#endif
