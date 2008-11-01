/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "restrict-access.h"
#include "auth-client.h"
#include "auth-master.h"

#include <unistd.h>

static uid_t current_uid = 0;

static void auth_set_env(const char *user, struct auth_user_reply *reply)
{
	const char *const *fields, *key, *value;
	unsigned int i, count;

	if (reply->gid != (gid_t)-1 && getegid() != reply->gid) {
		env_put(t_strconcat("RESTRICT_SETGID=",
				    dec2str(reply->gid), NULL));
	}
	if (reply->chroot != NULL)
		env_put(t_strconcat("RESTRICT_CHROOT=", reply->chroot, NULL));

	if (reply->home == NULL) {
		/* we must have a home directory */
		i_error("userdb(%s) didn't return a home directory", user);
		return;
	}
	if (reply->uid == (uid_t)-1) {
		i_error("userdb(%s) didn't return uid", user);
		return;
	}

	if (reply->uid != current_uid && current_uid != 0) {
		/* we're changing the UID, switch back to root */
		if (seteuid(0) != 0)
			i_fatal("seteuid(0) failed: %m");
		current_uid = 0;
	}

	/* change GID */
	restrict_access_by_env(FALSE);

	/* we'll change only effective UID. This is a bit unfortunate since
	   it allows reverting back to root, but we'll have to be able to
	   access different users' mailboxes.. */
	if (reply->uid != current_uid) {
		if (seteuid(reply->uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(reply->uid));
		current_uid = reply->uid;
	}

	fields = array_get(&reply->extra_fields, &count);
	for (i = 0; i < count; i++) {
		key = t_str_ucase(t_strcut(fields[i], '='));
		value = strchr(fields[i], '=');
		if (value != NULL)
			value++;
		else
			value = "1";
		env_put(t_strconcat(key, "=", value, NULL));
	}
	env_put(t_strconcat("HOME=", reply->home, NULL));
}

int auth_client_put_user_env(struct auth_connection *conn,
			     const char *user)
{
	struct auth_user_reply reply;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("userdb lookup", 512);
	ret = auth_master_user_lookup(conn, user, "expire", pool, &reply);
	if (ret > 0)
		auth_set_env(user, &reply);
	pool_unref(&pool);
	return ret;
}
