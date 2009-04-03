/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "restrict-access.h"
#include "deliver.h"
#include "auth-client.h"
#include "auth-master.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sysexits.h>

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

static int set_env(struct auth_user_reply *reply,
		   const char *user, uid_t euid)
{
	const char *extra_groups;
	unsigned int len;

	if (reply->uid == 0) {
		i_error("userdb(%s) returned 0 as uid", user);
		return -1;
	} else if (reply->uid == (uid_t)-1) {
		if (*deliver_set->mail_uid != '\0') {
			if (!parse_uid(deliver_set->mail_uid, &reply->uid) ||
			    reply->uid == 0) {
				i_error("mail_uid setting is invalid");
				return -1;
			}
		} else {
			i_error("User %s is missing UID (set mail_uid)", user);
			return -1;
		}
	}
	if (reply->gid == 0) {
		i_error("userdb(%s) returned 0 as gid", user);
		return -1;
	} else if (reply->gid == (gid_t)-1) {
		if (*deliver_set->mail_gid != '\0') {
			if (!parse_gid(deliver_set->mail_gid, &reply->gid) ||
			    reply->gid == 0) {
				i_error("mail_gid setting is invalid");
				return -1;
			}
		} else {
			i_error("User %s is missing GID (set mail_gid)", user);
			return -1;
		}
	}

	if (euid != reply->uid) {
		env_put(t_strconcat("RESTRICT_SETUID=",
				    dec2str(reply->uid), NULL));
	}
	if (euid == 0 || getegid() != reply->gid) {
		env_put(t_strconcat("RESTRICT_SETGID=",
				    dec2str(reply->gid), NULL));
	}

	if (reply->chroot == NULL)
		reply->chroot = deliver_set->mail_chroot;
	if (reply->chroot != NULL) {
		len = strlen(reply->chroot);
		if (len > 2 && strcmp(reply->chroot + len - 2, "/.") == 0 &&
		    reply->home != NULL &&
		    strncmp(reply->home, reply->chroot, len - 2) == 0) {
			/* strip chroot dir from home dir */
			reply->home += len - 2;
		}
		env_put(t_strconcat("RESTRICT_CHROOT=", reply->chroot, NULL));
	}
	if (reply->home != NULL)
		env_put(t_strconcat("HOME=", reply->home, NULL));

	extra_groups = deliver_set->mail_access_groups;
	if (extra_groups != NULL) {
		env_put(t_strconcat("RESTRICT_SETEXTRAGROUPS=",
				    extra_groups, NULL));
	}
	return 0;
}

int auth_client_lookup_and_restrict(const char *auth_socket, bool debug,
				    const char **user, uid_t euid, pool_t pool,
				    ARRAY_TYPE(const_string) *extra_fields_r)
{
        struct auth_master_connection *conn;
	struct auth_user_reply reply;
	int ret = EX_TEMPFAIL;

	conn = auth_master_init(auth_socket, debug);
	switch (auth_master_user_lookup(conn, *user, "deliver", pool, &reply)) {
	case 0:
		ret = EX_NOUSER;
		break;
	case 1:
		if (set_env(&reply, *user, euid) == 0) {
			*user = p_strdup(pool, reply.user);
			restrict_access_by_env(TRUE);
			ret = EX_OK;
		}
		break;
	}

	*extra_fields_r = reply.extra_fields;
	auth_master_deinit(&conn);
	return ret;
}
