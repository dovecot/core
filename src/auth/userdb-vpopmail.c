/* Copyright (C) 2002-2003 Timo Sirainen */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined(PASSDB_VPOPMAIL) || defined(USERDB_VPOPMAIL)

#include "common.h"
#include "userdb.h"
#include "userdb-vpopmail.h"

struct vqpasswd *vpopmail_lookup_vqp(const char *user,
				     char vpop_user[VPOPMAIL_LIMIT],
				     char vpop_domain[VPOPMAIL_LIMIT])
{
	struct vqpasswd *vpw;

	/* vpop_user must be zero-filled or parse_email() leaves an
	   extra character after the user name. we'll fill vpop_domain
	   as well just to be sure... */
	memset(vpop_user, '\0', VPOPMAIL_LIMIT);
	memset(vpop_domain, '\0', VPOPMAIL_LIMIT);

	if (parse_email(t_strdup_noconst(user), vpop_user, vpop_domain,
			VPOPMAIL_LIMIT-1) < 0) {
		if (verbose) {
			i_info("vpopmail(%s): parse_email() failed",
			       user);
		}
		return NULL;
	}

	vpw = vauth_getpw(vpop_user, vpop_domain);
	if (vpw == NULL) {
		if (verbose) {
			i_info("vpopmail(%s): unknown user (%s@%s)",
			       user, vpop_user, vpop_domain);
		}
		return NULL;
	}

	return vpw;
}

#ifdef USERDB_VPOPMAIL

static void vpopmail_lookup(const char *user, userdb_callback_t *callback,
			    void *context)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
        struct user_data data;
	uid_t uid;
	gid_t gid;
	pool_t pool;

	vpw = vpopmail_lookup_vqp(user, vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(NULL, context);
		return;
	}

	/* we have to get uid/gid separately, because the gid field in
	   struct vqpasswd isn't really gid at all but just some flags... */
	if (vget_assign(vpop_domain, NULL, 0, &uid, &gid) == NULL) {
		if (verbose) {
			i_info("vpopmail(%s): vget_assign(%s) failed",
			       user, vpop_domain);
		}
		callback(NULL, context);
		return;
	}

	if (vpw->pw_dir == NULL || vpw->pw_dir[0] == '\0') {
		/* user's homedir doesn't exist yet, create it */
		if (verbose) {
			i_info("vpopmail(%s): pw_dir isn't set, creating",
			       user);
		}

		if (make_user_dir(vpop_user, vpop_domain, uid, gid) == NULL) {
			i_error("vpopmail(%s): make_user_dir(%s, %s) failed",
				user, vpop_user, vpop_domain);
			callback(NULL, context);
			return;
		}

		/* get the user again so pw_dir is visible */
		vpw = vauth_getpw(vpop_user, vpop_domain);
		if (vpw == NULL) {
			callback(NULL, context);
			return;
		}
	}

	memset(&data, 0, sizeof(data));
	data.uid = uid;
	data.gid = gid;

	data.virtual_user = vpw->pw_name;
	data.home = vpw->pw_dir;

	callback(&data, context);
}

struct userdb_module userdb_vpopmail = {
	NULL, NULL,
	vpopmail_lookup
};

#endif
#endif
