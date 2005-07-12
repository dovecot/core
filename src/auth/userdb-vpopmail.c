/* Copyright (C) 2002-2003 Timo Sirainen */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "common.h"

#if defined(PASSDB_VPOPMAIL) || defined(USERDB_VPOPMAIL)

#include "userdb.h"
#include "userdb-vpopmail.h"

struct vqpasswd *vpopmail_lookup_vqp(struct auth_request *request,
				     char vpop_user[VPOPMAIL_LIMIT],
				     char vpop_domain[VPOPMAIL_LIMIT])
{
	struct vqpasswd *vpw;

	/* vpop_user must be zero-filled or parse_email() leaves an
	   extra character after the user name. we'll fill vpop_domain
	   as well just to be sure... */
	memset(vpop_user, '\0', VPOPMAIL_LIMIT);
	memset(vpop_domain, '\0', VPOPMAIL_LIMIT);

	if (parse_email(request->user, vpop_user, vpop_domain,
			VPOPMAIL_LIMIT-1) < 0) {
		auth_request_log_info(request, "vpopmail",
				      "parse_email() failed");
		return NULL;
	}

	vpw = vauth_getpw(vpop_user, vpop_domain);
	if (vpw == NULL) {
		auth_request_log_info(request, "vpopmail", "unknown user");
		return NULL;
	}

	return vpw;
}

#ifdef USERDB_VPOPMAIL

static void vpopmail_lookup(struct auth_request *auth_request,
			    userdb_callback_t *callback)
{
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	const char *result;
	uid_t uid;
	gid_t gid;

	vpw = vpopmail_lookup_vqp(auth_request, vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(NULL, auth_request);
		return;
	}

	/* we have to get uid/gid separately, because the gid field in
	   struct vqpasswd isn't really gid at all but just some flags... */
	if (vget_assign(vpop_domain, NULL, 0, &uid, &gid) == NULL) {
		auth_request_log_info(auth_request, "vpopmail",
				      "vget_assign(%s) failed", vpop_domain);
		callback(NULL, auth_request);
		return;
	}

	if (vpw->pw_dir == NULL || vpw->pw_dir[0] == '\0') {
		/* user's homedir doesn't exist yet, create it */
		auth_request_log_info(auth_request, "vpopmail",
				      "pw_dir isn't set, creating");

		if (make_user_dir(vpop_user, vpop_domain, uid, gid) == NULL) {
			auth_request_log_error(auth_request, "vpopmail",
					       "make_user_dir(%s, %s) failed",
					       vpop_user, vpop_domain);
			callback(NULL, auth_request);
			return;
		}

		/* get the user again so pw_dir is visible */
		vpw = vauth_getpw(vpop_user, vpop_domain);
		if (vpw == NULL) {
			callback(NULL, auth_request);
			return;
		}
	}

	result = t_strdup_printf("%s\tuid=%s\tgid=%s\thome=%s",
				 vpw->pw_name, dec2str(uid), dec2str(gid),
				 vpw->pw_dir);

	callback(result, auth_request);
}

struct userdb_module userdb_vpopmail = {
	"vpopmail",
	FALSE,

	NULL, NULL, NULL,
	vpopmail_lookup
};

#endif
#endif
