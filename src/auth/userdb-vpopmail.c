/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* Thanks to Courier-IMAP for showing how the vpopmail API should be used */

#include "auth-common.h"
#include "userdb.h"

#if defined(PASSDB_VPOPMAIL) || defined(USERDB_VPOPMAIL)
#include "str.h"
#include "var-expand.h"
#include "userdb-vpopmail.h"

struct vpopmail_userdb_module {
	struct userdb_module module;

	const char *quota_template_key;
	const char *quota_template_value;
};

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
		auth_request_log_info(request, AUTH_SUBSYS_DB,
				      "parse_email() failed");
		return NULL;
	}

	auth_request_log_debug(request, AUTH_SUBSYS_DB,
			       "lookup user=%s domain=%s",
			       vpop_user, vpop_domain);

	vpw = vauth_getpw(vpop_user, vpop_domain);
	if (vpw == NULL) {
		auth_request_log_unknown_user(request, AUTH_SUBSYS_DB);
		return NULL;
	}

	return vpw;
}
#endif

#ifdef USERDB_VPOPMAIL
static int
userdb_vpopmail_get_quota(const char *template, const char *vpop_str,
			  const char **quota_r, const char **error_r)
{
	struct var_expand_table *tab;
	string_t *quota;

	if (template == NULL || *vpop_str == '\0' ||
	    strcmp(vpop_str, "NOQUOTA") == 0) {
		*quota_r = "";
		return 0;
	}

	tab = t_new(struct var_expand_table, 2);
	tab[0].key = 'q';
	tab[0].value = format_maildirquota(vpop_str);

	quota = t_str_new(128);
	if (var_expand(quota, template, tab, error_r) < 0)
		return -1;

	*quota_r = str_c(quota);
	return 0;
}

static void vpopmail_lookup(struct auth_request *auth_request,
			    userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct vpopmail_userdb_module *module =
		(struct vpopmail_userdb_module *)_module;
	char vpop_user[VPOPMAIL_LIMIT], vpop_domain[VPOPMAIL_LIMIT];
	struct vqpasswd *vpw;
	const char *quota, *error;
	uid_t uid;
	gid_t gid;

	vpw = vpopmail_lookup_vqp(auth_request, vpop_user, vpop_domain);
	if (vpw == NULL) {
		callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		return;
	}

	/* we have to get uid/gid separately, because the gid field in
	   struct vqpasswd isn't really gid at all but just some flags... */
	if (vget_assign(vpop_domain, NULL, 0, &uid, &gid) == NULL) {
		auth_request_log_info(auth_request, AUTH_SUBSYS_DB,
				      "vget_assign(%s) failed", vpop_domain);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	if (auth_request->successful) {
		/* update the last login only when we're really  */
		vset_lastauth(vpop_user, vpop_domain,
			      t_strdup_noconst(auth_request->service));
	}

	if (vpw->pw_dir == NULL || vpw->pw_dir[0] == '\0') {
		/* user's homedir doesn't exist yet, create it */
		auth_request_log_info(auth_request, AUTH_SUBSYS_DB,
				      "pw_dir isn't set, creating");

		if (make_user_dir(vpop_user, vpop_domain, uid, gid) == NULL) {
			auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
					       "make_user_dir(%s, %s) failed",
					       vpop_user, vpop_domain);
			callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}

		/* get the user again so pw_dir is visible */
		vpw = vauth_getpw(vpop_user, vpop_domain);
		if (vpw == NULL) {
			callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}
	}

	if (userdb_vpopmail_get_quota(module->quota_template_value,
				      vpw->pw_shell, &quota, &error) < 0) {
		auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
				       "userdb_vpopmail_get_quota(%s, %s) failed: %s",
				       module->quota_template_value,
				       vpw->pw_shell, error);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	auth_request_set_userdb_field(auth_request, "uid", dec2str(uid));
	auth_request_set_userdb_field(auth_request, "gid", dec2str(gid));
	auth_request_set_userdb_field(auth_request, "home", vpw->pw_dir);

	if (*quota != '\0') {
		auth_request_set_userdb_field(auth_request,
					      module->quota_template_key,
					      quota);
	}
	callback(USERDB_RESULT_OK, auth_request);
}

static struct userdb_module *
vpopmail_preinit(pool_t pool, const char *args)
{
	struct vpopmail_userdb_module *module;
	const char *const *tmp, *p;

	module = p_new(pool, struct vpopmail_userdb_module, 1);
	module->module.blocking = TRUE;

	for (tmp = t_strsplit(args, " "); *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "cache_key="))
			module->module.default_cache_key =
				p_strdup(pool, *tmp + 10);
		else if (str_begins(*tmp, "quota_template=")) {
			p = strchr(*tmp + 15, '=');
			if (p == NULL) {
				i_fatal("vpopmail userdb: "
					"quota_template missing '='");
			}
			module->quota_template_key =
				p_strdup_until(pool, *tmp + 15, p);
			module->quota_template_value = p_strdup(pool, p + 1);
		} else if (strcmp(*tmp, "blocking=no") == 0) {
			module->module.blocking = FALSE;
		} else
			i_fatal("userdb vpopmail: Unknown setting: %s", *tmp);
	}
	return &module->module;
}

struct userdb_module_interface userdb_vpopmail = {
	"vpopmail",

	vpopmail_preinit,
	NULL,
	NULL,

	vpopmail_lookup,

	NULL,
	NULL,
	NULL
};
#else
struct userdb_module_interface userdb_vpopmail = {
	.name = "vpopmail"
};
#endif
