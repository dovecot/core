/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_PASSWD_FILE

#include "str.h"
#include "userdb.h"
#include "db-passwd-file.h"

struct passwd_file *userdb_pwf = NULL;

static void passwd_file_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct passwd_user *pu;
	string_t *str;

	pu = db_passwd_file_lookup(userdb_pwf, auth_request);
	if (pu == NULL) {
		callback(NULL, auth_request);
		return;
	}

	str = t_str_new(128);
	str_printfa(str, "%s\tuid=%s\tgid=%s",
		    auth_request->user, dec2str(pu->uid), dec2str(pu->gid));

	if (pu->home != NULL)
		str_printfa(str, "\thome=%s", pu->home);
	if (pu->mail != NULL)
		str_printfa(str, "\tmail=%s", pu->mail);

	callback(str_c(str), auth_request);
}

static void passwd_file_init(const char *args)
{
	if (passdb_pwf != NULL && strcmp(passdb_pwf->path, args) == 0) {
		userdb_pwf = passdb_pwf;
		userdb_pwf->refcount++;

		/* resync */
		userdb_pwf->userdb = TRUE;
                userdb_pwf->stamp = 0;
	} else {
		userdb_pwf = db_passwd_file_parse(args, TRUE);
	}
}

static void passwd_file_deinit(void)
{
	db_passwd_file_unref(userdb_pwf);
}

struct userdb_module userdb_passwd_file = {
	"passwd-file",
	FALSE,

	NULL,
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_lookup
};

#endif
