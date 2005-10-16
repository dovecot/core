/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"

#ifdef USERDB_PASSWD_FILE

#include "str.h"
#include "userdb.h"
#include "db-passwd-file.h"

struct db_passwd_file *userdb_pwf = NULL;

static void passwd_file_lookup(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct auth_stream_reply *reply;
	struct passwd_user *pu;

	pu = db_passwd_file_lookup(userdb_pwf, auth_request);
	if (pu == NULL) {
		callback(NULL, auth_request);
		return;
	}

	reply = auth_stream_reply_init(auth_request);
	auth_stream_reply_add(reply, NULL, auth_request->user);
	auth_stream_reply_add(reply, "uid", dec2str(pu->uid));
	auth_stream_reply_add(reply, "gid", dec2str(pu->gid));

	if (pu->home != NULL)
		auth_stream_reply_add(reply, "home", pu->home);
	if (pu->mail != NULL)
		auth_stream_reply_add(reply, "mail", pu->mail);

	callback(reply, auth_request);
}

static void passwd_file_init(const char *args)
{
	userdb_pwf = db_passwd_file_parse(args, TRUE);
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
