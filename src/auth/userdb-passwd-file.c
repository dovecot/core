/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERDB_PASSWD_FILE

#include "common.h"
#include "userdb.h"
#include "db-passwd-file.h"

struct passwd_file *userdb_pwf = NULL;

static void passwd_file_lookup(const char *user, userdb_callback_t *callback,
			       void *context)
{
	struct user_data data;
	struct passwd_user *pu;

	pu = db_passwd_file_lookup(userdb_pwf, user);
	if (pu == NULL) {
		callback(NULL, context);
		return;
	}

	memset(&data, 0, sizeof(data));
	data.uid = pu->uid;
	data.gid = pu->gid;

	data.virtual_user = user;
	data.home = pu->home;
	data.mail = pu->mail;

	data.chroot = pu->chroot;

	callback(&data, context);
}

static void passwd_file_init(const char *args)
{
	if (passdb_pwf != NULL && strcmp(passdb_pwf->path, args) == 0) {
		userdb_pwf = passdb_pwf;
                userdb_pwf->refcount++;
	} else {
		userdb_pwf = db_passwd_file_parse(args);
	}
}

static void passwd_file_deinit(void)
{
	db_passwd_file_unref(userdb_pwf);
}

struct userdb_module userdb_passwd_file = {
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_lookup
};

#endif
