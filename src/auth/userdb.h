#ifndef __USERDB_H
#define __USERDB_H

struct user_data {
	const char *virtual_user;
	const char *home;
	const char *mail;

	const char *system_user;
	uid_t uid;
	gid_t gid;

	int chroot; /* chroot to home directory */
};

typedef void userdb_callback_t(struct user_data *user, void *context);

struct userdb_module {
	void (*init)(const char *args);
	void (*deinit)(void);

	void (*lookup)(const char *user, const char *realm,
		       userdb_callback_t *callback, void *context);
};

extern struct userdb_module *userdb;

extern struct userdb_module userdb_static;
extern struct userdb_module userdb_passwd;
extern struct userdb_module userdb_passwd_file;
extern struct userdb_module userdb_vpopmail;

void userdb_init(void);
void userdb_deinit(void);

#endif
