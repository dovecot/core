#ifndef __USERDB_H
#define __USERDB_H

struct user_data {
	pool_t pool;

	char *virtual_user;
	char *home;
	char *mail;

	char *system_user;
	uid_t uid;
	gid_t gid;

	int chroot; /* chroot to home directory */
};

struct userdb_module {
	void (*init)(const char *args);
	void (*deinit)(void);

	struct user_data *(*lookup)(const char *user, const char *realm);
};

extern struct userdb_module *userdb;

extern struct userdb_module userdb_static;
extern struct userdb_module userdb_passwd;
extern struct userdb_module userdb_passwd_file;
extern struct userdb_module userdb_vpopmail;

void userdb_init(void);
void userdb_deinit(void);

#endif
