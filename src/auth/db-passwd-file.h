#ifndef __DB_PASSWD_FILE_H
#define __DB_PASSWD_FILE_H

struct passwd_user {
	char *user_realm; /* user@realm */
	const char *realm; /* NULL or points to user_realm */

	uid_t uid;
	gid_t gid;

	char *home;
	char *mail;

	char *password;

	unsigned int chroot:1;
};

struct passwd_file {
	int refcount;
	pool_t pool;

	char *path;
	time_t stamp;
	int fd;
	int userdb;

	struct hash_table *users;
};

extern struct passwd_file *userdb_pwf;
extern struct passwd_file *passdb_pwf;

struct passwd_user *
db_passwd_file_lookup(struct passwd_file *pw, const char *user);

struct passwd_file *db_passwd_file_parse(const char *path, int userdb);
void db_passwd_file_unref(struct passwd_file *pw);

#endif
