#ifndef __PASSWD_FILE_H
#define __PASSWD_FILE_H

enum password_type {
	PASSWORD_NONE,
	PASSWORD_DES,
	PASSWORD_MD5,
	PASSWORD_DIGEST_MD5
};

struct passwd_user {
	char *user_realm; /* user@realm */
	const char *realm; /* NULL or points to user_realm */

	uid_t uid;
	gid_t gid;

	char *home;
	char *mail;

	enum password_type password_type;
	char *password;

	unsigned int chroot:1;
};

struct passwd_file {
	int refcount;
	pool_t pool;

	char *path;
	time_t stamp;
	int fd;

	struct hash_table *users;
};

extern struct passwd_file *userdb_pwf;
extern struct passwd_file *passdb_pwf;

struct passwd_user *
passwd_file_lookup_user(struct passwd_file *pw,
			const char *user, const char *realm);

struct passwd_file *passwd_file_parse(const char *path);
void passwd_file_unref(struct passwd_file *pw);

#endif
