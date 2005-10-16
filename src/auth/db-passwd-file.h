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
};

struct passwd_file {
        struct db_passwd_file *db;
	pool_t pool;

	char *path;
	time_t stamp;
	int fd;

	struct hash_table *users;
};

struct db_passwd_file {
	struct db_passwd_file *next;

	int refcount;

	char *path;
	struct hash_table *files;
        struct passwd_file *default_file;

	unsigned int domain_var:1;
	unsigned int vars:1;
	unsigned int userdb:1;
};

struct passwd_user *
db_passwd_file_lookup(struct db_passwd_file *db, struct auth_request *request);

struct db_passwd_file *db_passwd_file_parse(const char *path, int userdb);
void db_passwd_file_unref(struct db_passwd_file *db);

#endif
