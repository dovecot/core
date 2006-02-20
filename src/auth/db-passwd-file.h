#ifndef __DB_PASSWD_FILE_H
#define __DB_PASSWD_FILE_H

struct passwd_user {
	uid_t uid;
	gid_t gid;

	char *home;
        char *password;
        char **extra_fields;
};

struct passwd_file {
        struct db_passwd_file *db;
	pool_t pool;

	char *path;
	time_t stamp;
	off_t size;
	int fd;

	struct hash_table *users;

	const char *first_missing_userdb_info;
	unsigned int missing_userdb_info_count;
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
	unsigned int debug:1;
};

struct passwd_user *
db_passwd_file_lookup(struct db_passwd_file *db, struct auth_request *request);

struct db_passwd_file *
db_passwd_file_init(const char *path, bool userdb, bool debug);
void db_passwd_file_parse(struct db_passwd_file *db);
void db_passwd_file_unref(struct db_passwd_file **db);

#endif
