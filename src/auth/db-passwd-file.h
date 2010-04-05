#ifndef DB_PASSWD_FILE_H
#define DB_PASSWD_FILE_H

#define PASSWD_FILE_DEFAULT_USERNAME_FORMAT "%u"
#define PASSWD_FILE_DEFAULT_SCHEME "CRYPT"

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
	int refcount;

	char *path;
	time_t stamp;
	off_t size;
	int fd;

	struct hash_table *users;
};

struct db_passwd_file {
	struct db_passwd_file *next;

	int refcount;

	char *path;
	struct hash_table *files;
        struct passwd_file *default_file;

	unsigned int vars:1;
	unsigned int userdb:1;
	unsigned int debug:1;
};

struct passwd_user *
db_passwd_file_lookup(struct db_passwd_file *db, struct auth_request *request,
		      const char *username_format);

struct db_passwd_file *
db_passwd_file_init(const char *path, bool userdb, bool debug);
void db_passwd_file_parse(struct db_passwd_file *db);
void db_passwd_file_unref(struct db_passwd_file **db);

#endif
