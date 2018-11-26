#ifndef DB_PASSWD_FILE_H
#define DB_PASSWD_FILE_H

#include "hash.h"

#define PASSWD_FILE_DEFAULT_USERNAME_FORMAT "%u"
#define PASSWD_FILE_DEFAULT_SCHEME "CRYPT"

struct passwd_user {
	uid_t uid;
	gid_t gid;

	char *username;
	char *home;
        char *password;
        char **extra_fields;
};

struct passwd_file {
        struct db_passwd_file *db;
	pool_t pool;
	int refcount;

	time_t last_sync_time;
	char *path;
	time_t stamp;
	off_t size;
	int fd;

	HASH_TABLE(char *, struct passwd_user *) users;
	HASH_TABLE(char *, char *) aliases;
};

struct db_passwd_file {
	struct db_passwd_file *next;

	int refcount;

	char *path;
	HASH_TABLE(char *, struct passwd_file *) files;
        struct passwd_file *default_file;

	bool vars:1;
	bool userdb:1;
	bool userdb_warn_missing:1;
	bool debug:1;
};

int db_passwd_file_lookup(struct db_passwd_file *db,
			  struct auth_request *request,
			  const char *username_format,
			  struct passwd_user **user_r);

struct db_passwd_file *
db_passwd_file_init(const char *path, bool userdb, bool debug);
void db_passwd_file_parse(struct db_passwd_file *db);
void db_passwd_file_unref(struct db_passwd_file **db);

#endif
