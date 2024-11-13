#ifndef DB_PASSWD_FILE_H
#define DB_PASSWD_FILE_H

#include "hash.h"

struct passwd_user {
	uid_t uid;
	gid_t gid;

	const char *home;
	const char *password;
	const char *const *extra_fields;
};

struct passwd_file {
        struct db_passwd_file *db;
	pool_t pool;
	int refcount;
	struct event *event;

	time_t last_sync_time;
	char *path;
	time_t stamp;
	off_t size;
	int fd;

	HASH_TABLE(char *, struct passwd_user *) users;
};

struct db_passwd_file {
	struct db_passwd_file *next;

	int refcount;
	struct event *event;

	char *path;
	struct var_expand_program *prog;
	HASH_TABLE(char *, struct passwd_file *) files;
        struct passwd_file *default_file;

	bool vars:1;
	bool userdb:1;
	bool userdb_warn_missing:1;
};

struct passwd_file_settings {
	pool_t pool;
	const char *passwd_file_path;
};

extern const struct setting_parser_info passwd_file_setting_parser_info;

extern const struct var_expand_provider db_passwd_file_var_expand_fn[];

int db_passwd_fix_path(const char *path, const char **path_r,
		       const char *orig_path, const char **error_r);
int db_passwd_file_lookup(struct db_passwd_file *db,
			  struct auth_request *request,
			  const char *username_format,
			  struct passwd_user **user_r);

struct db_passwd_file *
db_passwd_file_init(const char *path, bool userdb, bool debug);
void db_passwd_file_parse(struct db_passwd_file *db);
void db_passwd_file_unref(struct db_passwd_file **db);

#endif
