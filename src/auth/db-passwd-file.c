/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)

#include "userdb.h"
#include "db-passwd-file.h"

#include "array.h"
#include "buffer.h"
#include "istream.h"
#include "hash.h"
#include "str.h"
#include "eacces-error.h"
#include "ioloop.h"
#include "path-util.h"
#include "settings.h"

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#define PARSE_TIME_STARTUP_WARN_SECS 60
#define PARSE_TIME_RELOAD_WARN_SECS 10

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct passwd_file_settings)

static const struct setting_define passwd_file_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_passwd_file", },
	{ .type = SET_FILTER_NAME, .key = "userdb_passwd_file", },
	DEF(STR_NOVARS, passwd_file_path),

	SETTING_DEFINE_LIST_END
};

static const struct passwd_file_settings passwd_file_default_settings = {
	.passwd_file_path = "",
};

static const struct setting_keyvalue passwd_file_default_settings_keyvalue[] = {
	{ "passdb_passwd_file/passdb_default_password_scheme", "CRYPT" },
	{ NULL, NULL }
};

const struct setting_parser_info passwd_file_setting_parser_info = {
	.name = "passwd_file",

	.defines = passwd_file_setting_defines,
	.defaults = &passwd_file_default_settings,
	.default_settings = passwd_file_default_settings_keyvalue,

	.struct_size = sizeof(struct passwd_file_settings),
	.pool_offset1 = 1 + offsetof(struct passwd_file_settings, pool),
};

static int db_passwd_file_expand(const char *key, const char **value_r,
				 void *context, const char **error_r)
{
	struct auth_fields *pwd_fields = context;
	*value_r = auth_fields_find(pwd_fields, key);
	if (*value_r == NULL) {
		*error_r = t_strdup_printf("No such field '%s'", key);
		return -1;
	}
	return 0;
}

const struct var_expand_provider db_passwd_file_var_expand_fn[] = {
	{ .key = "passwd_file", .func = db_passwd_file_expand },
	VAR_EXPAND_TABLE_END
};

static struct db_passwd_file *passwd_files;

static void ATTR_NULL(3)
passwd_file_add(struct passwd_file *pw, const char *username,
		const char *pass, const char *const *args)
{
	/* args = uid, gid, user info, home dir, shell, extra_fields */
	struct passwd_user *pu;
	const char *extra_fields = NULL;
	char *user;
	size_t len;

	if (hash_table_lookup(pw->users, username) != NULL) {
		e_error(pw->event, "User %s exists more than once", username);
		return;
	}

	pu = p_new(pw->pool, struct passwd_user, 1);
	user = p_strdup(pw->pool, username);

	len = pass == NULL ? 0 : strlen(pass);
	if (len > 4 && pass[0] != '{' && pass[0] != '$' &&
	    pass[len-1] == ']' && pass[len-4] == '[') {
		/* password[type] - we're being libpam-pwdfile compatible
		   here. it uses 13 = DES and 34 = MD5. For backwards
		   compatibility with ourself, we have also 56 = Digest-MD5. */
		int num = (pass[len-3] - '0') * 10 + (pass[len-2] - '0');

		pass = t_strndup(pass, len-4);
		if (num == 34) {
			pu->password = p_strconcat(pw->pool, "{PLAIN-MD5}",
						   pass, NULL);
		} else if (num == 56) {
			pu->password = p_strconcat(pw->pool, "{DIGEST-MD5}",
						   pass, NULL);
			if (strlen(pu->password) != 32 + 12) {
				e_error(pw->event, "User %s "
					"has invalid password", username);
				return;
			}
		} else {
			pu->password = p_strconcat(pw->pool, "{CRYPT}",
						   pass, NULL);
		}
	} else {
		pu->password = p_strdup(pw->pool, pass);
	}

	pu->uid = (uid_t)-1;
	pu->gid = (gid_t)-1;

	if (*args == NULL)
		;
	else if (!pw->db->userdb || **args == '\0') {
		args++;
	} else {
		pu->uid = userdb_parse_uid(NULL, *args);
		if (pu->uid == 0 || pu->uid == (uid_t)-1) {
			e_error(pw->event, "User %s has invalid UID '%s'",
				username, *args);
			return;
		}
		args++;
	}

	if (*args == NULL) {
		if (pw->db->userdb_warn_missing) {
			e_error(pw->event, "User %s is missing userdb info",
				username);
		}
		/* don't allow userdb lookups */
		pu->uid = 0;
		pu->gid = 0;
	} else if (!pw->db->userdb || **args == '\0')
		args++;
	else {
		pu->gid = userdb_parse_gid(NULL, *args);
		if (pu->gid == 0 || pu->gid == (gid_t)-1) {
			e_error(pw->event, "User %s has invalid GID '%s'",
				username, *args);
			return;
		}
		args++;
	}

	/* user info */
	if (*args != NULL)
		args++;

	/* home */
	if (*args != NULL) {
		if (pw->db->userdb)
			pu->home = p_strdup_empty(pw->pool, *args);
		args++;
	}

	/* shell */
	if (*args != NULL)
		args++;

	if (*args != NULL) {
		/* space separated list of extra fields */
                extra_fields = t_strarray_join(args, ":");
        }

        if (extra_fields != NULL) {
		pu->extra_fields = (const char *const *)
			p_strsplit_spaces(pw->pool, extra_fields, " ");
        }

	hash_table_insert(pw->users, user, pu);
}

static struct passwd_file *
passwd_file_new(struct db_passwd_file *db, const char *expanded_path)
{
	struct passwd_file *pw;

	pw = i_new(struct passwd_file, 1);
	pw->db = db;
	pw->path = i_strdup(expanded_path);
	pw->fd = -1;
	pw->event = event_create(db->event);
	event_set_append_log_prefix(pw->event,
		t_strdup_printf("passwd-file %s:", pw->path));

	if (hash_table_is_created(db->files))
		hash_table_insert(db->files, pw->path, pw);
	return pw;
}

static int passwd_file_open(struct passwd_file *pw, bool startup,
			    const char **error_r)
{
	const char *no_args = NULL;
	struct istream *input;
	const char *line;
	struct stat st;
	time_t start_time, end_time;
	unsigned int time_secs;
	int fd;

	fd = open(pw->path, O_RDONLY);
	if (fd == -1) {
		if (errno == EACCES)
			*error_r = eacces_error_get("open", pw->path);
		else {
			*error_r = t_strdup_printf("open(%s) failed: %m",
						   pw->path);
		}
		return -1;
	}

	if (fstat(fd, &st) != 0) {
		*error_r = t_strdup_printf("fstat(%s) failed: %m",
					   pw->path);
		i_close_fd(&fd);
		return -1;
	}

	pw->fd = fd;
	pw->stamp = st.st_mtime;
	pw->size = st.st_size;

	pw->pool = pool_alloconly_create(MEMPOOL_GROWING"passwd_file", 10240);
	hash_table_create(&pw->users, pw->pool, 0, str_hash, strcmp);

	start_time = time(NULL);
	input = i_stream_create_fd(pw->fd, SIZE_MAX);
	i_stream_set_return_partial_line(input, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line == '\0' || *line == ':' || *line == '#')
			continue; /* no username or comment */

		T_BEGIN {
			const char *const *args = t_strsplit(line, ":");
			if (args[1] != NULL) {
				/* at least username+password */
				passwd_file_add(pw, args[0], args[1], args+2);
			} else {
				/* only username */
				passwd_file_add(pw, args[0], NULL, &no_args);
			}
		} T_END;
	}
	i_stream_destroy(&input);
	end_time = time(NULL);
	time_secs = end_time - start_time;

	if ((time_secs > PARSE_TIME_STARTUP_WARN_SECS && startup) ||
	    (time_secs > PARSE_TIME_RELOAD_WARN_SECS && !startup)) {
		e_warning(pw->event, "Reading %u users took %u secs",
			  hash_table_count(pw->users), time_secs);
	} else {
		e_debug(pw->event, "Read %u users in %u secs",
			hash_table_count(pw->users), time_secs);
	}
	return 0;
}

static void passwd_file_close(struct passwd_file *pw)
{
	i_close_fd_path(&pw->fd, pw->path);

	hash_table_destroy(&pw->users);
	pool_unref(&pw->pool);
}

static void passwd_file_free(struct passwd_file *pw)
{
	if (hash_table_is_created(pw->db->files))
		hash_table_remove(pw->db->files, pw->path);

	passwd_file_close(pw);
	event_unref(&pw->event);
	i_free(pw->path);
	i_free(pw);
}

static int passwd_file_sync(struct auth_request *request,
			    struct passwd_file *pw)
{
	struct stat st;
	const char *error;

	if (pw->last_sync_time == ioloop_time)
		return hash_table_is_created(pw->users) ? 1 : -1;
	pw->last_sync_time = ioloop_time;

	if (stat(pw->path, &st) < 0) {
		/* with variables don't give hard errors, or errors about
		   nonexistent files */
		int ret = -1;

		if (errno == EACCES) {
			e_error(authdb_event(request),
				"%s", eacces_error_get("stat", pw->path));
		} else if (errno == ENOENT) {
			e_info(authdb_event(request),
			       "missing passwd file: %s", pw->path);
			ret = 0;
		} else {
			e_error(authdb_event(request),
				"stat(%s) failed: %m", pw->path);
		}

		if (pw->db->default_file != pw)
			passwd_file_free(pw);
		return ret;
	}

	if (st.st_mtime != pw->stamp || st.st_size != pw->size) {
		passwd_file_close(pw);
		if (passwd_file_open(pw, FALSE, &error) < 0) {
			e_error(authdb_event(request),
				"%s", error);
			return -1;
		}
	}
	return 1;
}

static struct db_passwd_file *db_passwd_file_find(const char *path)
{
	struct db_passwd_file *f;

	for (f = passwd_files; f != NULL; f = f->next) {
		if (strcmp(f->path, path) == 0)
			return f;
	}

	return NULL;
}

static void db_passwd_file_set_userdb(struct db_passwd_file *db)
{
	db->userdb = TRUE;
	/* warn about missing userdb fields only when there aren't any other
	   userdbs. */
	db->userdb_warn_missing =
		array_is_created(&global_auth_settings->userdbs) &&
		array_count(&global_auth_settings->userdbs) == 1;
}

struct db_passwd_file *
db_passwd_file_init(const char *path, bool userdb, bool debug)
{
	const char *error;
	struct db_passwd_file *db;

	db = db_passwd_file_find(path);
	if (db != NULL) {
		db->refcount++;
		if (userdb)
			db_passwd_file_set_userdb(db);
		return db;
	}

	db = i_new(struct db_passwd_file, 1);
	db->refcount = 1;
	if (userdb)
		db_passwd_file_set_userdb(db);
	db->event = event_create(auth_event);
	event_set_forced_debug(db->event, debug);

	struct var_expand_program *prog;
	if (var_expand_program_create(path, &prog, &error) < 0)
		i_fatal("Invalid path '%s' for passwd-file", error);

	const char *const *vars = var_expand_program_variables(prog);
	db->path = i_strdup(path);

	if (*vars != NULL) {
		db->vars = TRUE;
		db->prog = prog;
	} else
		var_expand_program_free(&prog);
	if (db->vars) {
		hash_table_create(&db->files, default_pool, 0,
				  str_hash, strcmp);
	} else {
		db->default_file = passwd_file_new(db, path);
	}

	db->next = passwd_files;
	passwd_files = db;
	return db;
}

void db_passwd_file_parse(struct db_passwd_file *db)
{
	const char *error;

	if (db->default_file != NULL && db->default_file->stamp == 0) {
		/* no variables, open the file immediately */
		if (passwd_file_open(db->default_file, TRUE, &error) < 0)
			e_error(db->default_file->event, "%s", error);
	}
}

void db_passwd_file_unref(struct db_passwd_file **_db)
{
        struct db_passwd_file *db = *_db;
        struct db_passwd_file **p;
	struct hash_iterate_context *iter;
	char *path;
	struct passwd_file *file;

	*_db = NULL;
	i_assert(db->refcount >= 0);
	if (--db->refcount > 0)
		return;

	for (p = &passwd_files; *p != NULL; p = &(*p)->next) {
		if (*p == db) {
			*p = db->next;
			break;
		}
	}
	var_expand_program_free(&db->prog);

	if (db->default_file != NULL)
		passwd_file_free(db->default_file);
	else {
		iter = hash_table_iterate_init(db->files);
		while (hash_table_iterate(iter, db->files, &path, &file))
			passwd_file_free(file);
		hash_table_iterate_deinit(&iter);
		hash_table_destroy(&db->files);
	}
	event_unref(&db->event);
	i_free(db->path);
	i_free(db);
}

int db_passwd_fix_path(const char *path, const char **path_r,
		       const char *orig_path, const char **error_r)
{
	/* normalize path */
	const char *normalized;
	if (t_normpath(path, &normalized, error_r) < 0)
		return -1;

	/* check base path */
	const char *p;
	if (*orig_path != '%' &&
	    (p = strstr(orig_path, "%{")) != NULL) {
		ptrdiff_t len = p - orig_path;
		if (strncmp(orig_path, normalized, len) != 0) {
			*error_r = t_strdup_printf("Path is outside '%s'",
					t_strdup_until(orig_path, p));
			return -1;
		}
	}

	*path_r = normalized;
	return 0;
}

int db_passwd_file_lookup(struct db_passwd_file *db,
			  struct auth_request *request,
			  const char *username_format,
			  struct passwd_user **user_r)
{
	struct passwd_file *pw;
	string_t *username, *dest;
	const char *error;
	int ret;

	if (!db->vars)
		pw = db->default_file;
	else {
		const struct var_expand_params params = {
			.table = auth_request_get_var_expand_table(request),
			.providers = auth_request_var_expand_providers,
			.context = request,
			.event = authdb_event(request),
		};
		dest = t_str_new(256);
		if (var_expand_program_execute(dest, db->prog, &params, &error) < 0) {
			e_error(authdb_event(request),
				"Failed to expand passwd-file path %s: %s",
				db->path, error);
			return -1;
		}
		const char *path;
		if (db_passwd_fix_path(str_c(dest), &path, db->path, &error) < 0) {
			e_info(authdb_event(request), "Failed to normalize path: %s",
				error);
			return 0;
		}
		pw = hash_table_lookup(db->files, str_c(dest));
		if (pw == NULL) {
			/* doesn't exist yet. create lookup for it. */
			pw = passwd_file_new(db, str_c(dest));
		}
	}

	if ((ret = passwd_file_sync(request, pw)) <= 0) {
		/* pw may be freed now */
		return ret;
	}

	username = t_str_new(256);
	if (auth_request_var_expand(username, username_format, request,
				    auth_request_str_escape, &error) < 0) {
		e_error(authdb_event(request),
			"Failed to expand username_format=%s: %s",
			username_format, error);
		return -1;
	}

	e_debug(authdb_event(request),
		"lookup: user=%s file=%s",
		str_c(username), pw->path);

	*user_r = hash_table_lookup(pw->users, str_c(username));
	if (*user_r == NULL) {
		auth_request_db_log_unknown_user(request);
		return 0;
	}
	return 1;
}

#endif
