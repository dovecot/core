/* Copyright (C) 2002 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef USERINFO_PASSWD_FILE

#include "userinfo-passwd.h"

#include "buffer.h"
#include "istream.h"
#include "hash.h"
#include "hex-binary.h"
#include "md5.h"
#include "mycrypt.h"

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef struct {
	Pool pool;

	char *path;
	time_t stamp;
	int fd;

	HashTable *users;
} PasswdFile;

typedef enum {
	PASSWORD_DES,
	PASSWORD_MD5,
	PASSWORD_DIGEST_MD5
} PasswordType;

typedef struct {
	char *user_realm; /* user:realm */
	const char *realm; /* NULL or points to user_realm */
	char *password;
	char *home;
	char *mail;

	uid_t uid;
	gid_t gid;

	PasswordType password_type;
	unsigned int chroot:1;
} PasswdUser;

static PasswdFile *passwd_file;

static void passwd_file_sync(void);

static int get_reply_data(PasswdUser *pu, AuthCookieReplyData *reply)
{
	const char *user;
	struct passwd *pw;

	if (pu->uid == 0 || pu->gid == 0 ||
	    (pu->home == NULL && pu->mail == NULL)) {
		/* all required information was not set in passwd file,
		   check from system's passwd */
		user = pu->realm == NULL ? pu->user_realm :
			t_strndup(pu->user_realm, strlen(pu->user_realm) -
				  strlen(pu->realm) - 1);

		pw = getpwnam(user);
		if (pw == NULL)
			return FALSE;

		passwd_fill_cookie_reply(pw, reply);
	}

	if (pu->uid != 0)
		reply->uid = pu->uid;
	if (pu->gid != 0)
		reply->gid = pu->gid;

	if (pu->home != NULL) {
		if (strocpy(reply->home, pu->home, sizeof(reply->home)) < 0)
			i_panic("home overflow");
	}

	if (pu->mail != NULL) {
		if (strocpy(reply->mail, pu->mail, sizeof(reply->mail)) < 0)
			i_panic("mail overflow");
	}

	if (strocpy(reply->virtual_user, pu->user_realm,
		    sizeof(reply->virtual_user)) < 0)
		i_panic("virtual_user overflow");

	if (pu->realm != NULL) {
		/* @UNSAFE: ':' -> '@' to make it look prettier */
		size_t pos;

		pos = (size_t) (pu->realm - (const char *) pu->user_realm);
		reply->virtual_user[pos] = '@';
	}

	reply->chroot = pu->chroot;
	return TRUE;
}

static int passwd_file_verify_plain(const char *user, const char *password,
				    AuthCookieReplyData *reply)
{
	PasswdUser *pu;
	char *const *tmp;
	unsigned char digest[16];
	const char *str;

	passwd_file_sync();

	/* find it from all realms */
	pu = hash_lookup(passwd_file->users, user);
	if (pu == NULL) {
		t_push();
		for (tmp = auth_realms; *tmp != NULL; tmp++) {
                        str = t_strconcat(user, ":", *tmp, NULL);
			pu = hash_lookup(passwd_file->users, str);
		}
		t_pop();
	}

	if (pu == NULL)
		return FALSE;

	/* verify that password matches */
	switch (pu->password_type) {
	case PASSWORD_DES:
		if (strcmp(mycrypt(password, pu->password), pu->password) != 0)
			return FALSE;
		break;
	case PASSWORD_MD5:
		md5_get_digest(password, strlen(password), digest);
		str = binary_to_hex(digest, sizeof(digest));

		if (strcmp(str, pu->password) != 0)
			return FALSE;
		break;
	case PASSWORD_DIGEST_MD5:
		/* user:realm:passwd */
		str = t_strconcat(pu->user_realm,
				  pu->realm == NULL ? ":" : "",  ":",
				  password, NULL);

		md5_get_digest(str, strlen(str), digest);
		str = binary_to_hex(digest, sizeof(digest));

		if (strcmp(str, pu->password) != 0)
			return FALSE;
		break;
	default:
                i_unreached();
	}

	/* found */
	return get_reply_data(pu, reply);
}

static int passwd_file_lookup_digest_md5(const char *user, const char *realm,
					 unsigned char digest[16],
					 AuthCookieReplyData *reply)
{
	const char *id;
	PasswdUser *pu;
	Buffer *buf;

	passwd_file_sync();

	/* FIXME: we simply ignore UTF8 setting.. */

	id = realm == NULL || *realm == '\0' ? user :
		t_strconcat(user, ":", realm, NULL);

	pu = hash_lookup(passwd_file->users, id);
	if (pu == NULL)
		return FALSE;

	/* found */
	i_assert(strlen(pu->password) == 32);

	buf = buffer_create_data(data_stack_pool, digest, 16);
	if (!hex_to_binary(pu->password, buf))
		return FALSE;
	
	return get_reply_data(pu, reply);
}

static void passwd_file_add(PasswdFile *pw, const char *username,
			    const char *pass, char *const *args)
{
	/* args = uid, gid, user info, home dir, shell, realm, mail, chroot */
	PasswdUser *pu;
	const char *p;

	if (strlen(username) >= AUTH_MAX_USER_LEN) {
		i_error("Username %s is too long (max. %d chars) in password "
			"file %s", username, AUTH_MAX_USER_LEN, pw->path);
		return;
	}

	pu = p_new(pw->pool, PasswdUser, 1);

	p = strchr(pass, '[');
	if (p == NULL) {
		pu->password = p_strdup(pw->pool, pass);
		pu->password_type = PASSWORD_DES;
	} else {
		/* password[type] - we're being libpam-pwdfile compatible
		   here. it uses 13 = DES and 34 = MD5. We add
		   56 = Digest-MD5. */
		pu->password = p_strndup(pw->pool, pass, (size_t) (p-pass));
		if (p[1] == '3' && p[2] == '4') {
			pu->password_type = PASSWORD_MD5;
			str_lcase(pu->password);
		} else if (p[1] == '5' && p[2] == '6') {
			pu->password_type = PASSWORD_DIGEST_MD5;
			if (strlen(pu->password) != 32) {
				i_error("User %s has invalid password in "
					"file %s", username, pw->path);
				return;
			}
			str_lcase(pu->password);
		} else {
			pu->password_type = PASSWORD_DES;
		}
	}

	if (args[0] != NULL) {
		pu->uid = atoi(args[0]);
		if (pu->uid == 0) {
			i_error("User %s has UID 0 in password file %s",
				username, pw->path);
			return;
		}
		args++;
	}

	if (args[0] != NULL) {
		pu->gid = atoi(args[0]);
		if (pu->gid == 0) {
			i_error("User %s has GID 0 in password file %s",
				username, pw->path);
			return;
		}
		args++;
	}

	/* user info */
	if (args[0] != NULL)
		args++;

	/* home */
	if (args[0] != NULL) {
		if (strlen(args[0]) >= AUTH_MAX_HOME_LEN) {
			i_error("User %s has too long home directory in "
				"password file %s", username, pw->path);
			return;
		}

		pu->home = p_strdup(pw->pool, args[0]);
		args++;
	}

	/* shell */
	if (args[0] != NULL)
		args++;

	/* realm */
	if (args[0] == NULL || *args[0] == '\0') {
		pu->user_realm = p_strdup(pw->pool, username);
		if (hash_lookup(pw->users, username) != NULL) {
			i_error("User %s already exists in password file %s",
				username, pw->path);
			return;
		}
	} else {
		pu->user_realm = p_strconcat(pw->pool, username, ":",
					     args[0], NULL);
		pu->realm = pu->user_realm + strlen(username)+1;

		if (hash_lookup(pw->users, pu->user_realm) != NULL) {
			i_error("User %s already exists in realm %s in "
				"password file %s", username, args[0],
				pw->path);
			return;
		}
	}

	/* mail storage */
	if (args[0] != NULL) {
		if (strlen(args[0]) >= AUTH_MAX_MAIL_LEN) {
			i_error("User %s has too long mail storage in "
				"password file %s", username, pw->path);
			return;
		}

		pu->mail = p_strdup(pw->pool, args[0]);
		args++;
	}

	/* chroot */
	if (args[0] != NULL && strstr(args[0], "chroot") != NULL)
		pu->chroot = TRUE;

	hash_insert(pw->users, pu->user_realm, pu);
}

static void passwd_file_parse_file(PasswdFile *pw)
{
	IStream *input;
	char *const *args;
	const char *line;

	input = i_stream_create_file(pw->fd, default_pool, 2048, FALSE);
	for (;;) {
		line = i_stream_next_line(input);
		if (line == NULL) {
			if (i_stream_read(input) <= 0)
				break;
                        continue;
		}

		if (*line == '\0' || *line == ':')
			continue; /* no username */

		t_push();
		args = t_strsplit(line, ":");
		if (args[1] != NULL && IS_VALID_PASSWD(args[1])) {
			/* valid user/pass */
			passwd_file_add(pw, args[0], args[1], args+2);
		}
		t_pop();
	}
	i_stream_unref(input);
}

static PasswdFile *passwd_file_parse(const char *path)
{
	PasswdFile *pw;
	Pool pool;
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_fatal("Can't open passwd-file %s: %m", path);
	}

	if (fstat(fd, &st) != 0)
		i_fatal("fstat() failed for passwd-file %s: %m", path);

	pool = pool_create("PasswdFile", 10240, FALSE);
	pw = p_new(pool, PasswdFile, 1);
	pw->pool = pool;
	pw->path = p_strdup(pool, path);
	pw->stamp = st.st_mtime;
	pw->fd = fd;
	pw->users = hash_create(pool, 100, str_hash, (HashCompareFunc) strcmp);

	passwd_file_parse_file(pw);
	return pw;
}

static void passwd_file_free(PasswdFile *pw)
{
	pool_unref(pw->pool);
}

static void passwd_file_init(const char *args)
{
	passwd_file = passwd_file_parse(args);
}

static void passwd_file_deinit(void)
{
	passwd_file_free(passwd_file);
}

static void passwd_file_sync(void)
{
	const char *path;
	struct stat st;

	if (stat(passwd_file->path, &st) < 0)
		i_fatal("stat() failed for %s: %m", passwd_file->path);

	if (st.st_mtime != passwd_file->stamp) {
		path = t_strdup(passwd_file->path);
		passwd_file_free(passwd_file);
		passwd_file = passwd_file_parse(path);
	}
}

UserInfoModule userinfo_passwd_file = {
	passwd_file_init,
	passwd_file_deinit,

	passwd_file_verify_plain,
        passwd_file_lookup_digest_md5
};

#endif
