/* Copyright (C) 2002-2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#if defined (USERDB_PASSWD_FILE) || defined(PASSDB_PASSWD_FILE)

#include "common.h"
#include "userdb.h"
#include "passwd-file.h"

#include "buffer.h"
#include "istream.h"
#include "hash.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void passwd_file_add(struct passwd_file *pw, const char *username,
			    const char *pass, const char *const *args)
{
	/* args = uid, gid, user info, home dir, shell, mail, chroot */
	struct passwd_user *pu;
	const char *p;

	if (hash_lookup(pw->users, username) != NULL) {
		i_error("User %s already exists in password file %s",
			username, pw->path);
		return;
	}

	pu = p_new(pw->pool, struct passwd_user, 1);
	pu->user_realm = p_strdup(pw->pool, username);

	p = pass == NULL ? NULL : strchr(pass, '[');
	if (p == NULL) {
		pu->password = p_strdup(pw->pool, pass);
		pu->password_type = pass == NULL ? PASSWORD_NONE : PASSWORD_DES;
	} else {
		/* password[type] - we're being libpam-pwdfile compatible
		   here. it uses 13 = DES and 34 = MD5. We add
		   56 = Digest-MD5. */
		pu->password = p_strdup_until(pw->pool, pass, p);
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

	if (*args != NULL) {
		pu->uid = atoi(*args);
		if (pu->uid == 0) {
			i_error("User %s has UID 0 in password file %s",
				username, pw->path);
			return;
		}
		args++;
	}

	if (*args != NULL) {
		pu->gid = atoi(*args);
		if (pu->gid == 0) {
			i_error("User %s has GID 0 in password file %s",
				username, pw->path);
			return;
		}
		args++;
	}

	/* user info */
	if (*args != NULL)
		args++;

	/* home */
	if (*args != NULL) {
		pu->home = p_strdup(pw->pool, *args);
		args++;
	}

	/* shell */
	if (*args != NULL)
		args++;

	/* mail storage */
	if (*args != NULL) {
		pu->mail = p_strdup(pw->pool, *args);
		args++;
	}

	/* chroot */
	if (*args != NULL && strstr(*args, "chroot") != NULL)
		pu->chroot = TRUE;

	hash_insert(pw->users, pu->user_realm, pu);
}

static void passwd_file_open(struct passwd_file *pw)
{
	struct istream *input;
	const char *const *args;
	const char *line;
	struct stat st;
	int fd;

	fd = open(pw->path, O_RDONLY);
	if (fd == -1)
		i_fatal("Can't open passwd-file %s: %m", pw->path);

	if (fstat(fd, &st) != 0)
		i_fatal("fstat() failed for passwd-file %s: %m", pw->path);

	pw->fd = fd;
	pw->stamp = st.st_mtime;

	pw->pool = pool_alloconly_create("passwd_file", 10240);;
	pw->users = hash_create(default_pool, pw->pool, 100,
				str_hash, (hash_cmp_callback_t *)strcmp);

	input = i_stream_create_file(pw->fd, default_pool, 4096, FALSE);
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
		if (args[1] != NULL) {
			/* at least two fields */
			passwd_file_add(pw, args[0], args[1], args+2);
		}
		t_pop();
	}
	i_stream_unref(input);
}

static void passwd_file_close(struct passwd_file *pw)
{
	if (pw->fd != -1) {
		if (close(pw->fd) < 0)
			i_error("close(passwd_file) failed: %m");
		pw->fd = -1;
	}

	if (pw->users != NULL) {
		hash_destroy(pw->users);
		pw->users = NULL;
	}
	if (pw->pool != NULL) {
		pool_unref(pw->pool);
		pw->pool = NULL;
	}
}

struct passwd_file *passwd_file_parse(const char *path)
{
	struct passwd_file *pw;

	pw = i_new(struct passwd_file, 1);
	pw->refcount = 1;
	pw->path = i_strdup(path);

	passwd_file_open(pw);
	return pw;
}

void passwd_file_unref(struct passwd_file *pw)
{
	if (--pw->refcount == 0) {
		passwd_file_close(pw);
		i_free(pw->path);
		i_free(pw);
	}
}

static void passwd_file_sync(struct passwd_file *pw)
{
	struct stat st;

	if (stat(pw->path, &st) < 0)
		i_fatal("stat() failed for %s: %m", pw->path);

	if (st.st_mtime != pw->stamp) {
		passwd_file_close(pw);
		passwd_file_open(pw);
	}
}

struct passwd_user *
passwd_file_lookup_user(struct passwd_file *pw,
			const char *user, const char *realm)
{
	struct passwd_user *pu;

	if (realm != NULL)
		user = t_strconcat(user, "@", realm, NULL);

	passwd_file_sync(pw);

	pu = hash_lookup(pw->users, user);
	if (pu == NULL) {
		if (verbose)
			i_info("passwd-file(%s): unknown user", user);
	}

	return pu;
}

#endif
