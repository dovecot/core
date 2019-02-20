/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

/* Auth process maintains a random secret. Once a user authenticates the
   response to the REQUEST command from a master service is augmented with an
   auth_token value. This token is the SHA1 hash of the secret, the service
   name and the username of the user that just logged in. Using this token the
   service (e.g. imap) can login to another service (e.g. imap-urlauth) to
   gain access to resources that require additional privileges (e.g. another
   user's e-mail).
*/

#include "auth-common.h"
#include "hex-binary.h"
#include "hmac.h"
#include "sha1.h"
#include "randgen.h"
#include "read-full.h"
#include "write-full.h"
#include "safe-memset.h"
#include "auth-settings.h"
#include "auth-token.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define AUTH_TOKEN_SECRET_LEN 32

#define AUTH_TOKEN_SECRET_FNAME "auth-token-secret.dat"

static unsigned char auth_token_secret[AUTH_TOKEN_SECRET_LEN];

static int
auth_token_read_secret(const char *path,
		       unsigned char secret_r[AUTH_TOKEN_SECRET_LEN])
{
	struct stat st, lst;
	int fd, ret;		

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;
	}

	/* check secret len and file type */
	if (st.st_size != AUTH_TOKEN_SECRET_LEN || !S_ISREG(st.st_mode)) {
		i_error("Corrupted token secret file: %s", path);
		i_close_fd(&fd);
		i_unlink(path);
		return -1;
	}

	/* verify that we're not dealing with a symbolic link */
	if (lstat(path, &lst) < 0) {
		i_error("lstat(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;		
	}

	/* check security parameters for compromise */
	if ((st.st_mode & 07777) != 0600 ||
	    st.st_uid != geteuid() || st.st_nlink > 1 ||
	    !S_ISREG(lst.st_mode) || st.st_ino != lst.st_ino ||
	    !CMP_DEV_T(st.st_dev, lst.st_dev)) {
		i_error("Compromised token secret file: %s", path);
		i_close_fd(&fd);
		i_unlink(path);
		return -1;
	}

	/* FIXME: fail here to generate new secret if stored one is too old */

	ret = read_full(fd, secret_r, AUTH_TOKEN_SECRET_LEN);
	if (ret < 0)
		i_error("read(%s) failed: %m", path);
	else if (ret == 0) {
		i_error("Token secret file unexpectedly shrank: %s", path);
		ret = -1;
	}
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", path);

	e_debug(auth_event, "Read auth token secret from %s", path);
	return ret;
}

static int
auth_token_write_secret(const char *path,
			const unsigned char secret[AUTH_TOKEN_SECRET_LEN])
{
	const char *temp_path;
	mode_t old_mask;
	int fd, ret;

	temp_path = t_strconcat(path, ".tmp", NULL);

	old_mask = umask(0);
	fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	umask(old_mask);

	if (fd == -1) {
		i_error("open(%s) failed: %m", temp_path);
		return -1;
	}

	ret = write_full(fd, secret, AUTH_TOKEN_SECRET_LEN);
	if (ret < 0)
		i_error("write(%s) failed: %m", temp_path);
	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", temp_path);
		ret = -1;
	}

	if (ret < 0) {
		i_unlink(temp_path);
		return -1;
	}

	if (rename(temp_path, path) < 0) {
		i_error("rename(%s, %s) failed: %m", temp_path, path);
		i_unlink(temp_path);
		return -1;
	}

	e_debug(auth_event, "Wrote new auth token secret to %s", path);
	return 0;
}

void auth_token_init(void)
{
	const char *secret_path =
		t_strconcat(global_auth_settings->base_dir, "/",
			    AUTH_TOKEN_SECRET_FNAME, NULL);

	if (auth_token_read_secret(secret_path, auth_token_secret) < 0) {
		random_fill(auth_token_secret, sizeof(auth_token_secret));

		if (auth_token_write_secret(secret_path, auth_token_secret) < 0) {
			i_error("Failed to write auth token secret file; "
				"returned tokens will be invalid once auth restarts");
		}
	}
}

void auth_token_deinit(void)
{
	/* not very useful, but we do it anyway */
	safe_memset(auth_token_secret, 0, sizeof(auth_token_secret));
}

const char *auth_token_get(const char *service, const char *session_pid,
			   const char *username, const char *session_id)
{
	struct hmac_context ctx;
	unsigned char result[SHA1_RESULTLEN];

	hmac_init(&ctx, (const unsigned char*)username, strlen(username),
		  &hash_method_sha1);
	hmac_update(&ctx, session_pid, strlen(session_pid));
	if (session_id != NULL && *session_id != '\0')
		hmac_update(&ctx, session_id, strlen(session_id));
	hmac_update(&ctx, service, strlen(service));
	hmac_update(&ctx, auth_token_secret, sizeof(auth_token_secret));
	hmac_final(&ctx, result);

	return binary_to_hex(result, sizeof(result));
}
