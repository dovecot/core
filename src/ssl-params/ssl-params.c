/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-lock.h"
#include "read-full.h"
#include "master-service-settings.h"
#include "ssl-params-settings.h"
#include "ssl-params.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

#define MAX_PARAM_FILE_SIZE 1024
#define SSL_BUILD_PARAM_TIMEOUT_SECS (60*30)
#define SSL_PARAMS_PRIORITY 15

struct ssl_params {
	char *path;
	struct ssl_params_settings set;

	time_t last_mtime;
	struct timeout *to_rebuild;
	ssl_params_callback_t *callback;
};

static void ssl_params_if_unchanged(const char *path, time_t mtime)
{
	const char *temp_path;
	struct file_lock *lock;
	struct stat st, st2;
	mode_t old_mask;
	int fd, ret;

#ifdef HAVE_SETPRIORITY
	if (setpriority(PRIO_PROCESS, 0, SSL_PARAMS_PRIORITY) < 0)
		i_error("setpriority(%d) failed: %m", SSL_PARAMS_PRIORITY);
#endif

	temp_path = t_strconcat(path, ".tmp", NULL);

	old_mask = umask(0);
	fd = open(temp_path, O_WRONLY | O_CREAT, 0644);
	umask(old_mask);

	if (fd == -1)
		i_fatal("creat(%s) failed: %m", temp_path);

	/* If multiple dovecot instances are running, only one of them needs
	   to regenerate this file. */
	ret = file_wait_lock(fd, temp_path, F_WRLCK,
			     FILE_LOCK_METHOD_FCNTL,
			     SSL_BUILD_PARAM_TIMEOUT_SECS, &lock);
	if (ret < 0)
		i_fatal("file_try_lock(%s) failed: %m", temp_path);
	if (ret == 0) {
		/* someone else is writing this */
		i_fatal("Timeout while waiting for %s generation to complete",
			path);
	}

	/* make sure the .tmp file is still the one we created */
	if (fstat(fd, &st) < 0)
		i_fatal("fstat(%s) failed: %m", temp_path);
	if (stat(temp_path, &st2) < 0) {
		if (errno != ENOENT)
			i_fatal("stat(%s) failed: %m", temp_path);
		st2.st_ino = st.st_ino+1;
	}
	if (st.st_ino != st2.st_ino) {
		/* nope. so someone else just generated the file. */
		(void)close(fd);
		return;
	}

	/* check that the parameters file is still the same */
	if (stat(path, &st) == 0) {
		if (st.st_mtime != mtime) {
			(void)close(fd);
			return;
		}
	} else if (errno != ENOENT)
		i_fatal("stat(%s) failed: %m", path);

	/* ok, we really want to generate it. */
	if (ftruncate(fd, 0) < 0)
		i_fatal("ftruncate(%s) failed: %m", temp_path);

	i_info("Generating SSL parameters");
#ifdef HAVE_SSL
	ssl_generate_parameters(fd, temp_path);
#endif

	if (rename(temp_path, path) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_path, path);
	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_path);
	file_lock_free(&lock);

	i_info("SSL parameters regeneration completed");
}

static void ssl_params_rebuild(struct ssl_params *param)
{
	if (param->to_rebuild != NULL)
		timeout_remove(&param->to_rebuild);

	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child */
		ssl_params_if_unchanged(param->path, param->last_mtime);
		exit(0);
	default:
		/* parent */
		break;
	}
}

static void ssl_params_set_timeout(struct ssl_params *param)
{
	time_t next_rebuild, diff;

	if (param->to_rebuild != NULL)
		timeout_remove(&param->to_rebuild);
	if (param->set.ssl_parameters_regenerate == 0)
		return;

	next_rebuild = param->last_mtime +
		param->set.ssl_parameters_regenerate * 3600;

	if (ioloop_time >= next_rebuild) {
		ssl_params_rebuild(param);
		return;
	}

	diff = next_rebuild - ioloop_time;
	if (diff > INT_MAX / 1000)
		diff = INT_MAX / 1000;
	param->to_rebuild = timeout_add(diff * 1000, ssl_params_rebuild, param);
}

static int ssl_params_read(struct ssl_params *param)
{
	unsigned char *buffer;
	struct stat st;
	int fd, ret;

	fd = open(param->path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", param->path);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", param->path);
		(void)close(fd);
		return -1;
	}
	if (st.st_size == 0 || st.st_size > MAX_PARAM_FILE_SIZE) {
		i_error("Corrupted file: %s", param->path);
		(void)unlink(param->path);
		return -1;
	}

	buffer = t_malloc(st.st_size);
	ret = read_full(fd, buffer, st.st_size);
	if (ret < 0)
		i_error("read(%s) failed: %m", param->path);
	else if (ret == 0) {
		i_error("File unexpectedly shrank: %s", param->path);
		ret = -1;
	} else {
		param->last_mtime = st.st_mtime;
		ssl_params_set_timeout(param);
		param->callback(buffer, st.st_size);
	}

	if (close(fd) < 0)
		i_error("close(%s) failed: %m", param->path);
	return ret;
}

struct ssl_params *
ssl_params_init(const char *path, ssl_params_callback_t *callback,
		const struct ssl_params_settings *set)
{
	struct ssl_params *param;

	param = i_new(struct ssl_params, 1);
	param->path = i_strdup(path);
	param->set = *set;
	param->callback = callback;
	ssl_params_refresh(param);
	return param;
}

void ssl_params_refresh(struct ssl_params *param)
{
	if (ssl_params_read(param) < 0)
		ssl_params_rebuild(param);
}

void ssl_params_deinit(struct ssl_params **_param)
{
	struct ssl_params *param = *_param;

	*_param = NULL;
	if (param->to_rebuild != NULL)
		timeout_remove(&param->to_rebuild);
	i_free(param->path);
	i_free(param);
}
