/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "file-lock.h"
#include "read-full.h"
#include "write-full.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "iostream-ssl.h"
#include "ssl-params-settings.h"
#include "ssl-params.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

#define MAX_PARAM_FILE_SIZE 1024*1024
#define SSL_BUILD_PARAM_TIMEOUT_SECS (60*30)
#define SSL_PARAMS_PRIORITY 15

struct ssl_params {
	char *path;
	struct ssl_params_settings set;

	time_t last_mtime;
	ssl_params_callback_t *callback;
};

static void
ssl_params_if_unchanged(const char *path, time_t mtime,
			unsigned int ssl_dh_parameters_length ATTR_UNUSED)
{
	const char *temp_path, *error;
	struct file_lock *lock;
	struct stat st, st2;
	mode_t old_mask;
	int fd, ret;
	buffer_t *buf;

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
		i_close_fd(&fd);
		return;
	}

	/* check that the parameters file is still the same */
	if (stat(path, &st) == 0) {
		if (st.st_mtime != mtime) {
			i_close_fd(&fd);
			return;
		}
	} else if (errno != ENOENT)
		i_fatal("stat(%s) failed: %m", path);

	/* ok, we really want to generate it. */
	if (ftruncate(fd, 0) < 0)
		i_fatal("ftruncate(%s) failed: %m", temp_path);

	i_info("Generating SSL parameters");

	buf = buffer_create_dynamic(pool_datastack_create(), 1024);
	if (ssl_iostream_generate_params(buf, ssl_dh_parameters_length,
					 &error) < 0) {
		i_fatal("ssl_iostream_generate_params(%u) failed: %s",
			ssl_dh_parameters_length, error);
	}
	if (write_full(fd, buf->data, buf->used) < 0)
		i_fatal("write(%s) failed: %m", temp_path);

	if (rename(temp_path, path) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_path, path);
	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_path);
	file_lock_free(&lock);

	i_info("SSL parameters regeneration completed");
}

static void ssl_params_close_listeners(void)
{
	unsigned int i;

	/* we have forked, but the fds are still shared. we can't go
	   io_remove()ing the fds from ioloop, because with many ioloops
	   (e.g. epoll) the fds get removed from the main process's ioloop
	   as well. so we'll just do the closing here manually. */
	for (i = 0; i < master_service_get_socket_count(master_service); i++) {
		int fd = MASTER_LISTEN_FD_FIRST + i;

		if (close(fd) < 0)
			i_error("close(listener %d) failed: %m", fd);
	}
}

static void ssl_params_rebuild(struct ssl_params *param)
{
	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child - close listener fds so a long-running ssl-params
		   doesn't cause Dovecot restart to fail */
		ssl_params_close_listeners();
		ssl_params_if_unchanged(param->path, param->last_mtime,
					param->set.ssl_dh_parameters_length);
		exit(0);
	default:
		/* parent */
		break;
	}
}

static bool
ssl_params_verify(struct ssl_params *param,
		  const unsigned char *data, size_t size)
{
	unsigned int bitsize, len;
	bool found = FALSE;

	/* <bitsize><length><data>... */
	while (size >= sizeof(bitsize)) {
		memcpy(&bitsize, data, sizeof(bitsize));
		if (bitsize == 0) {
			if (found)
				return TRUE;
			i_warning("Regenerating %s for ssl_dh_parameters_length=%u",
				  param->path, param->set.ssl_dh_parameters_length);
			return FALSE;
		}
		data += sizeof(bitsize);
		size -= sizeof(bitsize);
		if (bitsize == param->set.ssl_dh_parameters_length)
			found = TRUE;

		if (size < sizeof(len))
			break;
		memcpy(&len, data, sizeof(len));
		if (len > size - sizeof(len))
			break;
		data += sizeof(bitsize) + len;
		size -= sizeof(bitsize) + len;
	}
	i_error("Corrupted %s", param->path);
	return FALSE;
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
		i_close_fd(&fd);
		return -1;
	}
	param->last_mtime = st.st_mtime;
	if (st.st_size == 0 || st.st_size > MAX_PARAM_FILE_SIZE) {
		i_error("Corrupted file: %s", param->path);
		i_close_fd(&fd);
		i_unlink(param->path);
		return -1;
	}

	buffer = t_malloc(st.st_size);
	ret = read_full(fd, buffer, st.st_size);
	if (ret < 0)
		i_error("read(%s) failed: %m", param->path);
	else if (ret == 0) {
		i_error("File unexpectedly shrank: %s", param->path);
		ret = -1;
	} else if (!ssl_params_verify(param, buffer, st.st_size)) {
		ret = -1;
	} else {
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
	i_free(param->path);
	i_free(param);
}
