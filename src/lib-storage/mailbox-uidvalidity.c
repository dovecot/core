/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "read-full.h"
#include "write-full.h"
#include "eacces-error.h"
#include "mailbox-list.h"
#include "mailbox-uidvalidity.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#define RETRY_COUNT 10

static uint32_t mailbox_uidvalidity_next_fallback(void)
{
	static uint32_t uid_validity = 0;

	/* we failed to use the uidvalidity file. don't fail the mailbox
	   creation because of it though, most of the time it's safe enough
	   to use the current time as the uidvalidity value. */
	if (uid_validity < (uint32_t)ioloop_time)
		uid_validity = (uint32_t)ioloop_time;
	else
		uid_validity++;
	return uid_validity;
}

static void mailbox_uidvalidity_write(struct mailbox_list *list,
				      const char *path, uint32_t uid_validity)
{
	char buf[8+1];
	int fd;
	mode_t mode, old_mask;
	gid_t gid;
	const char *gid_origin;

	mailbox_list_get_permissions(list, NULL, &mode, &gid, &gid_origin);

	old_mask = umask(0666 & ~mode);
	fd = open(path, O_RDWR | O_CREAT, 0666);
	umask(old_mask);
	if (fd == -1) {
		i_error("open(%s) failed: %m", path);
		return;
	}
	if (gid != (gid_t)-1 && fchown(fd, (uid_t)-1, gid) < 0) {
		if (errno == EPERM) {
			i_error("%s", eperm_error_get_chgrp("fchown", path,
							    gid, gid_origin));
		} else {
			i_error("fchown(%s, -1, %ld) failed: %m",
				path, (long)gid);
		}
	}

	i_snprintf(buf, sizeof(buf), "%08x", uid_validity);
	if (pwrite_full(fd, buf, strlen(buf), 0) < 0)
		i_error("write(%s) failed: %m", path);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", path);
}

static int
mailbox_uidvalidity_rename(const char *path, uint32_t *uid_validity,
			   bool log_enoent)
{
	string_t *src, *dest;
	unsigned int i, prefix_len;
	int ret;

	src = t_str_new(256);
	str_append(src, path);
	dest = t_str_new(256);
	str_append(dest, path);
	prefix_len = str_len(src);

	for (i = 0; i < RETRY_COUNT; i++) {
		str_truncate(src, prefix_len);
		str_truncate(dest, prefix_len);

		str_printfa(src, ".%08x", *uid_validity);
		*uid_validity += 1;
		str_printfa(dest, ".%08x", *uid_validity);

		if ((ret = rename(str_c(src), str_c(dest))) == 0 ||
		    errno != ENOENT)
			break;

		/* possibly a race condition. try the next value. */
	}
	if (ret < 0 && (errno != ENOENT || log_enoent))
		i_error("rename(%s, %s) failed: %m", str_c(src), str_c(dest));
	return ret;
}

static uint32_t
mailbox_uidvalidity_next_rescan(struct mailbox_list *list, const char *path)
{
	DIR *d;
	struct dirent *dp;
	const char *fname, *dir, *prefix, *tmp;
	char *endp;
	unsigned int i, prefix_len;
	uint32_t cur_value, min_value, max_value;
	mode_t old_mask;
	int fd;

	fname = strrchr(path, '/');
	if (fname == NULL) {
		dir = ".";
		fname = path;
	} else {
		dir = t_strdup_until(path, fname);
		fname++;
	}

	d = opendir(dir);
	if (d == NULL) {
		i_error("opendir(%s) failed: %m", dir);
		return mailbox_uidvalidity_next_fallback();
	}
	prefix = t_strconcat(fname, ".", NULL);
	prefix_len = strlen(prefix);

	/* just in case there happens to be multiple matching uidvalidity
	   files, track the min/max values. use the max value and delete the
	   min value file. */
	max_value = 0; min_value = (uint32_t)-1;
	while ((dp = readdir(d)) != NULL) {
		if (strncmp(dp->d_name, prefix, prefix_len) == 0) {
			cur_value = strtoul(dp->d_name + prefix_len, &endp, 16);
			if (*endp == '\0') {
				if (min_value > cur_value)
					min_value = cur_value;
				if (max_value < cur_value)
					max_value = cur_value;
			}
		}
	}
	if (closedir(d) < 0)
		i_error("closedir(%s) failed: %m", dir);

	if (max_value == 0) {
		/* no uidvalidity files. create one. */
		for (i = 0; i < RETRY_COUNT; i++) {
			cur_value = mailbox_uidvalidity_next_fallback();
			tmp = t_strdup_printf("%s.%08x", path, cur_value);
			/* the file is empty, don't bother with permissions */
			old_mask = umask(0);
			fd = open(tmp, O_RDWR | O_CREAT | O_EXCL, 0444);
			umask(old_mask);
			if (fd != -1 || errno != EEXIST)
				break;
			/* already exists. although it's quite unlikely we'll
			   hit this race condition. more likely we'll create
			   a duplicate file.. */
		}
		if (fd == -1) {
			i_error("creat(%s) failed: %m", tmp);
			return cur_value;
		}
		(void)close(fd);
		mailbox_uidvalidity_write(list, path, cur_value);
		return cur_value;
	}
	if (min_value != max_value) {
		/* duplicate uidvalidity files, delete the oldest */
		tmp = t_strdup_printf("%s.%08x", path, min_value);
		if (unlink(tmp) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", tmp);
	}

	cur_value = max_value;
	if (mailbox_uidvalidity_rename(path, &cur_value, TRUE) < 0)
		return mailbox_uidvalidity_next_fallback();
	mailbox_uidvalidity_write(list, path, cur_value);
	return cur_value;
}

uint32_t mailbox_uidvalidity_next(struct mailbox_list *list, const char *path)
{
	char buf[8+1], *endp;
	uint32_t cur_value;
	int fd, ret;

	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path);
		return mailbox_uidvalidity_next_rescan(list, path);
	}
	ret = read_full(fd, buf, sizeof(buf)-1);
	if (ret < 0) {
		i_error("read(%s) failed: %m", path);
		(void)close(fd);
		return mailbox_uidvalidity_next_rescan(list, path);
	}
	buf[sizeof(buf)-1] = 0;
	cur_value = strtoul(buf, &endp, 16);
	if (ret == 0 || endp != buf+sizeof(buf)-1) {
		/* broken value */
		(void)close(fd);
		return mailbox_uidvalidity_next_rescan(list, path);
	}

	/* we now have the current uidvalidity value that's hopefully correct */
	if (mailbox_uidvalidity_rename(path, &cur_value, FALSE) < 0)
		return mailbox_uidvalidity_next_rescan(list, path);

	/* fast path succeeded. write the current value to the main
	   uidvalidity file. */
	i_snprintf(buf, sizeof(buf), "%08x", cur_value);
	if (pwrite_full(fd, buf, strlen(buf), 0) < 0)
		i_error("write(%s) failed: %m", path);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", path);
	return cur_value;
}
