/* Copyright (C) 2002 Timo Sirainen */

/* ugly code here - text files are annoying to manage */

#include "lib.h"
#include "mmap-util.h"
#include "imap-match.h"
#include "mail-storage.h"
#include "subscription-file.h"

#include <unistd.h>
#include <fcntl.h>

#define SUBSCRIPTION_FILE_NAME ".subscriptions"

static int lock_file(int fd, int type)
{
	struct flock fl;

	/* lock whole file */
	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(fd, F_SETLKW, &fl) == -1) {
		if (errno != EINTR)
			return FALSE;
	}

	return TRUE;
}

static int subscription_open(MailStorage *storage, int update,
			     const char **path, void **mmap_base,
			     size_t *mmap_length)
{
	int fd;

	*path = t_strconcat(storage->dir, "/" SUBSCRIPTION_FILE_NAME, NULL);

	fd = update ? open(*path, O_RDWR | O_CREAT, 0660) :
		open(*path, O_RDONLY);
	if (fd == -1) {
		if (update || errno != ENOENT) {
			mail_storage_set_critical(storage, "Can't open "
						  "subscription file %s: %m",
						  *path);
		}
		return -1;
	}

	if (!lock_file(fd, update ? F_WRLCK : F_RDLCK)) {
		mail_storage_set_critical(storage, "fcntl() failed for "
					  "subscription file %s: %m", *path);
		(void)close(fd);
		return -1;
	}

	*mmap_base = update ? mmap_rw_file(fd, mmap_length) :
		mmap_ro_file(fd, mmap_length);
	if (*mmap_base == MAP_FAILED) {
		*mmap_base = NULL;
		mail_storage_set_critical(storage, "mmap() failed for "
					  "subscription file %s: %m", *path);
		(void)close(fd);
		return -1;
	}

	(void)madvise(*mmap_base, *mmap_length, MADV_SEQUENTIAL);
	return fd;
}

static int subscription_append(MailStorage *storage, int fd, const char *name,
			       unsigned int len, int prefix_lf,
			       const char *path)
{
	char *buf;

	if (lseek(fd, 0, SEEK_END) == -1) {
		mail_storage_set_critical(storage, "lseek() failed for "
					  "subscription file %s: %m", path);
		return FALSE;
	}

	buf = t_buffer_get(len+2);
	buf[0] = '\n';
	memcpy(buf+1, name, len);
	buf[len+1] = '\n';

	if (prefix_lf)
		len += 2;
	else {
		buf++;
		len++;
	}

	if ((size_t) write(fd, buf, len) != len) {
		mail_storage_set_critical(storage, "write() failed for "
					  "subscription file %s: %m", path);
		return FALSE;
	}

	return TRUE;
}

int subsfile_set_subscribed(MailStorage *storage, const char *name, int set)
{
	void *mmap_base;
	size_t mmap_length;
	const char *path;
	char *subscriptions, *end, *p;
	unsigned int namelen, afterlen, removelen;
	int fd,  failed, prefix_lf;

	if (strcasecmp(name, "INBOX") == 0)
		name = "INBOX";

	fd = subscription_open(storage, TRUE, &path, &mmap_base, &mmap_length);
	if (fd == -1)
		return FALSE;

	namelen = strlen(name);

	subscriptions = mmap_base;
	if (subscriptions == NULL)
		p = NULL;
	else {
		end = subscriptions + mmap_length;
		for (p = subscriptions; p != end; p++) {
			if (*p == *name && p+namelen <= end &&
			    strncmp(p, name, namelen) == 0) {
				/* make sure beginning and end matches too */
				if ((p == subscriptions || p[-1] == '\n') &&
				    (p+namelen == end || p[namelen] == '\n'))
					break;
			}
		}

		if (p == end)
			p = NULL;
	}

	failed = FALSE;
	if (p != NULL && !set) {
		/* remove it */
		afterlen = mmap_length - (unsigned int) (p - subscriptions);
		removelen = namelen < afterlen ? namelen+1 : namelen;

		if (removelen < afterlen)
			memmove(p, p+removelen, afterlen-removelen);

		if (ftruncate(fd, (off_t) (mmap_length - removelen)) == -1) {
			mail_storage_set_critical(storage, "ftruncate() "
						  "failed for subscription "
						  "file %s: %m", path);
			failed = TRUE;
		}
	} else if (p == NULL && set) {
		/* append it */
		prefix_lf = mmap_length > 0 &&
			subscriptions[mmap_length-1] != '\n';
		if (!subscription_append(storage, fd, name, namelen,
					 prefix_lf, path))
			failed = TRUE;
	}

	if (mmap_base != NULL && munmap(mmap_base, mmap_length) == -1) {
		mail_storage_set_critical(storage, "munmap() failed for "
					  "subscription file %s: %m", path);
		failed = TRUE;
	}

	if (close(fd) == -1) {
		mail_storage_set_critical(storage, "close() failed for "
					  "subscription file %s: %m", path);
		failed = TRUE;
	}
	return !failed;
}

int subsfile_foreach(MailStorage *storage, const char *mask,
		     SubsFileForeachFunc func, void *context)
{
        const ImapMatchGlob *glob;
	const char *path, *start, *end, *p, *line;
	void *mmap_base;
	size_t mmap_length;
	int fd, ret;

	fd = subscription_open(storage, FALSE, &path, &mmap_base, &mmap_length);
	if (fd == -1)
		return -1;

	glob = imap_match_init(mask, TRUE, storage->hierarchy_sep);

	start = mmap_base; end = start + mmap_length; ret = 1;
	while (ret) {
		t_push();

		for (p = start; p != end; p++) {
			if (*p == '\n')
				break;
		}

		line = t_strdup_until(start, p);
		if (line != NULL && *line != '\0' &&
		    imap_match(glob, line, 0, NULL) >= 0)
			ret = func(storage, line, context);
		t_pop();

		if (p == end)
			break;
		start = p+1;
	}

	(void)close(fd);
	return ret;
}
