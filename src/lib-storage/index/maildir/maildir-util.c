/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "hostpid.h"
#include "ioloop.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int maildir_file_do_try(struct index_mailbox *ibox, uint32_t uid,
			       maildir_file_do_func *func, void *context)
{
	const char *fname, *path;
        enum maildir_uidlist_rec_flag flags;
	int ret;

	fname = maildir_uidlist_lookup(ibox->uidlist, uid, &flags);
	if (fname == NULL)
		return -2; /* expunged */

	t_push();
	if ((flags & MAILDIR_UIDLIST_REC_FLAG_NEW_DIR) != 0) {
		/* probably in new/ dir */
		path = t_strconcat(ibox->path, "/new/", fname, NULL);
		ret = func(ibox, path, context);
		if (ret != 0) {
			t_pop();
			return ret;
		}
	}

	path = t_strconcat(ibox->path, "/cur/", fname, NULL);
	ret = func(ibox, path, context);
	t_pop();
	return ret;
}

int maildir_file_do(struct index_mailbox *ibox, uint32_t uid,
		    maildir_file_do_func *func, void *context)
{
	int i, ret;

	ret = maildir_file_do_try(ibox, uid, func, context);
	for (i = 0; i < 10 && ret == 0; i++) {
		/* file is either renamed or deleted. sync the maildir and
		   see which one. if file appears to be renamed constantly,
		   don't try to open it more than 10 times. */
		if (maildir_storage_sync_force(ibox) < 0)
			return -1;

		ret = maildir_file_do_try(ibox, uid, func, context);
	}

	if (i == 10) {
		mail_storage_set_critical(ibox->box.storage,
			"maildir_file_do(%s) racing", ibox->path);
	}

	return ret == -2 ? 0 : ret;
}

int maildir_filename_get_flags(const char *fname, pool_t pool,
			       enum mail_flags *flags_r,
			       const char *const **keywords_r)
{
	const char *info;
	unsigned int num;

	*flags_r = 0;
	*keywords_r = NULL;

	info = strchr(fname, ':');
	if (info == NULL || info[1] != '2' || info[2] != ',')
		return 0;

	for (info += 3; *info != '\0' && *info != ','; info++) {
		switch (*info) {
		case 'R': /* replied */
			*flags_r |= MAIL_ANSWERED;
			break;
		case 'S': /* seen */
			*flags_r |= MAIL_SEEN;
			break;
		case 'T': /* trashed */
			*flags_r |= MAIL_DELETED;
			break;
		case 'D': /* draft */
			*flags_r |= MAIL_DRAFT;
			break;
		case 'F': /* flagged */
			*flags_r |= MAIL_FLAGGED;
			break;
		default:
			if (*info >= 'a' && *info <= 'z') {
				/* FIXME: keyword */
				num = (*info - 'a');
				break;
			}

			/* unknown flag - ignore */
			break;
		}
	}

	return 1;
}

const char *maildir_filename_set_flags(const char *fname, enum mail_flags flags,
				       const char *const *keywords)
{
	string_t *flags_str;
	enum mail_flags flags_left;
	const char *info, *oldflags;
	int nextflag;

	/* remove the old :info from file name, and get the old flags */
	info = strrchr(fname, ':');
	if (info != NULL && strrchr(fname, '/') > info)
		info = NULL;

	oldflags = "";
	if (info != NULL) {
		fname = t_strdup_until(fname, info);
		if (info[1] == '2' && info[2] == ',')
			oldflags = info+3;
	}

	/* insert the new flags between old flags. flags must be sorted by
	   their ASCII code. unknown flags are kept. */
	flags_str = t_str_new(256);
	str_append(flags_str, fname);
	str_append(flags_str, ":2,");
	flags_left = flags;
	for (;;) {
		/* skip all known flags */
		while (*oldflags == 'D' || *oldflags == 'F' ||
		       *oldflags == 'R' || *oldflags == 'S' ||
		       *oldflags == 'T' ||
		       (*oldflags >= 'a' && *oldflags <= 'z'))
			oldflags++;

		nextflag = *oldflags == '\0' || *oldflags == ',' ? 256 :
			(unsigned char) *oldflags;

		if ((flags_left & MAIL_DRAFT) && nextflag > 'D') {
			str_append_c(flags_str, 'D');
			flags_left &= ~MAIL_DRAFT;
		}
		if ((flags_left & MAIL_FLAGGED) && nextflag > 'F') {
			str_append_c(flags_str, 'F');
			flags_left &= ~MAIL_FLAGGED;
		}
		if ((flags_left & MAIL_ANSWERED) && nextflag > 'R') {
			str_append_c(flags_str, 'R');
			flags_left &= ~MAIL_ANSWERED;
		}
		if ((flags_left & MAIL_SEEN) && nextflag > 'S') {
			str_append_c(flags_str, 'S');
			flags_left &= ~MAIL_SEEN;
		}
		if ((flags_left & MAIL_DELETED) && nextflag > 'T') {
			str_append_c(flags_str, 'T');
			flags_left &= ~MAIL_DELETED;
		}

		if (keywords != NULL && nextflag > 'a') {
			// FIXME
		}

		if (*oldflags == '\0' || *oldflags == ',')
			break;

		str_append_c(flags_str, *oldflags);
		oldflags++;
	}

	if (*oldflags == ',') {
		/* another flagset, we don't know about these, just keep them */
		while (*oldflags != '\0')
			str_append_c(flags_str, *oldflags++);
	}

	return str_c(flags_str);
}

const char *maildir_generate_tmp_filename(const struct timeval *tv)
{
	static unsigned int create_count = 0;
	static time_t first_stamp = 0;

	if (first_stamp == 0 || first_stamp == ioloop_time) {
		/* it's possible that within last second another process had
		   the same PID as us. Use usecs to make sure we don't create
		   duplicate base name. */
		first_stamp = ioloop_time;
		return t_strdup_printf("%s.P%sQ%uM%s.%s",
				       dec2str(tv->tv_sec), my_pid,
				       create_count++,
				       dec2str(tv->tv_usec), my_hostname);
	} else {
		/* Don't bother with usecs. Saves a bit space :) */
		return t_strdup_printf("%s.P%sQ%u.%s",
				       dec2str(tv->tv_sec), my_pid,
				       create_count++, my_hostname);
	}
}

int maildir_create_tmp(struct index_mailbox *ibox, const char *dir,
		       mode_t mode, const char **fname_r)
{
	const char *path, *tmp_fname;
	struct stat st;
	struct timeval *tv, tv_now;
	pool_t pool;
	int fd;

	tv = &ioloop_timeval;
	pool = pool_alloconly_create("maildir_tmp", 4096);
	for (;;) {
		p_clear(pool);
		tmp_fname = maildir_generate_tmp_filename(tv);

		path = p_strconcat(pool, dir, "/", tmp_fname, NULL);
		if (stat(path, &st) < 0 && errno == ENOENT) {
			/* doesn't exist */
			mode_t old_mask = umask(0);
			fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
			umask(old_mask);
			if (fd != -1 || errno != EEXIST)
				break;
		}

		/* wait and try again - very unlikely */
		sleep(2);
		tv = &tv_now;
		if (gettimeofday(&tv_now, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	}

	*fname_r = t_strdup(path);
	if (fd == -1) {
		if (ENOSPACE(errno)) {
			mail_storage_set_error(ibox->box.storage,
					       "Not enough disk space");
		} else {
			mail_storage_set_critical(ibox->box.storage,
						  "open(%s) failed: %m", path);
		}
	}

	pool_unref(pool);
	return fd;
}

/* a char* hash function from ASU -- from glib */
unsigned int maildir_hash(const void *p)
{
        const unsigned char *s = p;
	unsigned int g, h = 0;

	while (*s != ':' && *s != '\0') {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}

		s++;
	}

	return h;
}

int maildir_cmp(const void *p1, const void *p2)
{
	const char *s1 = p1, *s2 = p2;

	while (*s1 == *s2 && *s1 != ':' && *s1 != '\0') {
		s1++; s2++;
	}
	if ((*s1 == '\0' || *s1 == ':') &&
	    (*s2 == '\0' || *s2 == ':'))
		return 0;
	return *s1 - *s2;
}
