/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "hostpid.h"
#include "str.h"
#include "maildir-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

extern struct mail_index maildir_index;

static int maildir_index_open(struct mail_index *index,
			      enum mail_index_open_flags flags)
{
	maildir_clean_tmp(t_strconcat(index->mailbox_path, "/tmp", NULL));
	return mail_index_open(index, flags);
}

const char *maildir_get_location(struct mail_index *index,
				 struct mail_index_record *rec, int *new_dir)
{
	const char *fname, *new_fname;

	if (new_dir != NULL)
		*new_dir = FALSE;

	if (index->new_filenames != NULL) {
		/* this has the most up-to-date filename */
		new_fname = hash_lookup(index->new_filenames,
					POINTER_CAST(rec->uid));
		if (new_fname != NULL) {
			if (*new_fname == '/') {
				new_fname++;
				if (new_dir != NULL)
					*new_dir = TRUE;
			}
			return new_fname;
		}
	}

	/* cache file file should give us at least the base name. */
	fname = mail_cache_lookup_string_field(index->cache, rec,
					       MAIL_CACHE_LOCATION);
	if (fname == NULL) {
		/* Not cached, we'll have to resync the directory. */
		return NULL;
	}

	if (new_dir != NULL) {
		*new_dir = (mail_cache_get_index_flags(index->cache, rec) &
			    MAIL_INDEX_FLAG_MAILDIR_NEW) != 0;
	}

	return fname;
}

static int
maildir_file_do_try(struct mail_index *index, struct mail_index_record *rec,
		    const char **fname,
		    maildir_file_do_func *func, void *context)
{
	const char *path;
	int ret, new_dir;

	*fname = maildir_get_location(index, rec, &new_dir);
	if (*fname == NULL)
		return 0;

	if (new_dir) {
		/* probably in new/ dir */
		path = t_strconcat(index->mailbox_path, "/new/", *fname, NULL);
		ret = func(index, path, context);
		if (ret != 0)
			return ret;
	}

	path = t_strconcat(index->mailbox_path, "/cur/", *fname, NULL);
	return func(index, path, context);
}

int maildir_file_do(struct mail_index *index, struct mail_index_record *rec,
		    maildir_file_do_func *func, void *context)
{
	const char *fname;
	int i, ret, found;

	ret = maildir_file_do_try(index, rec, &fname, func, context);
	for (i = 0; i < 10 && ret == 0; i++) {
		/* file is either renamed or deleted. sync the maildir and
		   see which one. if file appears to be renamed constantly,
		   don't try to open it more than 10 times. */
		fname = t_strdup(fname);
		if (!maildir_index_sync_readonly(index, fname, &found))
			return FALSE;

		if (!found && fname != NULL)
			return TRUE;

		ret = maildir_file_do_try(index, rec, &fname, func, context);
	}

	return ret >= 0;
}

const char *maildir_generate_tmp_filename(const struct timeval *tv)
{
	static unsigned int create_count = 0;
	static time_t first_stamp = 0;

	if (first_stamp == 0 || first_stamp == ioloop_time) {
		/* it's possible that within last second another process had
		   the same UID as us. Use usecs to make sure we don't create
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

int maildir_create_tmp(struct mail_index *index, const char *dir, mode_t mode,
		       const char **fname)
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

	*fname = t_strdup(path);
	if (fd == -1)
		index_file_set_syscall_error(index, path, "open()");

	pool_unref(pool);
	return fd;
}

enum mail_flags maildir_filename_get_flags(const char *fname,
					   enum mail_flags default_flags)
{
	const char *info;
	enum mail_flags flags;

	info = strchr(fname, ':');
	if (info == NULL || info[1] != '2' || info[2] != ',')
		return default_flags;

	flags = 0;
	for (info += 3; *info != '\0' && *info != ','; info++) {
		switch (*info) {
		case 'R': /* replied */
			flags |= MAIL_ANSWERED;
			break;
		case 'S': /* seen */
			flags |= MAIL_SEEN;
			break;
		case 'T': /* trashed */
			flags |= MAIL_DELETED;
			break;
		case 'D': /* draft */
			flags |= MAIL_DRAFT;
			break;
		case 'F': /* flagged */
			flags |= MAIL_FLAGGED;
			break;
		default:
			if (*info >= 'a' && *info <= 'z') {
				/* custom flag */
				flags |= 1 << (MAIL_CUSTOM_FLAG_1_BIT +
					       *info-'a');
				break;
			}

			/* unknown flag - ignore */
			break;
		}
	}

	return flags;
}

const char *maildir_filename_set_flags(const char *fname, enum mail_flags flags)
{
	string_t *flags_str;
	const char *info, *oldflags;
	int i, nextflag;

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
	for (;;) {
		/* skip all known flags */
		while (*oldflags == 'D' || *oldflags == 'F' ||
		       *oldflags == 'R' || *oldflags == 'S' ||
		       *oldflags == 'T' ||
		       (*oldflags >= 'a' && *oldflags <= 'z'))
			oldflags++;

		nextflag = *oldflags == '\0' || *oldflags == ',' ? 256 :
			(unsigned char) *oldflags;

		if ((flags & MAIL_DRAFT) && nextflag > 'D') {
			str_append_c(flags_str, 'D');
			flags &= ~MAIL_DRAFT;
		}
		if ((flags & MAIL_FLAGGED) && nextflag > 'F') {
			str_append_c(flags_str, 'F');
			flags &= ~MAIL_FLAGGED;
		}
		if ((flags & MAIL_ANSWERED) && nextflag > 'R') {
			str_append_c(flags_str, 'R');
			flags &= ~MAIL_ANSWERED;
		}
		if ((flags & MAIL_SEEN) && nextflag > 'S') {
			str_append_c(flags_str, 'S');
			flags &= ~MAIL_SEEN;
		}
		if ((flags & MAIL_DELETED) && nextflag > 'T') {
			str_append_c(flags_str, 'T');
			flags &= ~MAIL_DELETED;
		}

		if ((flags & MAIL_CUSTOM_FLAGS_MASK) && nextflag > 'a') {
			for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
				if (flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT)))
					str_append_c(flags_str, 'a' + i);
			}
			flags &= ~MAIL_CUSTOM_FLAGS_MASK;
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

void maildir_index_update_filename(struct mail_index *index, unsigned int uid,
				   const char *fname, int new_dir)
{
	const char *new_fname, *old_fname;

	if (index->new_filename_pool == NULL) {
		index->new_filename_pool =
			pool_alloconly_create("Maildir filenames", 10240);
	}
	if (index->new_filenames == NULL) {
		index->new_filenames =
			hash_create(system_pool, index->new_filename_pool, 0,
				    NULL, NULL);
	}

	t_push();
	new_fname = !new_dir ? fname : t_strconcat("/", fname, NULL);
	old_fname = hash_lookup(index->new_filenames, POINTER_CAST(uid));
	if (old_fname == NULL || strcmp(old_fname, new_fname) != 0) {
		hash_insert(index->new_filenames, POINTER_CAST(uid),
                            p_strdup(index->new_filename_pool, new_fname));
	}
	t_pop();
}

struct mail_index *
maildir_index_alloc(const char *maildir, const char *index_dir,
		    const char *control_dir)
{
	struct mail_index *index;

	i_assert(maildir != NULL);
	i_assert(control_dir != NULL);

	index = i_new(struct mail_index, 1);
	memcpy(index, &maildir_index, sizeof(struct mail_index));

	index->maildir_lock_fd = -1;
	index->mailbox_path = i_strdup(maildir);
	index->control_dir = i_strdup(control_dir);
	index->mailbox_readonly = access(maildir, W_OK) < 0;
	mail_index_init(index, index_dir);
	return index;
}

static void maildir_index_free(struct mail_index *index)
{
	if (index->new_filenames != NULL)
		hash_destroy(index->new_filenames);
	if (index->new_filename_pool != NULL)
		pool_unref(index->new_filename_pool);

	mail_index_close(index);
	i_free(index->dir);
	i_free(index->mailbox_path);
	i_free(index->control_dir);
	i_free(index);
}

static int do_get_received_date(struct mail_index *index,
				const char *path, void *context)
{
	time_t *date = context;
	struct stat st;

	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;
		index_file_set_syscall_error(index, path, "stat()");
		return -1;
	}

	*date = st.st_mtime;
	return 1;
}

static time_t maildir_get_received_date(struct mail_index *index,
					struct mail_index_record *rec)
{
	time_t date;

	/* try getting it from cache */
	if (mail_cache_copy_fixed_field(index->cache, rec,
					MAIL_CACHE_RECEIVED_DATE,
					&date, sizeof(date)))
		return date;

	date = (time_t)-1;
	if (!maildir_file_do(index, rec, do_get_received_date, &date))
		return (time_t)-1;

	return date;
}

struct mail_index maildir_index = {
	maildir_index_open,
	maildir_index_free,
	mail_index_set_lock,
	mail_index_try_lock,
        mail_index_set_lock_notify_callback,
	mail_index_rebuild,
	mail_index_fsck,
	maildir_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	maildir_open_mail,
	maildir_get_received_date,
	mail_index_expunge,
	maildir_index_update_flags,
	mail_index_append,
	mail_index_get_last_error,
	mail_index_get_last_error_text,

	MAIL_INDEX_PRIVATE_FILL
};
