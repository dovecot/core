/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "write-full.h"
#include "imap-util.h"
#include "flags-file.h"

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

/* Header is simply a counter which is increased every time the file is
   updated. This allows other processes to easily notice if there's been
   any changes. */

#define COUNTER_SIZE 4
#define HEADER_SIZE (COUNTER_SIZE + 1) /* 0000\n */

struct _FlagsFile {
	MailStorage *storage;
	char *path;
	int fd;
	int lock_type;

	char sync_counter[COUNTER_SIZE];
	char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT];
	int custom_flags_refcount;

	void *mmap_base;
	size_t mmap_length;

	unsigned int syncing:1;
};

static int lock_file(FlagsFile *ff, int type);

static int update_mmap(FlagsFile *ff)
{
	ff->mmap_base = mmap_rw_file(ff->fd, &ff->mmap_length);
	if (ff->mmap_base == MAP_FAILED) {
		ff->mmap_base = NULL;
		mail_storage_set_critical(ff->storage, "mmap() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	(void)madvise(ff->mmap_base, ff->mmap_length, MADV_SEQUENTIAL);
	return TRUE;
}

static int flags_file_init(FlagsFile *ff)
{
	static char buf[HEADER_SIZE] = "0000\n";
	off_t pos;

	if (!lock_file(ff, F_WRLCK))
		return FALSE;

	/* make sure it's still empty after locking */
	pos = lseek(ff->fd, 0, SEEK_END);
	if (pos != -1 && pos < HEADER_SIZE)
		pos = lseek(ff->fd, 0, SEEK_SET);

	if (pos == -1) {
		mail_storage_set_critical(ff->storage, "lseek() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	/* write the header - it's a 4 byte counter as hex */
	if (write_full(ff->fd, buf, HEADER_SIZE) < 0) {
		mail_storage_set_critical(ff->storage, "write() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	if (!lock_file(ff, F_UNLCK))
		return FALSE;

	return TRUE;
}

static void flags_file_sync(FlagsFile *ff)
{
	char *data, *data_end, *line;
	unsigned int num;
	int i;

	memcpy(ff->sync_counter, ff->mmap_base, COUNTER_SIZE);

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (ff->custom_flags[i] != NULL) {
			i_free(ff->custom_flags[i]);
                        ff->custom_flags[i] = NULL;
		}
	}

	data = ff->mmap_base;
	data_end = data + ff->mmap_length;

	/* this loop skips the first line, which is the header */
	while (data != data_end) {
		if (*data != '\n') {
			data++;
			continue;
		}

		/* beginning of line, get the index */
		if (data+1 == data_end)
			break;
		data++;

		if (!i_isdigit(*data))
			continue;

		num = 0;
		while (data != data_end && *data >= '0' && *data <= '9') {
			num = num*10 + (*data-'0');
			data++;
		}

		if (num < MAIL_CUSTOM_FLAGS_COUNT) {
			/* get the name */
			if (data == data_end || *data != ' ')
				continue;

			line = ++data;
			while (data != data_end && *data != '\n')
				data++;

			if (ff->custom_flags[num] != NULL) {
				i_warning("Error in custom flags file %s: "
					  "Duplicated ID %u", ff->path, num);
				i_free(ff->custom_flags[num]);
			}

			ff->custom_flags[num] = i_strdup_until(line, data);
		}
	}
}

static int flags_file_check_sync(FlagsFile *ff)
{
	if (ff->custom_flags_refcount > 0) {
		/* we've been locked from updates for now.. */
		return TRUE;
	}

	if (ff->mmap_length != 0 &&
	    memcmp(ff->sync_counter, ff->mmap_base, COUNTER_SIZE) == 0)
		return TRUE;

	/* file modified, resync */
	if (!update_mmap(ff))
		return FALSE;

	if (ff->mmap_length < HEADER_SIZE) {
		/* it's broken, rewrite header */
		if (ff->lock_type == F_RDLCK)
			(void)lock_file(ff, F_UNLCK);

		if (!flags_file_init(ff))
			return FALSE;

		if (!update_mmap(ff))
			return FALSE;
	}

	flags_file_sync(ff);
	return TRUE;
}

static int lock_file(FlagsFile *ff, int type)
{
	struct flock fl;

	if (ff->lock_type == type)
		return TRUE;

	/* lock whole file */
	fl.l_type = type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	while (fcntl(ff->fd, F_SETLKW, &fl) == -1) {
		if (errno != EINTR) {
			mail_storage_set_critical(ff->storage, "fcntl() failed "
						  "for flags file %s: %m",
						  ff->path);
			return FALSE;
		}
	}

	ff->lock_type = type;

	if (type != F_UNLCK && !ff->syncing) {
		ff->syncing = TRUE;
		if (!flags_file_check_sync(ff)) {
			ff->syncing = FALSE;
			return FALSE;
		}

		/* syncing may have changed locking, do it again */
		if (!lock_file(ff, type)) {
			ff->syncing = FALSE;
			return FALSE;
		}

		ff->syncing = FALSE;
	}
	return TRUE;
}

FlagsFile *flags_file_open_or_create(MailStorage *storage, const char *path)
{
	FlagsFile *ff;
	int fd;

	fd = open(path, O_RDWR | O_CREAT, 0660);
	if (fd == -1) {
		mail_storage_set_critical(storage, "Can't open flags file "
					  "%s: %m", path);
		return NULL;
	}

	ff = i_new(FlagsFile, 1);
	ff->storage = storage;
	ff->path = i_strdup(path);
	ff->fd = fd;

	if (!update_mmap(ff)) {
		flags_file_destroy(ff);
		return NULL;
	}

	if (ff->mmap_length < HEADER_SIZE) {
		/* we just created it, write the header */
		ff->syncing = TRUE;
		if (!flags_file_init(ff) || !update_mmap(ff)) {
			flags_file_destroy(ff);
			return NULL;
		}
		ff->syncing = FALSE;
	}

        flags_file_sync(ff);
	return ff;
}

void flags_file_destroy(FlagsFile *ff)
{
	int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++)
		i_free(ff->custom_flags[i]);

	(void)munmap(ff->mmap_base, ff->mmap_length);
	(void)close(ff->fd);

	i_free(ff->path);
	i_free(ff);
}

static int flags_file_update_counter(FlagsFile *ff)
{
	int i;

	if (lseek(ff->fd, 0, SEEK_SET) == -1) {
		mail_storage_set_critical(ff->storage, "lseek() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	for (i = COUNTER_SIZE-1; i >= 0; i--) {
		if (ff->sync_counter[i] == '9') {
			ff->sync_counter[i] = 'A';
			break;
		}

		if (ff->sync_counter[i] == 'F') {
			/* digit wrapped, update next one */
			ff->sync_counter[i] = '0';
		} else {
			ff->sync_counter[i]++;
			break;
		}
	}

	if (write_full(ff->fd, ff->sync_counter, COUNTER_SIZE) < 0) {
		mail_storage_set_critical(ff->storage, "write() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	return TRUE;
}

static int flags_file_add(FlagsFile *ff, int idx, const char *name)
{
	const char *buf;
	unsigned int len;
	off_t pos;

	i_assert(idx < MAIL_CUSTOM_FLAGS_COUNT);

	/* first update the sync counter */
	if (!flags_file_update_counter(ff))
		return FALSE;

	/* add the flag */
	pos = lseek(ff->fd, 0, SEEK_END);
	if (pos == -1) {
		mail_storage_set_critical(ff->storage, "lseek() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	if (pos != (off_t)ff->mmap_length) {
		mail_storage_set_critical(ff->storage, "flags file %s was "
					  "changed by someone while we were"
					  "trying to modify it", ff->path);
		return FALSE;
	}

	buf = t_strdup_printf("\n%d %s\n", idx, name);
	len = strlen(buf);

	if (((char *) ff->mmap_base)[ff->mmap_length-1] == '\n') {
		/* don't add the \n prefix */
		buf++;
		len--;
	}

	if (write_full(ff->fd, buf, len) < 0) {
		mail_storage_set_critical(ff->storage, "write() failed for "
					  "flags file %s: %m", ff->path);
		return FALSE;
	}

	if (!update_mmap(ff))
		return FALSE;

	return TRUE;
}

static int flags_file_remove(FlagsFile *ff, unsigned int idx)
{
	char *data, *data_end, *line;
	unsigned int num;
	int pos, linelen;

	data = ff->mmap_base;
	data_end = data + ff->mmap_length;

	while (data != data_end) {
		if (*data != '\n') {
			data++;
			continue;
		}

		/* beginning of line, get the index */
		if (data+1 == data_end)
			break;
		line = ++data;

		num = 0;
		while (data != data_end && *data >= '0' && *data <= '9') {
			num = num*10 + (*data-'0');
			data++;
		}

		if (num == idx) {
			/* remove this line */
			while (data != data_end && data[-1] != '\n')
				data++;

			linelen = (int) (data - line);
			pos = (int) (data - (char *) ff->mmap_base);
			memmove(line, data, ff->mmap_length - pos);

			ff->mmap_length -= linelen;
			if (ftruncate(ff->fd, (off_t) ff->mmap_length) == -1) {
				mail_storage_set_critical(ff->storage,
					"ftruncate() failed for flags file "
					"%s: %m", ff->path);
				return FALSE;
			}

			return TRUE;
		}
	}

	return FALSE;
}

static int find_first_unused_flag(FlagsFile *ff)
{
	int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (ff->custom_flags[i] == NULL)
			return i;
	}

	return -1;
}

static void remove_unused_custom_flags(FlagsFile *ff, MailFlags used_flags)
{
	unsigned int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if ((used_flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT))) == 0) {
			i_free(ff->custom_flags[i]);
			ff->custom_flags[i] = NULL;

			flags_file_remove(ff, i);
		}
	}
}

static int get_flag_index(FlagsFile *ff, const char *flag,
			  MailFlags (*get_used_flags)(void *context),
			  void *context)
{
	int i, first_empty;

	/* check existing flags */
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (ff->custom_flags[i] == NULL)
			continue;

		i_assert(ff->custom_flags[i] != '\0');
		if (strcasecmp(ff->custom_flags[i], flag) == 0)
			return i;
	}

	/* unlock + write lock, don't directly change from read -> write lock
	   to prevent deadlocking */
	if (!lock_file(ff, F_UNLCK) || !lock_file(ff, F_WRLCK))
		return -1;

	/* new flag, add it. first find the first free flag, note that
	   unlock+lock might have just changed it. */
	first_empty = find_first_unused_flag(ff);
	if (first_empty == -1) {
		/* all custom flags are used, see if some of them are unused */
		remove_unused_custom_flags(ff, get_used_flags(context));

		first_empty = find_first_unused_flag(ff);
		if (first_empty == -1) {
			/* everything is in use */
			return -1;
		}
	}

	if (!flags_file_add(ff, first_empty, flag))
		return -1;

	ff->custom_flags[first_empty] = i_strdup(flag);
	return first_empty;
}

int flags_file_fix_custom_flags(FlagsFile *ff, MailFlags *flags,
				const char *custom_flags[],
				MailFlags (*get_used_flags)(void *context),
				void *context)
{
	MailFlags oldflags, flag;
	int i, idx;

	if ((*flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return TRUE;

	if (!lock_file(ff, F_RDLCK))
		return FALSE;

	oldflags = *flags;
	*flags &= MAIL_SYSTEM_FLAGS_MASK;

	flag = MAIL_CUSTOM_FLAG_1;
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++, flag <<= 1) {
		if (oldflags & flag) {
			i_assert(custom_flags[i] != NULL &&
				 *custom_flags[i] != '\0');

			idx = get_flag_index(ff, custom_flags[i],
					     get_used_flags, context);
			if (idx == -1) {
				mail_storage_set_error(ff->storage,
					"Maximum number of different custom "
					"flags exceeded");
				(void)lock_file(ff, F_UNLCK);
				return FALSE;
			}
			*flags |= 1 << (idx + MAIL_CUSTOM_FLAG_1_BIT);
		}
	}

	if (!lock_file(ff, F_UNLCK))
		return FALSE;

	return TRUE;
}

const char **flags_file_list_get(FlagsFile *ff)
{
	ff->custom_flags_refcount++;
	return (const char **) ff->custom_flags;
}

void flags_file_list_unref(FlagsFile *ff)
{
	i_assert(ff->custom_flags_refcount > 0);

	ff->custom_flags_refcount--;
}
