/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "file-lock.h"
#include "mmap-util.h"
#include "write-full.h"
#include "imap-util.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-custom-flags.h"

#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Header is simply a counter which is increased every time the file is
   updated. This allows other processes to easily notice if there's been
   any changes. */

#define COUNTER_SIZE 4
#define HEADER_SIZE (COUNTER_SIZE + 1) /* 0000\n */

struct mail_custom_flags {
	struct mail_index *index;
	char *filepath;
	int fd;
	int lock_type;

	char sync_counter[COUNTER_SIZE];
	char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT];

	void *mmap_base;
	size_t mmap_length;

	unsigned int syncing:1;
	unsigned int noupdate:1;
	unsigned int changed:1;
};

static int lock_file(struct mail_custom_flags *mcf, int type);

static int index_cf_set_syscall_error(struct mail_custom_flags *mcf,
				      const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		mcf->index->nodiskspace = TRUE;
		return FALSE;
	}

	index_set_error(mcf->index, "%s failed with custom flags file %s: %m",
			function, mcf->filepath);
	return FALSE;
}

static int update_mmap(struct mail_custom_flags *mcf)
{
	if (mcf->mmap_base != NULL) {
		if (munmap(mcf->mmap_base, mcf->mmap_length) < 0)
			index_cf_set_syscall_error(mcf, "munmap()");
	}

	mcf->mmap_base = mmap_rw_file(mcf->fd, &mcf->mmap_length);
	if (mcf->mmap_base == MAP_FAILED) {
		mcf->mmap_base = NULL;
		return index_cf_set_syscall_error(mcf, "mmap()");
	}

	(void)madvise(mcf->mmap_base, mcf->mmap_length, MADV_SEQUENTIAL);
	return TRUE;
}

static int custom_flags_init(struct mail_custom_flags *mcf)
{
	static char buf[HEADER_SIZE] = "0000\n";
	struct stat st;
	int failed;

	if (!lock_file(mcf, F_WRLCK))
		return FALSE;

	failed = FALSE;

	/* make sure it's still empty after locking */
	if (fstat(mcf->fd, &st) < 0) {
		index_cf_set_syscall_error(mcf, "fstat()");
		failed = TRUE;
	} else if (st.st_size < HEADER_SIZE) {
		/* write the header - it's a 4 byte counter as hex */
		if (write_full(mcf->fd, buf, HEADER_SIZE) < 0) {
			index_cf_set_syscall_error(mcf, "write_full()");
			failed = TRUE;
		}
	}

	if (!lock_file(mcf, F_UNLCK))
		return FALSE;

	return !failed;
}

static void custom_flags_sync(struct mail_custom_flags *mcf)
{
	char *data, *data_end, *line;
	unsigned int num;
	int i;

	if (mcf->noupdate)
		return;

	memcpy(mcf->sync_counter, mcf->mmap_base, COUNTER_SIZE);

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (mcf->custom_flags[i] != NULL) {
			i_free(mcf->custom_flags[i]);
                        mcf->custom_flags[i] = NULL;
		}
	}

	data = mcf->mmap_base;
	data_end = data + mcf->mmap_length;

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

			if (mcf->custom_flags[num] != NULL) {
				i_warning("Error in custom flags file %s: "
					  "Duplicated ID %u", mcf->filepath,
					  num);
				i_free(mcf->custom_flags[num]);
			}

			mcf->custom_flags[num] = i_strdup_until(line, data);
		}
	}
}

static int custom_flags_check_sync(struct mail_custom_flags *mcf)
{
	if (mcf->noupdate)
		return TRUE;

	if (mcf->mmap_length != 0 &&
	    memcmp(mcf->sync_counter, mcf->mmap_base, COUNTER_SIZE) == 0)
		return TRUE;

	/* file modified, resync */
	if (!update_mmap(mcf))
		return FALSE;

	if (mcf->mmap_length < HEADER_SIZE) {
		/* it's broken, rewrite header */
		if (mcf->lock_type == F_RDLCK)
			(void)lock_file(mcf, F_UNLCK);

		if (lseek(mcf->fd, 0, SEEK_SET) < 0) {
			index_cf_set_syscall_error(mcf, "lseek()");
			return FALSE;
		}

		if (!custom_flags_init(mcf))
			return FALSE;

		if (!update_mmap(mcf))
			return FALSE;
	}

	custom_flags_sync(mcf);
	mcf->changed = TRUE;
	return TRUE;
}

static int lock_file(struct mail_custom_flags *mcf, int type)
{
	if (mcf->lock_type == type)
		return TRUE;

	if (mcf->fd != -1) {
		/* FIXME: possibility to use .lock file instead */
		if (file_wait_lock(mcf->fd, type) <= 0) {
			index_cf_set_syscall_error(mcf, "file_wait_lock()");
			return FALSE;
		}
	}

	mcf->lock_type = type;

	if (type != F_UNLCK && !mcf->syncing) {
		mcf->syncing = TRUE;
		if (!custom_flags_check_sync(mcf)) {
			mcf->syncing = FALSE;
			return FALSE;
		}

		/* syncing may have changed locking, do it again */
		if (!lock_file(mcf, type)) {
			mcf->syncing = FALSE;
			return FALSE;
		}

		mcf->syncing = FALSE;
	}
	return TRUE;
}

int mail_custom_flags_open_or_create(struct mail_index *index)
{
	struct mail_custom_flags *mcf;
	const char *path;
	int fd;

	path = t_strconcat(index->custom_flags_dir, "/",
			   CUSTOM_FLAGS_FILE_NAME, NULL);
	if (path == NULL)
		fd = -1;
	else {
		fd = open(path, O_RDWR | O_CREAT, 0660);
		if (fd == -1)
			index_file_set_syscall_error(index, path, "open()");
	}

	mcf = i_new(struct mail_custom_flags, 1);
	mcf->index = index;
	mcf->filepath = i_strdup(path);
	mcf->fd = fd;

	if (fd != -1) {
		if (!update_mmap(mcf)) {
			(void)close(mcf->fd);
			mcf->fd = -1;
		}

		if (mcf->mmap_length < HEADER_SIZE) {
			/* we just created it, write the header */
			mcf->syncing = TRUE;
			if (!custom_flags_init(mcf) || !update_mmap(mcf)) {
				(void)close(mcf->fd);
				mcf->fd = -1;
			}
			mcf->syncing = FALSE;
		}
	}

	mcf->noupdate = mcf->fd == -1;
	mcf->index->allow_new_custom_flags = mcf->fd != -1;

	custom_flags_sync(mcf);

	index->custom_flags = mcf;
	return TRUE;
}

void mail_custom_flags_free(struct mail_custom_flags *mcf)
{
	int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++)
		i_free(mcf->custom_flags[i]);

	if (mcf->mmap_base != NULL) {
		if (munmap(mcf->mmap_base, mcf->mmap_length) < 0)
			index_cf_set_syscall_error(mcf, "munmap()");
	}

	if (mcf->fd != -1) {
		if (close(mcf->fd) < 0)
			index_cf_set_syscall_error(mcf, "close()");
	}

	i_free(mcf->filepath);
	i_free(mcf);
}

static int custom_flags_update_counter(struct mail_custom_flags *mcf)
{
	int i;

	if (lseek(mcf->fd, 0, SEEK_SET) < 0)
		return index_cf_set_syscall_error(mcf, "lseek()");

	for (i = COUNTER_SIZE-1; i >= 0; i--) {
		if (mcf->sync_counter[i] == '9') {
			mcf->sync_counter[i] = 'A';
			break;
		}

		if (mcf->sync_counter[i] == 'F') {
			/* digit wrapped, update next one */
			mcf->sync_counter[i] = '0';
		} else {
			mcf->sync_counter[i]++;
			break;
		}
	}

	if (write_full(mcf->fd, mcf->sync_counter, COUNTER_SIZE) < 0)
		return index_cf_set_syscall_error(mcf, "write_full()");

	mcf->changed = TRUE;
	return TRUE;
}

static int custom_flags_add(struct mail_custom_flags *mcf,
			    int idx, const char *name)
{
	const char *buf;
	size_t len;
	off_t pos;

	i_assert(idx < MAIL_CUSTOM_FLAGS_COUNT);

	/* first update the sync counter */
	if (!custom_flags_update_counter(mcf))
		return FALSE;

	/* add the flag */
	pos = lseek(mcf->fd, 0, SEEK_END);
	if (pos < 0)
		return index_cf_set_syscall_error(mcf, "lseek()");

	if (pos != (off_t)mcf->mmap_length) {
		index_set_error(mcf->index, "Custom flags file %s was "
				"changed by someone while we were"
				"trying to modify it", mcf->filepath);
		return FALSE;
	}

	buf = t_strdup_printf("\n%d %s\n", idx, name);
	len = strlen(buf);

	if (((char *) mcf->mmap_base)[mcf->mmap_length-1] == '\n') {
		/* don't add the \n prefix */
		buf++;
		len--;
	}

	if (write_full(mcf->fd, buf, len) < 0)
		return index_cf_set_syscall_error(mcf, "write_full()");

	if (!update_mmap(mcf))
		return FALSE;

	return TRUE;
}

static int custom_flags_remove(struct mail_custom_flags *mcf, unsigned int idx)
{
	char *data, *data_end, *line;
	unsigned int num;
	int pos, linelen;

	data = mcf->mmap_base;
	data_end = data + mcf->mmap_length;

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
			pos = (int) (data - (char *) mcf->mmap_base);
			memmove(line, data, mcf->mmap_length - pos);

			mcf->mmap_length -= linelen;
			if (ftruncate(mcf->fd, (off_t) mcf->mmap_length) < 0) {
				index_cf_set_syscall_error(mcf, "ftruncate()");
				return FALSE;
			}

			return TRUE;
		}
	}

	return FALSE;
}

static int find_first_unused_flag(struct mail_custom_flags *mcf)
{
	int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (mcf->custom_flags[i] == NULL)
			return i;
	}

	return -1;
}

static void remove_unused_custom_flags(struct mail_custom_flags *mcf,
				       enum mail_flags used_flags)
{
	unsigned int i;

	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if ((used_flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT))) == 0) {
			i_free(mcf->custom_flags[i]);
			mcf->custom_flags[i] = NULL;

			custom_flags_remove(mcf, i);
		}
	}
}

static enum mail_flags get_used_flags(struct mail_custom_flags *mcf)
{
	struct mail_index_record *rec;
	enum mail_flags used_flags;

	used_flags = 0;

	rec = mcf->index->lookup(mcf->index, 1);
	while (rec != NULL) {
		used_flags |= rec->msg_flags;
		rec = mcf->index->next(mcf->index, rec);
	}

	return used_flags;
}

static int get_flag_index(struct mail_custom_flags *mcf, const char *flag,
			  int index_hint)
{
	int i, first_empty;

	if (index_hint >= 0 && index_hint < MAIL_CUSTOM_FLAGS_COUNT) {
		if (mcf->custom_flags[index_hint] != NULL &&
		    strcasecmp(mcf->custom_flags[index_hint], flag) == 0)
			return index_hint;
	}

	/* check existing flags */
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (mcf->custom_flags[i] != NULL) {
			i_assert(mcf->custom_flags[i] != '\0');
			if (strcasecmp(mcf->custom_flags[i], flag) == 0)
				return i;
		}
	}

	if (mcf->noupdate)
		return -1;

	if (mcf->lock_type != F_WRLCK) {
		/* unlock + write lock, don't directly change from
		   read -> write lock to prevent deadlocking */
		if (!lock_file(mcf, F_UNLCK) || !lock_file(mcf, F_WRLCK))
			return -1;

		/* list may have already changed between the lock changes,
		   check again */
		return get_flag_index(mcf, flag, -1);
	}

	/* new flag, add it. first find the first free flag, note that
	   unlock+lock might have just changed it. */
	first_empty = find_first_unused_flag(mcf);
	if (first_empty == -1) {
		/* all custom flags are used, see if some of them are unused */
		remove_unused_custom_flags(mcf, get_used_flags(mcf));

		first_empty = find_first_unused_flag(mcf);
		if (first_empty == -1) {
			/* everything is in use */
			return -1;
		}
	}

	if (!custom_flags_add(mcf, first_empty, flag))
		return -1;

	mcf->index->set_flags |= MAIL_INDEX_FLAG_DIRTY_CUSTOMFLAGS;

	mcf->custom_flags[first_empty] = i_strdup(flag);
	return first_empty;
}

int mail_custom_flags_fix_list(struct mail_custom_flags *mcf,
			       enum mail_flags *flags,
			       const char *custom_flags[], unsigned int count)
{
	enum mail_flags oldflags, flag;
	int i, idx;

	i_assert(count < 32);

	if ((*flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return 1;

	if (!lock_file(mcf, F_RDLCK))
		return -1;

	oldflags = *flags;
	*flags &= MAIL_SYSTEM_FLAGS_MASK;

	flag = MAIL_CUSTOM_FLAG_1;
	for (i = 0; i < (int)count; i++, flag <<= 1) {
		if ((oldflags & flag) && custom_flags[i] != NULL) {
			i_assert(*custom_flags[i] != '\0');

			idx = get_flag_index(mcf, custom_flags[i], i);
			if (idx == -1) {
				(void)lock_file(mcf, F_UNLCK);
				return 0;
			}
			*flags |= 1 << (idx + MAIL_CUSTOM_FLAG_1_BIT);
		}
	}

	if (!lock_file(mcf, F_UNLCK))
		return -1;

	return 1;
}

const char **mail_custom_flags_list_get(struct mail_custom_flags *mcf)
{
	return (const char **) mcf->custom_flags;
}

int mail_custom_flags_has_changes(struct mail_custom_flags *mcf)
{
	if (!mcf->changed)
		return FALSE;
	else {
		mcf->changed = FALSE;
		return TRUE;
	}
}
