/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

/* note that everything here depends on uidlist file being locked the whole
   time. that's why we don't have any locking of our own, or that we do things
   that would be racy otherwise. */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "istream.h"
#include "eacces-error.h"
#include "file-dotlock.h"
#include "write-full.h"
#include "nfs-workarounds.h"
#include "maildir-storage.h"
#include "maildir-uidlist.h"
#include "maildir-keywords.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <utime.h>

/* how many seconds to wait before overriding dovecot-keywords.lock */
#define KEYWORDS_LOCK_STALE_TIMEOUT (60*2)

struct maildir_keywords {
	struct maildir_mailbox *mbox;
	struct mail_storage *storage;
	char *path;

	pool_t pool;
	ARRAY_TYPE(keywords) list;
	struct hash_table *hash; /* name -> idx+1 */

        struct dotlock_settings dotlock_settings;

	time_t synced_mtime;
	unsigned int synced:1;
	unsigned int changed:1;
};

struct maildir_keywords_sync_ctx {
	struct maildir_keywords *mk;
	struct mail_index *index;

	const ARRAY_TYPE(keywords) *keywords;
	ARRAY_DEFINE(idx_to_chr, char);
	unsigned int chridx_to_idx[MAILDIR_MAX_KEYWORDS];
	bool readonly;
};

struct maildir_keywords *maildir_keywords_init(struct maildir_mailbox *mbox)
{
	struct maildir_keywords *mk;

	mk = maildir_keywords_init_readonly(&mbox->box);
	mk->mbox = mbox;
	return mk;
}

struct maildir_keywords *
maildir_keywords_init_readonly(struct mailbox *box)
{
	struct maildir_keywords *mk;
	const char *dir;

	dir = mailbox_list_get_path(box->list, box->name,
				    MAILBOX_LIST_PATH_TYPE_CONTROL);

	mk = i_new(struct maildir_keywords, 1);
	mk->storage = box->storage;
	mk->path = i_strconcat(dir, "/" MAILDIR_KEYWORDS_NAME, NULL);
	mk->pool = pool_alloconly_create("maildir keywords", 512);
	i_array_init(&mk->list, MAILDIR_MAX_KEYWORDS);
	mk->hash = hash_table_create(default_pool, mk->pool, 0,
				     strcase_hash, (hash_cmp_callback_t *)strcasecmp);

	mk->dotlock_settings.use_excl_lock =
		box->storage->set->dotlock_use_excl;
	mk->dotlock_settings.nfs_flush =
		box->storage->set->mail_nfs_storage;
	mk->dotlock_settings.timeout =
		mail_storage_get_lock_timeout(box->storage,
					      KEYWORDS_LOCK_STALE_TIMEOUT + 2);
	mk->dotlock_settings.stale_timeout = KEYWORDS_LOCK_STALE_TIMEOUT;
	mk->dotlock_settings.temp_prefix =
		mailbox_list_get_temp_prefix(box->list);
	return mk;
}

void maildir_keywords_deinit(struct maildir_keywords **_mk)
{
	struct maildir_keywords *mk = *_mk;

	*_mk = NULL;
	hash_table_destroy(&mk->hash);
	array_free(&mk->list);
	pool_unref(&mk->pool);
	i_free(mk->path);
	i_free(mk);
}

static void maildir_keywords_clear(struct maildir_keywords *mk)
{
	array_clear(&mk->list);
	hash_table_clear(mk->hash, FALSE);
	p_clear(mk->pool);
}

static int maildir_keywords_sync(struct maildir_keywords *mk)
{
	struct istream *input;
	struct stat st;
	char *line, *p, *new_name;
	const char **strp;
	unsigned int idx;
	int fd;

        /* Remember that we rely on uidlist file locking in here. That's why
           we rely on stat()'s timestamp and don't bother handling ESTALE
           errors. */

	if (mk->storage->set->mail_nfs_storage) {
		/* file is updated only by replacing it, no need to flush
		   attribute cache */
		nfs_flush_file_handle_cache(mk->path);
	}

	if (nfs_safe_stat(mk->path, &st) < 0) {
		if (errno == ENOENT) {
			maildir_keywords_clear(mk);
			mk->synced = TRUE;
			return 0;
		}
                mail_storage_set_critical(mk->storage,
					  "stat(%s) failed: %m", mk->path);
		return -1;
	}

	if (st.st_mtime == mk->synced_mtime) {
		/* hasn't changed */
		mk->synced = TRUE;
		return 0;
	}
	mk->synced_mtime = st.st_mtime;

	fd = open(mk->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			maildir_keywords_clear(mk);
			mk->synced = TRUE;
			return 0;
		}
                mail_storage_set_critical(mk->storage,
					  "open(%s) failed: %m", mk->path);
		return -1;
	}

	maildir_keywords_clear(mk);
	input = i_stream_create_fd(fd, 1024, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		p = strchr(line, ' ');
		if (p == NULL) {
			/* note that when converting .customflags file this
			   case happens in the first line. */
			continue;
		}
		*p++ = '\0';

		if (str_to_uint(line, &idx) < 0 ||
		    idx >= MAILDIR_MAX_KEYWORDS || *p == '\0') {
			/* shouldn't happen */
			continue;
		}

		/* save it */
		new_name = p_strdup(mk->pool, p);
		hash_table_insert(mk->hash, new_name, POINTER_CAST(idx + 1));

		strp = array_idx_modifiable(&mk->list, idx);
		*strp = new_name;
	}
	i_stream_destroy(&input);

	if (close(fd) < 0) {
                mail_storage_set_critical(mk->storage,
					  "close(%s) failed: %m", mk->path);
		return -1;
	}

	mk->synced = TRUE;
	return 0;
}

static int
maildir_keywords_lookup(struct maildir_keywords *mk, const char *name,
			unsigned int *chridx_r)
{
	void *p;

	p = hash_table_lookup(mk->hash, name);
	if (p == NULL) {
		if (mk->synced)
			return 0;

		if (maildir_keywords_sync(mk) < 0)
			return -1;
		i_assert(mk->synced);

		p = hash_table_lookup(mk->hash, name);
		if (p == NULL)
			return 0;
	}

	*chridx_r = POINTER_CAST_TO(p, int)-1;
	return 1;
}

static void
maildir_keywords_create(struct maildir_keywords *mk, const char *name,
			unsigned int chridx)
{
	const char **strp;
	char *new_name;

	i_assert(chridx < MAILDIR_MAX_KEYWORDS);

	new_name = p_strdup(mk->pool, name);
	hash_table_insert(mk->hash, new_name, POINTER_CAST(chridx + 1));

	strp = array_idx_modifiable(&mk->list, chridx);
	*strp = new_name;

	mk->changed = TRUE;
}

static int
maildir_keywords_lookup_or_create(struct maildir_keywords *mk, const char *name,
				  unsigned int *chridx_r)
{
	const char *const *keywords;
	unsigned int i, count;
	int ret;

	if ((ret = maildir_keywords_lookup(mk, name, chridx_r)) != 0)
		return ret;

	/* see if we are full */
	keywords = array_get(&mk->list, &count);
	for (i = 0; i < count; i++) {
		if (keywords[i] == NULL)
			break;
	}

	if (i == count && count >= MAILDIR_MAX_KEYWORDS)
		return -1;

	if (!maildir_uidlist_is_locked(mk->mbox->uidlist))
		return -1;

	maildir_keywords_create(mk, name, i);
	*chridx_r = i;
	return 1;
}

static const char *
maildir_keywords_idx(struct maildir_keywords *mk, unsigned int idx)
{
	const char *const *keywords;
	unsigned int count;

	keywords = array_get(&mk->list, &count);
	if (idx >= count) {
		if (mk->synced)
			return NULL;

		if (maildir_keywords_sync(mk) < 0)
			return NULL;
		i_assert(mk->synced);

		keywords = array_get(&mk->list, &count);
	}
	return idx >= count ? NULL : keywords[idx];
}

static int maildir_keywords_write_fd(struct maildir_keywords *mk,
				     const char *path, int fd)
{
	struct maildir_mailbox *mbox = mk->mbox;
	struct mailbox *box = &mbox->box;
	const char *const *keywords;
	unsigned int i, count;
	string_t *str;
	struct stat st;

	str = t_str_new(256);
	keywords = array_get(&mk->list, &count);
	for (i = 0; i < count; i++) {
		if (keywords[i] != NULL)
			str_printfa(str, "%u %s\n", i, keywords[i]);
	}
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		mail_storage_set_critical(mk->storage,
					  "write_full(%s) failed: %m", path);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		mail_storage_set_critical(mk->storage,
					  "fstat(%s) failed: %m", path);
		return -1;
	}

	if (st.st_gid != box->file_create_gid &&
	    box->file_create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, box->file_create_gid) < 0) {
			if (errno == EPERM) {
				mail_storage_set_critical(mk->storage, "%s",
					eperm_error_get_chgrp("fchown", path,
						box->file_create_gid,
						box->file_create_gid_origin));
			} else {
				mail_storage_set_critical(mk->storage,
					"fchown(%s) failed: %m", path);
			}
		}
	}

	/* mtime must grow every time */
	if (st.st_mtime <= mk->synced_mtime) {
		struct utimbuf ut;

		mk->synced_mtime = ioloop_time <= mk->synced_mtime ?
			mk->synced_mtime + 1 : ioloop_time;
		ut.actime = ioloop_time;
		ut.modtime = mk->synced_mtime;
		if (utime(path, &ut) < 0) {
			mail_storage_set_critical(mk->storage,
				"utime(%s) failed: %m", path);
			return -1;
		}
	}

	if (fsync(fd) < 0) {
		mail_storage_set_critical(mk->storage,
			"fsync(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int maildir_keywords_commit(struct maildir_keywords *mk)
{
	struct dotlock *dotlock;
	const char *lock_path;
	mode_t old_mask;
	int i, fd;

	mk->synced = FALSE;

	if (!mk->changed || mk->mbox == NULL)
		return 0;

	lock_path = t_strconcat(mk->path, ".lock", NULL);
	(void)unlink(lock_path);

	for (i = 0;; i++) {
		/* we could just create the temp file directly, but doing it
		   this ways avoids potential problems with overwriting
		   contents in malicious symlinks */
		old_mask = umask(0777 & ~mk->mbox->box.file_create_mode);
		fd = file_dotlock_open(&mk->dotlock_settings, mk->path,
				       DOTLOCK_CREATE_FLAG_NONBLOCK, &dotlock);
		umask(old_mask);
		if (fd != -1)
			break;

		if (errno != ENOENT || i == MAILDIR_DELETE_RETRY_COUNT) {
			mail_storage_set_critical(mk->storage,
				"file_dotlock_open(%s) failed: %m", mk->path);
			return -1;
		}
		/* the control dir doesn't exist. create it unless the whole
		   mailbox was just deleted. */
		if (!maildir_set_deleted(&mk->mbox->box))
			return -1;
	}

	if (maildir_keywords_write_fd(mk, lock_path, fd) < 0) {
		file_dotlock_delete(&dotlock);
		return -1;
	}

	if (file_dotlock_replace(&dotlock, 0) < 0) {
		mail_storage_set_critical(mk->storage,
			"file_dotlock_replace(%s) failed: %m", mk->path);
		return -1;
	}

	mk->changed = FALSE;
	return 0;
}

struct maildir_keywords_sync_ctx *
maildir_keywords_sync_init(struct maildir_keywords *mk,
			   struct mail_index *index)
{
	struct maildir_keywords_sync_ctx *ctx;

	ctx = i_new(struct maildir_keywords_sync_ctx, 1);
	ctx->mk = mk;
	ctx->index = index;
	ctx->keywords = mail_index_get_keywords(index);
	i_array_init(&ctx->idx_to_chr, MAILDIR_MAX_KEYWORDS);
	return ctx;
}

struct maildir_keywords_sync_ctx *
maildir_keywords_sync_init_readonly(struct maildir_keywords *mk,
				    struct mail_index *index)
{
	struct maildir_keywords_sync_ctx *ctx;

	ctx = maildir_keywords_sync_init(mk, index);
	ctx->readonly = TRUE;
	return ctx;
}

void maildir_keywords_sync_deinit(struct maildir_keywords_sync_ctx **_ctx)
{
	struct maildir_keywords_sync_ctx *ctx = *_ctx;

	*_ctx = NULL;

	T_BEGIN {
		(void)maildir_keywords_commit(ctx->mk);
	} T_END;

	array_free(&ctx->idx_to_chr);
	i_free(ctx);
}

unsigned int maildir_keywords_char_idx(struct maildir_keywords_sync_ctx *ctx,
				       char keyword)
{
	const char *name;
	unsigned int chridx, idx;

	i_assert(keyword >= MAILDIR_KEYWORD_FIRST &&
		 keyword <= MAILDIR_KEYWORD_LAST);
	chridx = keyword - MAILDIR_KEYWORD_FIRST;

	if (ctx->chridx_to_idx[chridx] != 0)
		return ctx->chridx_to_idx[chridx];

	/* lookup / create */
	name = maildir_keywords_idx(ctx->mk, chridx);
	if (name == NULL) {
		/* name is lost. just generate one ourself. */
		name = t_strdup_printf("unknown-%u", chridx);
		while (maildir_keywords_lookup(ctx->mk, name, &idx) > 0) {
			/* don't create a duplicate name.
			   keep changing the name until it doesn't exist */
			name = t_strconcat(name, "?", NULL);
		}
                maildir_keywords_create(ctx->mk, name, chridx);
	}

	mail_index_keyword_lookup_or_create(ctx->index, name, &idx);
        ctx->chridx_to_idx[chridx] = idx;
	return idx;
}

char maildir_keywords_idx_char(struct maildir_keywords_sync_ctx *ctx,
			       unsigned int idx)
{
	const char *const *name_p;
	char *chr_p;
	unsigned int chridx;
	int ret;

	chr_p = array_idx_modifiable(&ctx->idx_to_chr, idx);
	if (*chr_p != '\0')
		return *chr_p;

	name_p = array_idx(ctx->keywords, idx);
	ret = !ctx->readonly ?
		maildir_keywords_lookup_or_create(ctx->mk, *name_p, &chridx) :
		maildir_keywords_lookup(ctx->mk, *name_p, &chridx);
	if (ret <= 0)
		return '\0';

	*chr_p = chridx + MAILDIR_KEYWORD_FIRST;
	return *chr_p;
}
