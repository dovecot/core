/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "hash.h"
#include "istream.h"
#include "write-full.h"
#include "seq-range-array.h"
#include "mail-storage.h"
#include "fts-expunge-log.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct fts_expunge_log_record {
	/* CRC32 of this entire record (except this checksum) */
	uint32_t checksum;
	/* Size of this entire record */
	uint32_t record_size;

	/* Mailbox GUID */
	guid_128_t guid;
	/* { uid1, uid2 } pairs */
	/* uint32_t expunge_uid_ranges[]; */

	/* Total number of messages expunged so far in this log */
	/* uint32_t expunge_count; */
};

struct fts_expunge_log {
	char *path;

	int fd;
	struct stat st;
};

struct fts_expunge_log_mailbox {
	guid_128_t guid;
	ARRAY_TYPE(seq_range) uids;
	unsigned uids_count;
};

struct fts_expunge_log_append_ctx {
	struct fts_expunge_log *log;
	pool_t pool;

	HASH_TABLE(uint8_t *, struct fts_expunge_log_mailbox *) mailboxes;
	struct fts_expunge_log_mailbox *prev_mailbox;

	bool failed;
};

struct fts_expunge_log_read_ctx {
	struct fts_expunge_log *log;

	struct istream *input;
	buffer_t buffer;
	struct fts_expunge_log_read_record read_rec;

	bool failed;
	bool corrupted;
	bool unlink;
};

struct fts_expunge_log *fts_expunge_log_init(const char *path)
{
	struct fts_expunge_log *log;

	log = i_new(struct fts_expunge_log, 1);
	log->path = i_strdup(path);
	log->fd = -1;
	return log;
}

void fts_expunge_log_deinit(struct fts_expunge_log **_log)
{
	struct fts_expunge_log *log = *_log;

	*_log = NULL;
	i_close_fd(&log->fd);
	i_free(log->path);
	i_free(log);
}

static int fts_expunge_log_open(struct fts_expunge_log *log, bool create)
{
	int fd;

	i_assert(log->fd == -1);

	/* FIXME: use proper permissions */
	fd = open(log->path, O_RDWR | O_APPEND | (create ? O_CREAT : 0), 0600);
	if (fd == -1) {
		if (errno == ENOENT && !create)
			return 0;

		i_error("open(%s) failed: %m", log->path);
		return -1;
	}
	if (fstat(fd, &log->st) < 0) {
		i_error("fstat(%s) failed: %m", log->path);
		i_close_fd(&fd);
		return -1;
	}
	log->fd = fd;
	return 1;
}

static int
fts_expunge_log_reopen_if_needed(struct fts_expunge_log *log, bool create)
{
	struct stat st;

	if (log->fd == -1)
		return fts_expunge_log_open(log, create);

	if (stat(log->path, &st) == 0) {
		if (st.st_ino == log->st.st_ino &&
		    CMP_DEV_T(st.st_dev, log->st.st_dev)) {
			/* same file */
			return 0;
		}
		/* file changed */
	} else if (errno == ENOENT) {
		/* recreate the file */
	} else {
		i_error("stat(%s) failed: %m", log->path);
		return -1;
	}
	if (close(log->fd) < 0)
		i_error("close(%s) failed: %m", log->path);
	log->fd = -1;
	return fts_expunge_log_open(log, create);
}

static int
fts_expunge_log_read_expunge_count(struct fts_expunge_log *log,
				   uint32_t *expunge_count_r)
{
	ssize_t ret;

	i_assert(log->fd != -1);

	if (fstat(log->fd, &log->st) < 0) {
		i_error("fstat(%s) failed: %m", log->path);
		return -1;
	}
	if ((uoff_t)log->st.st_size < sizeof(*expunge_count_r)) {
		*expunge_count_r = 0;
		return 0;
	}
	/* we'll assume that write()s atomically grow the file size, as
	   O_APPEND almost guarantees. even if not, having a race condition
	   isn't the end of the world. the expunge count is simply read wrong
	   and fts optimize is performed earlier or later than intended. */
	ret = pread(log->fd, expunge_count_r, sizeof(*expunge_count_r),
		    log->st.st_size - 4);
	if (ret < 0) {
		i_error("pread(%s) failed: %m", log->path);
		return -1;
	}
	if (ret != sizeof(*expunge_count_r)) {
		i_error("pread(%s) read only %d of %d bytes", log->path,
			(int)ret, (int)sizeof(*expunge_count_r));
		return -1;
	}
	return 0;
}

struct fts_expunge_log_append_ctx *
fts_expunge_log_append_begin(struct fts_expunge_log *log)
{
	struct fts_expunge_log_append_ctx *ctx;
	pool_t pool;

	pool = pool_alloconly_create("fts expunge log append", 1024);
	ctx = p_new(pool, struct fts_expunge_log_append_ctx, 1);
	ctx->log = log;
	ctx->pool = pool;
	hash_table_create(&ctx->mailboxes, pool, 0, guid_128_hash, guid_128_cmp);

	if (log != NULL && fts_expunge_log_reopen_if_needed(log, TRUE) < 0)
		ctx->failed = TRUE;
	return ctx;
}

static struct fts_expunge_log_mailbox *
fts_expunge_log_mailbox_alloc(struct fts_expunge_log_append_ctx *ctx,
			      const guid_128_t mailbox_guid)
{
	uint8_t *guid_p;
	struct fts_expunge_log_mailbox *mailbox;

	mailbox = p_new(ctx->pool, struct fts_expunge_log_mailbox, 1);
	guid_128_copy(mailbox->guid, mailbox_guid);
	p_array_init(&mailbox->uids, ctx->pool, 16);

	guid_p = mailbox->guid;
	hash_table_insert(ctx->mailboxes, guid_p, mailbox);
	return mailbox;
}

static struct fts_expunge_log_mailbox *
fts_expunge_log_append_mailbox(struct fts_expunge_log_append_ctx *ctx,
			       const guid_128_t mailbox_guid)
{
	const uint8_t *guid_p = mailbox_guid;
	struct fts_expunge_log_mailbox *mailbox;

	if (ctx->prev_mailbox != NULL &&
	    guid_128_equals(mailbox_guid, ctx->prev_mailbox->guid))
		mailbox = ctx->prev_mailbox;
	else {
		mailbox = hash_table_lookup(ctx->mailboxes, guid_p);
		if (mailbox == NULL)
			mailbox = fts_expunge_log_mailbox_alloc(ctx, mailbox_guid);
		ctx->prev_mailbox = mailbox;
	}
	return mailbox;
}
void fts_expunge_log_append_next(struct fts_expunge_log_append_ctx *ctx,
				 const guid_128_t mailbox_guid,
				 uint32_t uid)
{
	struct fts_expunge_log_mailbox *mailbox;

	mailbox = fts_expunge_log_append_mailbox(ctx, mailbox_guid);
	if (!seq_range_array_add(&mailbox->uids, uid))
		mailbox->uids_count++;
}
void fts_expunge_log_append_range(struct fts_expunge_log_append_ctx *ctx,
				  const guid_128_t mailbox_guid,
				  const struct seq_range *uids)
{
	struct fts_expunge_log_mailbox *mailbox;

	mailbox = fts_expunge_log_append_mailbox(ctx, mailbox_guid);
	mailbox->uids_count += seq_range_array_add_range_count(&mailbox->uids,
							       uids->seq1, uids->seq2);
	/* To be honest, an unbacked log doesn't need to maintain the uids_count,
	   but we don't know here if we're supporting an unbacked log or not, so we
	   have to maintain the value, just in case.
	   At the moment, the only caller of this function is for unbacked logs. */
}
void fts_expunge_log_append_record(struct fts_expunge_log_append_ctx *ctx,
				   const struct fts_expunge_log_read_record *record)
{
	const struct seq_range *range;
	/* FIXME: Optimise with a merge */
	array_foreach(&record->uids, range)
		fts_expunge_log_append_range(ctx, record->mailbox_guid, range);
}
static void fts_expunge_log_append_mailbox_record(struct fts_expunge_log_append_ctx *ctx,
						  struct fts_expunge_log_mailbox *mailbox)
{
	const struct seq_range *range;
	/* FIXME: Optimise with a merge */
	array_foreach(&mailbox->uids, range)
		fts_expunge_log_append_range(ctx, mailbox->guid, range);
}

static void
fts_expunge_log_export(struct fts_expunge_log_append_ctx *ctx,
		       uint32_t expunge_count, buffer_t *output)
{
	struct hash_iterate_context *iter;
	uint8_t *guid_p;
	struct fts_expunge_log_mailbox *mailbox;
	struct fts_expunge_log_record *rec;
	size_t rec_offset;

	iter = hash_table_iterate_init(ctx->mailboxes);
	while (hash_table_iterate(iter, ctx->mailboxes, &guid_p, &mailbox)) {
		rec_offset = output->used;
		rec = buffer_append_space_unsafe(output, sizeof(*rec));
		memcpy(rec->guid, mailbox->guid, sizeof(rec->guid));

		/* uint32_t expunge_uid_ranges[]; */
		buffer_append(output, array_front(&mailbox->uids),
			      array_count(&mailbox->uids) *
			      sizeof(struct seq_range));
		/* uint32_t expunge_count; */
		expunge_count += mailbox->uids_count;
		buffer_append(output, &expunge_count, sizeof(expunge_count));

		/* update the header now that we know the record contents */
		rec = buffer_get_space_unsafe(output, rec_offset,
					      output->used - rec_offset);
		rec->record_size = output->used - rec_offset;
		rec->checksum = crc32_data(&rec->record_size,
					   rec->record_size -
					   sizeof(rec->checksum));
	}
	hash_table_iterate_deinit(&iter);
}

static int
fts_expunge_log_write(struct fts_expunge_log_append_ctx *ctx)
{
	struct fts_expunge_log *log = ctx->log;
	buffer_t *buf;
	uint32_t expunge_count, *e;
	int ret;

	/* Unbacked expunge logs cannot be written, by definition */
	i_assert(log != NULL);

	/* try to append to the latest file */
	if (fts_expunge_log_reopen_if_needed(log, TRUE) < 0)
		return -1;

	if (fts_expunge_log_read_expunge_count(log, &expunge_count) < 0)
		return -1;

	buf = buffer_create_dynamic(default_pool, 1024);
	fts_expunge_log_export(ctx, expunge_count, buf);
	/* the file was opened with O_APPEND, so this write() should be
	   appended atomically without any need for locking. */
	for (;;) {
		if ((ret = write_full(log->fd, buf->data, buf->used)) < 0) {
			i_error("write(%s) failed: %m", log->path);
			if (ftruncate(log->fd, log->st.st_size) < 0)
				i_error("ftruncate(%s) failed: %m", log->path);
		}
		if ((ret = fts_expunge_log_reopen_if_needed(log, TRUE)) <= 0)
			break;
		/* the log was unlinked, so we'll need to write again to
		   the new file. the expunge_count needs to be reset to zero
		   from here. */
		e = buffer_get_space_unsafe(buf, buf->used - sizeof(uint32_t),
					    sizeof(uint32_t));
		i_assert(*e > expunge_count);
		*e -= expunge_count;
		expunge_count = 0;
	}
	buffer_free(&buf);

	if (ret == 0) {
		/* finish by closing the log. this forces NFS to flush the
		   changes to disk without our having to explicitly play with
		   fsync() */
		if (close(log->fd) < 0) {
			/* FIXME: we should ftruncate() in case there
			   were partial writes.. */
			i_error("close(%s) failed: %m", log->path);
			ret = -1;
		}
		log->fd = -1;
	}
	return ret;
}

static int fts_expunge_log_append_finalize(struct fts_expunge_log_append_ctx **_ctx,
					   bool commit)
{
	struct fts_expunge_log_append_ctx *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;
	if (commit && ret == 0)
		ret = fts_expunge_log_write(ctx);

	hash_table_destroy(&ctx->mailboxes);
	pool_unref(&ctx->pool);
	return ret;
}

int fts_expunge_log_uid_count(struct fts_expunge_log *log,
			      unsigned int *expunges_r)
{
	int ret;

	if ((ret = fts_expunge_log_reopen_if_needed(log, FALSE)) <= 0) {
		*expunges_r = 0;
		return ret;
	}

	return fts_expunge_log_read_expunge_count(log, expunges_r);
}

int fts_expunge_log_append_commit(struct fts_expunge_log_append_ctx **_ctx)
{
	return fts_expunge_log_append_finalize(_ctx, TRUE);
}

int fts_expunge_log_append_abort(struct fts_expunge_log_append_ctx **_ctx)
{
	return fts_expunge_log_append_finalize(_ctx, FALSE);
}

struct fts_expunge_log_read_ctx *
fts_expunge_log_read_begin(struct fts_expunge_log *log)
{
	struct fts_expunge_log_read_ctx *ctx;

	ctx = i_new(struct fts_expunge_log_read_ctx, 1);
	ctx->log = log;
	if (fts_expunge_log_reopen_if_needed(log, FALSE) < 0)
		ctx->failed = TRUE;
	else if (log->fd != -1)
		ctx->input = i_stream_create_fd(log->fd, (size_t)-1);
	ctx->unlink = TRUE;
	return ctx;
}

static bool
fts_expunge_log_record_size_is_valid(const struct fts_expunge_log_record *rec,
				     unsigned int *uids_size_r)
{
	if (rec->record_size < sizeof(*rec) + sizeof(uint32_t)*3)
		return FALSE;
	*uids_size_r = rec->record_size - sizeof(*rec) - sizeof(uint32_t);
	return *uids_size_r % sizeof(uint32_t)*2 == 0;
}

static void
fts_expunge_log_read_failure(struct fts_expunge_log_read_ctx *ctx,
			     unsigned int wanted_size)
{
	size_t size;

	if (ctx->input->stream_errno != 0) {
		ctx->failed = TRUE;
		i_error("read(%s) failed: %s", ctx->log->path,
			i_stream_get_error(ctx->input));
	} else {
		size = i_stream_get_data_size(ctx->input);
		ctx->corrupted = TRUE;
		i_error("Corrupted fts expunge log %s: "
			"Unexpected EOF (read %"PRIuSIZE_T" / %u bytes)",
			ctx->log->path, size, wanted_size);
	}
}

const struct fts_expunge_log_read_record *
fts_expunge_log_read_next(struct fts_expunge_log_read_ctx *ctx)
{
	const unsigned char *data;
	const struct fts_expunge_log_record *rec;
	unsigned int uids_size;
	size_t size;
	uint32_t checksum;

	if (ctx->input == NULL)
		return NULL;

	/* initial read to try to get the record */
	(void)i_stream_read_bytes(ctx->input, &data, &size, IO_BLOCK_SIZE);
	if (size == 0 && ctx->input->stream_errno == 0) {
		/* expected EOF - mark the file as read by unlinking it */
		if (ctx->unlink)
			i_unlink_if_exists(ctx->log->path);

		/* try reading again, in case something new was written */
		i_stream_sync(ctx->input);
		(void)i_stream_read_bytes(ctx->input, &data, &size,
					  IO_BLOCK_SIZE);
	}
	if (size < sizeof(*rec)) {
		if (size == 0 && ctx->input->stream_errno == 0) {
			/* expected EOF */
			return NULL;
		}
		fts_expunge_log_read_failure(ctx, sizeof(*rec));
		return NULL;
	}
	rec = (const void *)data;

	if (!fts_expunge_log_record_size_is_valid(rec, &uids_size)) {
		ctx->corrupted = TRUE;
		i_error("Corrupted fts expunge log %s: "
			"Invalid record size: %u",
			ctx->log->path, rec->record_size);
		return NULL;
	}

	/* read the entire record */
	while (size < rec->record_size) {
		if (i_stream_read_bytes(ctx->input, &data, &size, rec->record_size) < 0) {
			fts_expunge_log_read_failure(ctx, rec->record_size);
			return NULL;
		}
		rec = (const void *)data;
	}

	/* verify that the record checksum is valid */
	checksum = crc32_data(&rec->record_size,
			      rec->record_size - sizeof(rec->checksum));
	if (checksum != rec->checksum) {
		ctx->corrupted = TRUE;
		i_error("Corrupted fts expunge log %s: "
			"Record checksum mismatch: %u != %u",
			ctx->log->path, checksum, rec->checksum);
		return NULL;
	}

	memcpy(ctx->read_rec.mailbox_guid, rec->guid,
	       sizeof(ctx->read_rec.mailbox_guid));
	/* create the UIDs array by pointing it directly into input
	   stream's buffer */
	buffer_create_from_const_data(&ctx->buffer, rec + 1, uids_size);
	array_create_from_buffer(&ctx->read_rec.uids, &ctx->buffer,
				 sizeof(struct seq_range));

	i_stream_skip(ctx->input, rec->record_size);
	return &ctx->read_rec;
}

int fts_expunge_log_read_end(struct fts_expunge_log_read_ctx **_ctx)
{
	struct fts_expunge_log_read_ctx *ctx = *_ctx;
	int ret = ctx->failed ? -1 : (ctx->corrupted ? 0 : 1);

	*_ctx = NULL;

	if (ctx->corrupted) {
		if (ctx->unlink)
			i_unlink_if_exists(ctx->log->path);
	}

	i_stream_unref(&ctx->input);
	i_free(ctx);
	return ret;
}

int fts_expunge_log_flatten(const char *path,
			    struct fts_expunge_log_append_ctx **flattened_r)
{
	struct fts_expunge_log *read;
	struct fts_expunge_log_read_ctx *read_ctx;
	const struct fts_expunge_log_read_record *record;
	struct fts_expunge_log_append_ctx *append;
	int ret;

	i_assert(path != NULL && flattened_r != NULL);
	read = fts_expunge_log_init(path);

	read_ctx = fts_expunge_log_read_begin(read);
	read_ctx->unlink = FALSE;

	append = fts_expunge_log_append_begin(NULL);
	while((record = fts_expunge_log_read_next(read_ctx)) != NULL) {
		fts_expunge_log_append_record(append, record);
	}

	if ((ret = fts_expunge_log_read_end(&read_ctx)) > 0)
		*flattened_r = append;
	fts_expunge_log_deinit(&read);

	return ret;
}
bool fts_expunge_log_contains(const struct fts_expunge_log_append_ctx *ctx,
			      const guid_128_t mailbox_guid, uint32_t uid)
{
	const struct fts_expunge_log_mailbox *mailbox;
	const uint8_t *guid_p = mailbox_guid;

	mailbox = hash_table_lookup(ctx->mailboxes, guid_p);
	if (mailbox == NULL)
		return FALSE;
	return seq_range_exists(&mailbox->uids, uid);	
}
int fts_expunge_log_append_remove(struct fts_expunge_log_append_ctx *from,
				   const struct fts_expunge_log_read_record *record)
{
	const uint8_t *guid_p = record->mailbox_guid;
	struct fts_expunge_log_mailbox *mailbox = hash_table_lookup(from->mailboxes, guid_p);
	if (mailbox == NULL)
		return 0; /* may only remove things that exist */

	mailbox->uids_count -= seq_range_array_remove_seq_range(&mailbox->uids, &record->uids);
	return 1;
}
int fts_expunge_log_subtract(struct fts_expunge_log_append_ctx *from,
			     struct fts_expunge_log *subtract)
{
	unsigned int failures = 0;
	struct fts_expunge_log_read_ctx *read_ctx = fts_expunge_log_read_begin(subtract);
	read_ctx->unlink = FALSE;

	const struct fts_expunge_log_read_record *record;
	while ((record = fts_expunge_log_read_next(read_ctx)) != NULL) {
		if (fts_expunge_log_append_remove(from, record) <= 0)
			failures++;
	}
	if (failures > 0)
		i_warning("fts: Expunge log subtract ignored %u nonexistent mailbox GUIDs",
			  failures);
	return fts_expunge_log_read_end(&read_ctx);
}
/* It could be argued that somehow adding a log (file) to the append context
   and then calling the _write() helper would be easier. But then there's the
   _commit() vs. _abort() cleanup that would need to be addressed. Just creating
   a copy is simpler. */
int fts_expunge_log_flat_write(const struct fts_expunge_log_append_ctx *read_log,
			       const char *path)
{
	int ret;
	struct fts_expunge_log *nlog = fts_expunge_log_init(path);
	struct fts_expunge_log_append_ctx *nappend = fts_expunge_log_append_begin(nlog);

	struct hash_iterate_context *iter;
	uint8_t *guid_p;
	struct fts_expunge_log_mailbox *mailbox;

	iter = hash_table_iterate_init(read_log->mailboxes);
	while (hash_table_iterate(iter, read_log->mailboxes, &guid_p, &mailbox))
		fts_expunge_log_append_mailbox_record(nappend, mailbox);

	hash_table_iterate_deinit(&iter);
	ret = fts_expunge_log_append_commit(&nappend);
	fts_expunge_log_deinit(&nlog);

	return ret;
}
