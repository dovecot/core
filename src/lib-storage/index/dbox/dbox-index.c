/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-dec.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "safe-mkstemp.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-index.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#define DBOX_INDEX_LOCK_RETRY_COUNT 10

struct dbox_index {
	struct dbox_mailbox *mbox;

	struct istream *input;
	char *path;
	int fd;

	uint32_t uid_validity, next_uid;
	unsigned int next_file_id;

	pool_t record_data_pool;
	ARRAY_DEFINE(records, struct dbox_index_record);
};

struct dbox_index_append_context {
	struct dbox_index *index;
	ARRAY_DEFINE(files, struct dbox_file *);

	uoff_t output_offset;
	unsigned int new_record_idx;
	unsigned int first_new_file_id;

	unsigned int locked_header:1;
};

static int dbox_index_recreate(struct dbox_index *index, bool locked);

struct dbox_index *dbox_index_init(struct dbox_mailbox *mbox)
{
	struct dbox_index *index;

	index = i_new(struct dbox_index, 1);
	index->mbox = mbox;
	index->path = i_strdup_printf("%s/"DBOX_INDEX_NAME, mbox->path);
	index->fd = -1;
	index->next_uid = 1;
	index->next_file_id = 1;
	i_array_init(&index->records, 128);
	index->record_data_pool =
		pool_alloconly_create("dbox index record data", 256);
	return index;
}

static void dbox_index_close(struct dbox_index *index)
{
	if (index->input != NULL)
		i_stream_unref(&index->input);
	if (index->fd != -1) {
		if (close(index->fd) < 0)
			i_error("close(%s) failed: %m", index->path);
		index->fd = -1;
	}
}

void dbox_index_deinit(struct dbox_index **_index)
{
	struct dbox_index *index = *_index;

	*_index = NULL;

	dbox_index_close(index);
	array_free(&index->records);
	pool_unref(&index->record_data_pool);
	i_free(index->path);
	i_free(index);
}

static int dbox_index_parse_maildir(struct dbox_index *index, const char *line,
				    struct dbox_index_record *rec)
{
	char *p;
	unsigned long uid;

	if (*line++ != ' ')
		return -1;

	uid = strtoul(line, &p, 10);
	if (*p++ != ' ' || *p == '\0' || uid == 0 || uid >= (uint32_t)-1)
		return -1;

	rec->data = p_strdup(index->record_data_pool, line);
	return 0;
}

static int dbox_index_parse_line(struct dbox_index *index, const char *line,
				 unsigned int offset)
{
	struct dbox_index_record rec;

	memset(&rec, 0, sizeof(rec));
	rec.file_offset = offset;

	/* <file id> <status><expunges><dirty> [<status-specific data>] */
	while (*line >= '0' && *line <= '9') {
		rec.file_id = rec.file_id*10 + *line - '0';
		line++;
	}
	if (*line++ != ' ')
		return -1;

	if ((rec.file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
		/* UID files shouldn't be listed in dbox.index */
		return -1;
	}

	if (line[0] == '\0' || line[1] == '\0' || line[2] == '\0')
		return -1;
	rec.status = line[0];
	rec.expunges = line[1] != '0';
	rec.dirty = line[2] != '0';

	line += 3;
	if (rec.status == DBOX_INDEX_FILE_STATUS_MAILDIR) {
		if (dbox_index_parse_maildir(index, line, &rec) < 0)
			return -1;
	}
	array_append(&index->records, &rec, 1);
	return 0;
}

static int
dbox_index_set_corrupted(struct dbox_index *index, const char *reason)
{
	mail_storage_set_critical(index->mbox->ibox.box.storage,
				  "dbox index %s corrupted: %s",
				  index->path, reason);

	if (unlink(index->path) < 0 && errno != ENOENT)
		i_error("unlink(%s) failed: %m", index->path);
	return -1;
}

static void dbox_index_header_init(struct dbox_index *index,
				   struct dbox_index_file_header *hdr)
{
	if (index->uid_validity == 0) {
		const struct mail_index_header *hdr;

		hdr = mail_index_get_header(index->mbox->ibox.view);
		index->uid_validity = hdr->uid_validity != 0 ?
			hdr->uid_validity : (uint32_t)ioloop_time;
	}

	memset(hdr, ' ', sizeof(*hdr));
	hdr->version = DBOX_INDEX_VERSION;
	dec2hex(hdr->uid_validity_hex, index->uid_validity,
		sizeof(hdr->uid_validity_hex));
	dec2hex(hdr->next_uid_hex, index->next_uid, sizeof(hdr->next_uid_hex));
	dec2hex(hdr->next_file_id_hex, index->next_file_id,
		sizeof(hdr->next_file_id_hex));
}

static int dbox_index_parse_header(struct dbox_index *index, const char *line)
{
	struct dbox_index_file_header hdr;

	if (strlen(line) < sizeof(hdr))
		return dbox_index_set_corrupted(index, "Header too short");

	memcpy(&hdr, line, sizeof(hdr));
	if (hdr.version != DBOX_INDEX_VERSION)
		return dbox_index_set_corrupted(index, "Invalid version");

	index->uid_validity =
		hex2dec(hdr.uid_validity_hex, sizeof(hdr.uid_validity_hex));
	if (index->uid_validity == 0)
		return dbox_index_set_corrupted(index, "uid_validity = 0");

	index->next_uid = hex2dec(hdr.next_uid_hex, sizeof(hdr.next_uid_hex));
	if (index->next_uid == 0)
		return dbox_index_set_corrupted(index, "next_uid = 0");
	index->next_file_id =
		hex2dec(hdr.next_file_id_hex, sizeof(hdr.next_file_id_hex));
	return 0;
}

static int dbox_index_read_header(struct dbox_index *index)
{
	const char *line;

	i_stream_sync(index->input);
	i_stream_seek(index->input, 0);

	line = i_stream_read_next_line(index->input);
	if (line == NULL)
		return dbox_index_set_corrupted(index, "Missing header");
	return dbox_index_parse_header(index, line);
}

static int dbox_index_read(struct dbox_index *index)
{
	struct istream *input;
	const char *line;
	uoff_t start_offset;
	int ret;

	if (index->fd != -1)
		dbox_index_close(index);

	index->fd = open(index->path, O_RDWR);
	if (index->fd == -1) {
		if (errno == ENOENT)
			return 0;
		mail_storage_set_critical(index->mbox->ibox.box.storage,
					  "open(%s) failed: %m", index->path);
		return -1;
	}

	p_clear(index->record_data_pool);
	array_clear(&index->records);
	input = index->input = i_stream_create_fd(index->fd, 1024, FALSE);

	ret = dbox_index_read_header(index);
	start_offset = input->v_offset;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (dbox_index_parse_line(index, line, start_offset) < 0) {
			dbox_index_set_corrupted(index, "Corrupted record");
			ret = -1;
			break;
		}
		start_offset = input->v_offset;
	}
	return ret == 0 ? 1 :
		(input->stream_errno == 0 ? 0 : -1);
}

static int dbox_index_read_or_create(struct dbox_index *index)
{
	unsigned int i;
	int ret;

	for (i = 0;; i++) {
		if ((ret = dbox_index_read(index)) != 0)
			return ret;

		/* doesn't exist / corrupted */
		if (i == DBOX_INDEX_LOCK_RETRY_COUNT)
			break;

		if (index->fd != -1)
			dbox_index_close(index);

		if (dbox_index_recreate(index, FALSE) < 0)
			return -1;
	}

	mail_storage_set_critical(index->mbox->ibox.box.storage,
		"dbox index recreation keeps failing: %s", index->path);
	return -1;
}

static int dbox_index_refresh(struct dbox_index *index)
{
	struct stat st1, st2;

	if (index->fd == -1) {
		if (dbox_index_read_or_create(index) < 0)
			return -1;
		i_assert(index->fd != -1);
		return 1;
	}

	if (fstat(index->fd, &st1) < 0) {
		mail_storage_set_critical(index->mbox->ibox.box.storage,
					  "fstat(%s) failed: %m", index->path);
		return -1;
	}
	if (stat(index->path, &st2) < 0) {
		mail_storage_set_critical(index->mbox->ibox.box.storage,
					  "stat(%s) failed: %m", index->path);
		return -1;
	}

	if (st1.st_ino != st2.st_ino || !CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		if (dbox_index_read(index) < 0)
			return -1;
		return 1;
	}
	return 0;
}

int dbox_index_get_uid_validity(struct dbox_index *index,
				uint32_t *uid_validity_r)
{
	if (index->fd == -1) {
		if (dbox_index_refresh(index) < 0)
			return -1;
	}
	*uid_validity_r = index->uid_validity;
	return 0;
}

static int dbox_index_record_cmp(const void *key, const void *data)
{
	const unsigned int *file_id = key;
	const struct dbox_index_record *rec = data;

	return *file_id - rec->file_id;
}

struct dbox_index_record *
dbox_index_record_lookup(struct dbox_index *index, unsigned int file_id)
{
	struct dbox_index_record *records;
	unsigned int count;

	if ((file_id & DBOX_FILE_ID_FLAG_UID) != 0)
		return NULL;

	if (index->fd == -1) {
		if (dbox_index_refresh(index) < 0)
			return NULL;
	}

	records = array_get_modifiable(&index->records, &count);
	return bsearch(&file_id, records, count, sizeof(*records),
		       dbox_index_record_cmp);
}

static int
dbox_index_lock_range(struct dbox_index *index, int cmd, int lock_type,
		      off_t start, off_t len)
{
	struct flock fl;

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = start;
	fl.l_len = len;
	if (fcntl(index->fd, cmd, &fl) < 0) {
		if ((errno == EACCES || errno == EAGAIN || errno == EINTR) &&
		    cmd == F_SETLK)
			return 0;
		mail_storage_set_critical(index->mbox->ibox.box.storage,
			"fcntl(%s, %s) failed: %m", index->path,
			lock_type == F_UNLCK ? "F_UNLCK" : "F_WRLCK");
		return -1;
	}
	return 1;
}

static void dbox_index_unlock_range(struct dbox_index *index,
				    off_t start, off_t len)
{
	(void)dbox_index_lock_range(index, F_SETLK, F_UNLCK, start, len);
}

static int
dbox_index_try_lock_once(struct dbox_index *index, unsigned int file_id,
			 enum dbox_index_file_lock_status *lock_status_r)
{
	struct dbox_index_record *rec;
	int ret;

	i_assert((file_id & DBOX_FILE_ID_FLAG_UID) == 0);

	rec = dbox_index_record_lookup(index, file_id);
	if (rec == NULL || rec->status == DBOX_INDEX_FILE_STATUS_UNLINKED) {
		*lock_status_r = DBOX_INDEX_FILE_LOCK_UNLINKED;
		return 0;
	}

	if (rec->status != DBOX_INDEX_FILE_STATUS_APPENDABLE) {
		*lock_status_r = DBOX_INDEX_FILE_LOCK_NOT_NEEDED;
		return 1;
	}

	/* we'll need to try to lock this record */
	ret = dbox_index_lock_range(index, F_SETLK, F_WRLCK,
				    rec->file_offset, 1);
	if (ret > 0) {
		*lock_status_r = DBOX_INDEX_FILE_LOCKED;
		rec->locked = TRUE;
	} else if (ret == 0)
		*lock_status_r = DBOX_INDEX_FILE_LOCK_TRY_AGAIN;
	return ret;
}

int dbox_index_try_lock_file(struct dbox_index *index, unsigned int file_id,
			     enum dbox_index_file_lock_status *lock_status_r)
{
	int i, ret;

	if ((file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
		*lock_status_r = DBOX_INDEX_FILE_LOCK_NOT_NEEDED;
		return 1;
	}

	if (index->fd == -1) {
		if (dbox_index_refresh(index) < 0)
			return 1;
	}

	for (i = 0; i < DBOX_INDEX_LOCK_RETRY_COUNT; i++) {
		ret = dbox_index_try_lock_once(index, file_id, lock_status_r);
		if (ret <= 0 || *lock_status_r != DBOX_INDEX_FILE_LOCKED)
			return ret;

		/* if file was recreated, reopen it and try again */
		if ((ret = dbox_index_refresh(index)) <= 0)
			return ret < 0 ? -1 : 1;
	}

	i_warning("dbox index keeps getting recreated: %s", index->path);
	return 0;
}

void dbox_index_unlock_file(struct dbox_index *index, unsigned int file_id)
{
	struct dbox_index_record *rec;

	rec = dbox_index_record_lookup(index, file_id);
	if (rec == NULL || !rec->locked)
		return;

	dbox_index_unlock_range(index, rec->file_offset, 1);
	rec->locked = FALSE;
}

int dbox_index_try_lock_recreate(struct dbox_index *index)
{
	int i, ret;

	if (index->fd == -1) {
		if (dbox_index_refresh(index) < 0)
			return 1;
	}

	for (i = 0; i < DBOX_INDEX_LOCK_RETRY_COUNT; i++) {
		/* lock the whole file */
		ret = dbox_index_lock_range(index, F_SETLK, F_WRLCK, 0, 0);
		if (ret <= 0)
			return ret;
		if ((ret = dbox_index_refresh(index)) <= 0)
			return ret < 0 ? -1 : 1;
	}

	i_warning("dbox index keeps getting recreated: %s", index->path);
	return 0;
}

static int dbox_index_lock_header(struct dbox_index *index)
{
	int i, ret;

	if (index->fd == -1) {
		if (dbox_index_refresh(index) < 0)
			return 1;
	}

	for (i = 0; i < DBOX_INDEX_LOCK_RETRY_COUNT; i++) {
		ret = dbox_index_lock_range(index, F_SETLKW, F_WRLCK, 0,
					sizeof(struct dbox_index_file_header));
		if (ret <= 0)
			return -1;

		/* if file was recreated, reopen it and try again */
		if ((ret = dbox_index_refresh(index)) <= 0)
			return ret < 0;
	}

	mail_storage_set_critical(index->mbox->ibox.box.storage,
		"dbox index keeps getting recreated: %s", index->path);
	return -1;
}

static void dbox_index_unlock_header(struct dbox_index *index)
{
	dbox_index_unlock_range(index, 0,
				sizeof(struct dbox_index_file_header));
}

static void
dbox_index_append_record(const struct dbox_index_record *rec, string_t *str)
{
	str_printfa(str, "%u %c%c%c",
		    rec->file_id, rec->status,
		    rec->expunges ? 'E' : '0',
		    rec->dirty ? 'D' : '0');

	switch (rec->status) {
	case DBOX_INDEX_FILE_STATUS_APPENDABLE:
		str_append(str, " 00000000");
		break;
	case DBOX_INDEX_FILE_STATUS_APPENDING:
	case DBOX_INDEX_FILE_STATUS_UNLINKED:
		i_unreached();
		break;
	case DBOX_INDEX_FILE_STATUS_NONAPPENDABLE:
	case DBOX_INDEX_FILE_STATUS_SINGLE_MESSAGE:
		break;
	case DBOX_INDEX_FILE_STATUS_MAILDIR:
		str_append_c(str, ' ');
		str_append(str, rec->data);
		break;
	}
	str_append_c(str, '\n');
}

static int dbox_index_recreate(struct dbox_index *index, bool locked)
{
	struct mail_storage *storage = &index->mbox->storage->storage;
	struct dbox_index_record *records;
	struct ostream *output;
	struct dbox_index_file_header hdr;
	string_t *temp_path, *str;
	unsigned int i, count;
	int fd, ret = 0;

	t_push();
	temp_path = t_str_new(256);
	str_append(temp_path, index->path);
	if (locked) {
		str_append(temp_path, ".tmp");
		fd = open(str_c(temp_path), O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd == -1) {
			mail_storage_set_critical(storage,
				"open(%s, O_CREAT) failed: %m",
				str_c(temp_path));
			t_pop();
			return -1;
		}
	} else {
		str_append_c(temp_path, '.');
		fd = safe_mkstemp_hostpid(temp_path, 0600,
					  (uid_t)-1, (gid_t)-1);
		if (fd == -1) {
			mail_storage_set_critical(storage,
				"safe_mkstemp_hostpid(%s) failed: %m",
				str_c(temp_path));
			t_pop();
			return -1;
		}
	}

	str = t_str_new(256);
	output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(output);

	dbox_index_header_init(index, &hdr);
	o_stream_send(output, &hdr, sizeof(hdr));
	o_stream_send(output, "\n", 1);

	records = array_get_modifiable(&index->records, &count);
	for (i = 0; i < count; ) {
		if (records[i].status == DBOX_INDEX_FILE_STATUS_UNLINKED) {
			array_delete(&index->records, i, 1);
			records = array_get_modifiable(&index->records, &count);
		} else {
			records[i].file_offset = output->offset;
			str_truncate(str, 0);
			dbox_index_append_record(&records[i], str);
			o_stream_send(output, str_data(str), str_len(str));
			i++;
		}
	}

	if (o_stream_flush(output) < 0) {
		mail_storage_set_critical(storage,
			"write(%s) failed: %m", str_c(temp_path));
		ret = -1;
	}

	o_stream_destroy(&output);
	if (ret == 0 && index->mbox->ibox.fsync_disable) {
		if (fdatasync(fd) < 0) {
			mail_storage_set_critical(storage,
				"fdatasync(%s) failed: %m", str_c(temp_path));
			ret = -1;
		}
	}
	if (close(fd) < 0) {
		mail_storage_set_critical(storage,
			"close(%s) failed: %m", str_c(temp_path));
		ret = -1;
	}
	if (ret == 0) {
		if (locked) {
			if (rename(str_c(temp_path), index->path) < 0) {
				mail_storage_set_critical(storage,
					"rename(%s, %s) failed: %m",
					str_c(temp_path), index->path);
				ret = -1;
			}
		} else {
			if (link(str_c(temp_path), index->path) < 0 &&
			    errno != EEXIST) {
				mail_storage_set_critical(storage,
					"link(%s, %s) failed: %m",
					str_c(temp_path), index->path);
				ret = -1;
			}
		}
	}
	if (ret < 0 || !locked) {
		if (unlink(str_c(temp_path)) < 0)
			i_error("unlink(%s) failed: %m", str_c(temp_path));
	}
	t_pop();
	return ret;
}

struct dbox_index_append_context *
dbox_index_append_begin(struct dbox_index *index)
{
	struct dbox_index_append_context *ctx;
	const void *data;
	bool expunged;

	ctx = i_new(struct dbox_index_append_context, 1);
	ctx->index = index;
	ctx->first_new_file_id = (unsigned int)-1;
	i_array_init(&ctx->files, 64);

	/* refresh the index now if there's a possibility of some appendable
	   files existing */
	if (mail_index_view_get_messages_count(index->mbox->ibox.view) > 0) {
		mail_index_lookup_ext(index->mbox->ibox.view, 1,
				      index->mbox->dbox_ext_id,
				      &data, &expunged);
		if (data != NULL)
			(void)dbox_index_refresh(index);
	}
	return ctx;
}

static bool
dbox_index_append_file_record(struct dbox_index_append_context *ctx,
			      struct dbox_index_record *record,
			      uoff_t mail_size, struct dbox_file **file_r,
			      struct ostream **output_r)
{
	struct dbox_file *const *files, *file;
	enum dbox_index_file_lock_status lock_status;
	unsigned int i, count;

	if (record->status != DBOX_INDEX_FILE_STATUS_APPENDABLE)
		return FALSE;

	if (record->expunges)
		return FALSE;

	/* if we already have it in our files list, we already checked that
	   we can't append to it. */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id == record->file_id)
			return FALSE;
	}
	i_assert(!record->locked);

	if (dbox_index_try_lock_file(ctx->index, record->file_id,
				     &lock_status) <= 0)
		return FALSE;

	/* open the file to see if we can append */
	file = dbox_file_init(ctx->index->mbox, record->file_id);
	if (dbox_file_get_append_stream(file, mail_size, output_r) <= 0) {
		dbox_index_unlock_file(ctx->index, record->file_id);
		dbox_file_unref(&file);
		return FALSE;
	}
	*file_r = file;
	return TRUE;
}

int dbox_index_append_next(struct dbox_index_append_context *ctx,
			   uoff_t mail_size,
			   struct dbox_file **file_r,
			   struct ostream **output_r)
{
	struct dbox_file *const *files, *file = NULL;
	struct dbox_index_record *records;
	unsigned int i, count;
	int ret;

	/* first try to use files already used in this append */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (dbox_file_get_append_stream(files[i], mail_size,
						output_r) > 0) {
			*file_r = files[i];
			return 0;
		}
	}

	/* try to find an existing appendable file */
	records = array_get_modifiable(&ctx->index->records, &count);
	for (i = 0; i < count; i++) {
		if (dbox_index_append_file_record(ctx, &records[i], mail_size,
						  &file, output_r))
			break;
	}

	if (file == NULL) {
		/* create a new file */
		file = dbox_file_init(ctx->index->mbox, 0);
		if ((ret = dbox_file_get_append_stream(file, mail_size,
						       output_r)) <= 0) {
			i_assert(ret < 0);
			(void)unlink(dbox_file_get_path(file));
			dbox_file_unref(&file);
			return -1;
		}
	}

	*file_r = file;
	array_append(&ctx->files, &file, 1);
	return 0;
}

void dbox_index_append_file(struct dbox_index_append_context *ctx,
			    struct dbox_file *file)
{
	file->refcount++;
	array_append(&ctx->files, &file, 1);
}

static int dbox_index_append_commit_new(struct dbox_index_append_context *ctx,
					struct dbox_file *file, string_t *str)
{
	struct mail_storage *storage = &ctx->index->mbox->storage->storage;
	struct dbox_index_record rec;
	struct stat st;
	unsigned int file_id;

	i_assert(file->append_count > 0);

	if (file->append_count == 1 && !file->maildir_file &&
	    !dbox_file_can_append(file, 0)) {
		/* single UID message file */
		i_assert(file->last_append_uid != 0);
		file_id = file->last_append_uid | DBOX_FILE_ID_FLAG_UID;
		return dbox_file_assign_id(file, file_id);
	}

	if (!ctx->locked_header) {
		if (dbox_index_lock_header(ctx->index) < 0)
			return -1;
		if (dbox_index_read_header(ctx->index) < 0) {
			dbox_index_unlock_header(ctx->index);
			return -1;
		}
		if (fstat(ctx->index->fd, &st) < 0) {
			mail_storage_set_critical(storage,
				"fstat(%s) failed: %m", ctx->index->path);
			dbox_index_unlock_header(ctx->index);
			return -1;
		}
		ctx->output_offset = st.st_size;
		ctx->new_record_idx = array_count(&ctx->index->records);
		ctx->first_new_file_id = ctx->index->next_file_id;
		ctx->locked_header = TRUE;
	}

	file_id = ctx->index->next_file_id++;
	if (dbox_file_assign_id(file, file_id) < 0)
		return -1;

	memset(&rec, 0, sizeof(rec));
	rec.file_id = file_id;
	rec.file_offset = ctx->output_offset + str_len(str);
	if (file->maildir_file) {
		rec.status = DBOX_INDEX_FILE_STATUS_MAILDIR;
		rec.data = p_strdup_printf(ctx->index->record_data_pool,
					   "%u %s", file->last_append_uid,
					   file->fname);

	} else {
		rec.status = dbox_file_can_append(file, 0) ?
			DBOX_INDEX_FILE_STATUS_APPENDABLE :
			DBOX_INDEX_FILE_STATUS_NONAPPENDABLE;
	}

	array_append(&ctx->index->records, &rec, 1);
	dbox_index_append_record(&rec, str);
	return 0;
}

static void
dbox_index_append_rollback_commit(struct dbox_index_append_context *ctx)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id >= ctx->first_new_file_id) {
			if (unlink(dbox_file_get_path(files[i])) < 0) {
				i_error("unlink(%s) failed: %m",
					dbox_file_get_path(files[i]));
			}
			files[i]->deleted = TRUE;
		} else {
			/* FIXME: we should delete the appended mails.. */
		}
	}
	array_delete(&ctx->index->records, ctx->new_record_idx,
		     array_count(&ctx->index->records) - ctx->new_record_idx);
}

static int
dbox_index_append_write_records(struct dbox_index_append_context *ctx,
				string_t *str)
{
	int ret;

	ret = dbox_index_lock_range(ctx->index, F_SETLKW, F_WRLCK,
				    ctx->output_offset, str_len(str));
	if (ret <= 0)
		return -1;

	if (pwrite_full(ctx->index->fd, str_data(str), str_len(str),
			ctx->output_offset) < 0) {
		mail_storage_set_critical(&ctx->index->mbox->storage->storage,
			"pwrite(%s) failed: %m", ctx->index->path);
		if (ftruncate(ctx->index->fd, ctx->output_offset) < 0)
			i_error("ftruncate(%s) failed: %m", ctx->index->path);
		ret = -1;
	}
	dbox_index_unlock_range(ctx->index, ctx->output_offset, str_len(str));
	return ret < 0 ? -1 : 0;
}

static int dbox_index_write_header(struct dbox_index *index)
{
	struct dbox_index_file_header hdr;

	dbox_index_header_init(index, &hdr);
	if (pwrite_full(index->fd, &hdr, sizeof(hdr), 0) < 0) {
		mail_storage_set_critical(&index->mbox->storage->storage,
			"pwrite(%s) failed: %m", index->path);
		return -1;
	}
	return 0;
}

int dbox_index_append_assign_file_ids(struct dbox_index_append_context *ctx)
{
	struct dbox_file *const *files, *file;
	string_t *str;
	unsigned int i, count;
	int ret = 0;

	str = str_new(default_pool, 1024);
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		file = files[i];

		if (file->file_id == 0) {
			t_push();
			if (dbox_index_append_commit_new(ctx, file, str) < 0)
				ret = -1;
			t_pop();
		}
	}

	if (ret == 0 && str_len(str) > 0) {
		/* write the new records to index */
		ret = dbox_index_append_write_records(ctx, str);
	}
	if (ret < 0 && str_len(str) > 0) {
		/* we have to rollback changes we made */
		dbox_index_append_rollback_commit(ctx);
	}
	str_free(&str);
	return ret;
}

int dbox_index_append_commit(struct dbox_index_append_context **_ctx)
{
	struct dbox_index_append_context *ctx = *_ctx;
	struct dbox_file **files;
	unsigned int i, count;
	int ret = 0;

	*_ctx = NULL;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id < ctx->first_new_file_id) {
			/* FIXME: update status */
			dbox_index_unlock_file(ctx->index, files[i]->file_id);
		}
		dbox_file_unref(&files[i]);
	}

	if (ctx->locked_header) {
		if (dbox_index_write_header(ctx->index) < 0)
			ret = -1;
		dbox_index_unlock_header(ctx->index);
	}

	array_free(&ctx->files);
	i_free(ctx);
	return 0;
}

void dbox_index_append_rollback(struct dbox_index_append_context **_ctx)
{
	struct dbox_index_append_context *ctx = *_ctx;
	struct dbox_file *const *files, *file;
	unsigned int i, count;

	*_ctx = NULL;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		file = files[i];

		if (file->file_id != 0)
			dbox_index_unlock_file(ctx->index, file->file_id);
		else {
			if (unlink(dbox_file_get_path(file)) < 0) {
				i_error("unlink(%s) failed: %m",
					dbox_file_get_path(file));
			}
		}
		dbox_file_unref(&file);
	}
	array_free(&ctx->files);
	i_free(ctx);
}
