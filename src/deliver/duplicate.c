/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "home-expand.h"
#include "file-dotlock.h"
#include "hash.h"
#include "duplicate.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define DUPLICATE_PATH "~/.dovecot.lda-dupes"
#define COMPRESS_PERCENTAGE 10
#define DUPLICATE_BUFSIZE 4096
#define DUPLICATE_VERSION 2

struct duplicate {
	const void *id;
	unsigned int id_size;

	const char *user;
	time_t time;
};

struct duplicate_file_header {
	uint32_t version;
};

struct duplicate_record_header {
	uint32_t stamp;
	uint32_t id_size;
	uint32_t user_size;
};

struct duplicate_file {
	pool_t pool;
	struct hash_table *hash;
	const char *path;

	int new_fd;
	struct dotlock *dotlock;
	unsigned int changed:1;
};

static struct dotlock_settings duplicate_dotlock_set = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 20,
	MEMBER(stale_timeout) 10,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};
static struct duplicate_file *duplicate_file = NULL;

static int duplicate_cmp(const void *p1, const void *p2)
{
	const struct duplicate *d1 = p1, *d2 = p2;

	return (d1->id_size == d2->id_size &&
		memcmp(d1->id, d2->id, d1->id_size) == 0 &&
		strcasecmp(d1->user, d2->user) == 0) ? 0 : 1;
}

static unsigned int duplicate_hash(const void *p)
{
	/* a char* hash function from ASU -- from glib */
	const struct duplicate *d = p;
        const unsigned char *s = d->id, *end = s + d->id_size;
	unsigned int g, h = 0;

	while (s != end) {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h ^ strcase_hash(d->user);
}

static int
duplicate_read_records(struct duplicate_file *file, struct istream *input,
		       unsigned int record_size)
{
	const unsigned char *data;
	struct duplicate_record_header hdr;
	size_t size;
	unsigned int change_count;

	change_count = 0;
	while (i_stream_read_data(input, &data, &size, record_size) > 0) {
		if (record_size == sizeof(hdr))
			memcpy(&hdr, data, sizeof(hdr));
		else {
			/* FIXME: backwards compatibility with v1.0 */
			time_t stamp;

			i_assert(record_size ==
				 sizeof(time_t) + sizeof(uint32_t)*2);
			memcpy(&stamp, data, sizeof(stamp));
			hdr.stamp = stamp;
			memcpy(&hdr.id_size, data + sizeof(time_t),
			       sizeof(hdr.id_size));
			memcpy(&hdr.user_size,
			       data + sizeof(time_t) + sizeof(uint32_t),
			       sizeof(hdr.user_size));
		}
		i_stream_skip(input, record_size);

		if (hdr.id_size == 0 || hdr.user_size == 0 ||
		    hdr.id_size > DUPLICATE_BUFSIZE ||
		    hdr.user_size > DUPLICATE_BUFSIZE) {
			i_error("broken duplicate file %s", file->path);
			return -1;
		}

		if (i_stream_read_data(input, &data, &size,
				       hdr.id_size + hdr.user_size - 1) <= 0) {
			i_error("unexpected end of file in %s", file->path);
			return -1;
		}

		if ((time_t)hdr.stamp >= ioloop_time) {
			/* still valid, save it */
			struct duplicate *d;
			void *new_id;

			new_id = p_malloc(file->pool, hdr.id_size);
			memcpy(new_id, data, hdr.id_size);

			d = p_new(file->pool, struct duplicate, 1);
			d->id = new_id;
			d->id_size = hdr.id_size;
			d->user = p_strndup(file->pool,
					    data + hdr.id_size, hdr.user_size);
			d->time = hdr.stamp;
			hash_table_insert(file->hash, d, d);
		} else {
                        change_count++;
		}
		i_stream_skip(input, hdr.id_size + hdr.user_size);
	}

	if (hash_table_count(file->hash) *
	    COMPRESS_PERCENTAGE / 100 > change_count)
		file->changed = TRUE;
	return 0;
}

static int duplicate_read(struct duplicate_file *file)
{
	struct istream *input;
	struct duplicate_file_header hdr;
	const unsigned char *data;
	size_t size;
	int fd;
	unsigned int record_size = 0;

	fd = open(file->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		i_error("open(%s) failed: %m", file->path);
		return -1;
	}

	/* <timestamp> <id_size> <user_size> <id> <user> */
	input = i_stream_create_fd(fd, DUPLICATE_BUFSIZE, FALSE);
	if (i_stream_read_data(input, &data, &size, sizeof(hdr)) > 0) {
		memcpy(&hdr, data, sizeof(hdr));
		if (hdr.version == 0 || hdr.version > DUPLICATE_VERSION + 10) {
			/* FIXME: backwards compatibility with v1.0 */
			record_size = sizeof(time_t) + sizeof(uint32_t)*2;
		} else if (hdr.version == DUPLICATE_VERSION) {
			record_size = sizeof(struct duplicate_record_header);
			i_stream_skip(input, sizeof(hdr));
		}
	}

	if (record_size == 0 ||
	    duplicate_read_records(file, input, record_size) < 0) {
		if (unlink(file->path) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", file->path);
	}

	i_stream_unref(&input);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", file->path);
	return 0;
}

static struct duplicate_file *duplicate_new(const char *path)
{
	struct duplicate_file *file;
	pool_t pool;

	pool = pool_alloconly_create("duplicates", 10240);

	file = p_new(pool, struct duplicate_file, 1);
	file->pool = pool;
	file->path = p_strdup(pool, path);
	file->new_fd = file_dotlock_open(&duplicate_dotlock_set, path, 0,
					 &file->dotlock);
	if (file->new_fd == -1)
		i_error("file_dotlock_create(%s) failed: %m", path);
	file->hash = hash_table_create(default_pool, pool, 0,
				       duplicate_hash, duplicate_cmp);
	(void)duplicate_read(file);
	return file;
}

static void duplicate_free(struct duplicate_file **_file)
{
	struct duplicate_file *file = *_file;

	*_file = NULL;
	if (file->dotlock != NULL)
		file_dotlock_delete(&file->dotlock);

	hash_table_destroy(&file->hash);
	pool_unref(&file->pool);
}

int duplicate_check(const void *id, size_t id_size, const char *user)
{
	struct duplicate d;

	if (duplicate_file == NULL)
		duplicate_file = duplicate_new(home_expand(DUPLICATE_PATH));

	d.id = id;
	d.id_size = id_size;
	d.user = user;

	return hash_table_lookup(duplicate_file->hash, &d) != NULL;
}

void duplicate_mark(const void *id, size_t id_size,
                    const char *user, time_t timestamp)
{
	struct duplicate *d;
	void *new_id;

	if (duplicate_file == NULL)
		duplicate_file = duplicate_new(home_expand(DUPLICATE_PATH));

	new_id = p_malloc(duplicate_file->pool, id_size);
	memcpy(new_id, id, id_size);

	d = p_new(duplicate_file->pool, struct duplicate, 1);
	d->id = new_id;
	d->id_size = id_size;
	d->user = p_strdup(duplicate_file->pool, user);
	d->time = timestamp;

	duplicate_file->changed = TRUE;
	hash_table_insert(duplicate_file->hash, d, d);
}

void duplicate_flush(void)
{
	struct duplicate_file *file = duplicate_file;
	struct duplicate_file_header hdr;
	struct duplicate_record_header rec;
	struct ostream *output;
        struct hash_iterate_context *iter;
	void *key, *value;

	if (duplicate_file == NULL || !file->changed || file->new_fd == -1)
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = DUPLICATE_VERSION;

	output = o_stream_create_fd_file(file->new_fd, 0, FALSE);
	o_stream_send(output, &hdr, sizeof(hdr));

	memset(&rec, 0, sizeof(rec));
	iter = hash_table_iterate_init(file->hash);
	while (hash_table_iterate(iter, &key, &value)) {
		struct duplicate *d = value;

		rec.stamp = d->time;
		rec.id_size = d->id_size;
		rec.user_size = strlen(d->user);

		o_stream_send(output, &rec, sizeof(rec));
		o_stream_send(output, d->id, rec.id_size);
		o_stream_send(output, d->user, rec.user_size);
	}
	hash_table_iterate_deinit(&iter);
	o_stream_unref(&output);

	file->changed = FALSE;
	if (file_dotlock_replace(&file->dotlock, 0) < 0)
		i_error("file_dotlock_replace(%s) failed: %m", file->path);
	file->new_fd = -1;
}

void duplicate_init(void)
{
	duplicate_dotlock_set.use_excl_lock =
		getenv("DOTLOCK_USE_EXCL") != NULL;
	duplicate_dotlock_set.nfs_flush =
		getenv("MAIL_NFS_STORAGE") != NULL;
}

void duplicate_deinit(void)
{
	if (duplicate_file != NULL) {
		duplicate_flush();
		duplicate_free(&duplicate_file);
	}
}
