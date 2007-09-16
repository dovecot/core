/* Copyright (C) 2005-2006 Timo Sirainen */

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

struct duplicate {
	const void *id;
	unsigned int id_size;

	const char *user;
	time_t time;
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

	MEMBER(timeout) 10,
	MEMBER(stale_timeout) 60,

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

static int duplicate_read(struct duplicate_file *file)
{
	int fd;
	struct istream *input;
	const unsigned char *data;
	size_t size;
	time_t stamp;
	unsigned int offset, id_size, user_size, change_count;
	bool broken = FALSE;

	fd = open(file->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		i_error("open(%s) failed: %m", file->path);
		return -1;
	}

	/* <timestamp> <id_size> <user_size> <id> <user> */
	input = i_stream_create_fd(fd, DUPLICATE_BUFSIZE, FALSE);

	change_count = 0;
	while (i_stream_read_data(input, &data, &size, sizeof(stamp) +
				  sizeof(id_size) + sizeof(user_size)) > 0) {
		offset = 0;
		memcpy(&stamp, data, sizeof(stamp));
		offset += sizeof(stamp);
		memcpy(&id_size, data + offset, sizeof(id_size));
		offset += sizeof(id_size);
		memcpy(&user_size, data + offset, sizeof(user_size));
		offset += sizeof(user_size);

		i_stream_skip(input, offset);

		if (id_size == 0 || user_size == 0 ||
		    id_size > DUPLICATE_BUFSIZE ||
		    user_size > DUPLICATE_BUFSIZE) {
			i_error("broken duplicate file %s", file->path);
			broken = TRUE;
			break;
		}

		if (i_stream_read_data(input, &data, &size,
				       id_size + user_size - 1) <= 0) {
			i_error("unexpected end of file in %s", file->path);
			broken = TRUE;
			break;
		}

		if (stamp >= ioloop_time) {
			/* still valid, save it */
			struct duplicate *d;
			void *new_id;

			new_id = p_malloc(file->pool, id_size);
			memcpy(new_id, data, id_size);

			d = p_new(file->pool, struct duplicate, 1);
			d->id = new_id;
			d->id_size = id_size;
			d->user = p_strndup(file->pool,
					    data + id_size, user_size);
			d->time = stamp;
			hash_insert(file->hash, d, d);
		} else {
                        change_count++;
		}
		i_stream_skip(input, id_size + user_size);
	}

	if (hash_size(file->hash) * COMPRESS_PERCENTAGE / 100 > change_count)
		file->changed = TRUE;

	i_stream_unref(&input);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", file->path);
	if (broken) {
		if (unlink(file->path) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", file->path);
	}
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
	file->hash = hash_create(default_pool, pool, 0,
				 duplicate_hash, duplicate_cmp);
	(void)duplicate_read(file);
	return file;
}

static void duplicate_free(struct duplicate_file *file)
{
	if (file->dotlock != NULL)
		file_dotlock_delete(&file->dotlock);

	hash_destroy(&file->hash);
	pool_unref(file->pool);
}

int duplicate_check(const void *id, size_t id_size, const char *user)
{
	struct duplicate d;

	if (duplicate_file == NULL)
		duplicate_file = duplicate_new(home_expand(DUPLICATE_PATH));

	d.id = id;
	d.id_size = id_size;
	d.user = user;

	return hash_lookup(duplicate_file->hash, &d) != NULL;
}

void duplicate_mark(const void *id, size_t id_size,
                    const char *user, time_t time)
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
	d->time = time;

	duplicate_file->changed = TRUE;
	hash_insert(duplicate_file->hash, d, d);
}

void duplicate_flush(void)
{
	struct duplicate_file *file = duplicate_file;
	struct ostream *output;
        struct hash_iterate_context *iter;
	void *key, *value;

	if (duplicate_file == NULL || !file->changed || file->new_fd == -1)
		return;

	output = o_stream_create_fd_file(file->new_fd, 0, FALSE);
	iter = hash_iterate_init(file->hash);
	while (hash_iterate(iter, &key, &value)) {
		struct duplicate *d = value;
		unsigned int user_size = strlen(d->user);

		o_stream_send(output, &d->time, sizeof(d->time));
		o_stream_send(output, &d->id_size, sizeof(d->id_size));
		o_stream_send(output, &user_size, sizeof(user_size));
		o_stream_send(output, d->id, d->id_size);
		o_stream_send(output, d->user, user_size);
	}
	hash_iterate_deinit(&iter);
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
}

void duplicate_deinit(void)
{
	if (duplicate_file != NULL) {
		duplicate_flush();
		duplicate_free(duplicate_file);
	}
}
