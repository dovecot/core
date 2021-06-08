/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "home-expand.h"
#include "file-dotlock.h"
#include "hash.h"
#include "mail-user.h"
#include "mail-storage-settings.h"
#include "mail-duplicate.h"

#include <fcntl.h>
#include <unistd.h>

#define COMPRESS_PERCENTAGE 10
#define DUPLICATE_BUFSIZE 4096
#define DUPLICATE_VERSION 2

struct mail_duplicate {
	const void *id;
	unsigned int id_size;

	const char *user;
	time_t time;
};

struct mail_duplicate_file_header {
	uint32_t version;
};

struct mail_duplicate_record_header {
	uint32_t stamp;
	uint32_t id_size;
	uint32_t user_size;
};

struct mail_duplicate_transaction {
	pool_t pool;
	struct mail_duplicate_db *db;

	HASH_TABLE(struct mail_duplicate *, struct mail_duplicate *) hash;
	const char *path;

	int new_fd;
	struct dotlock *dotlock;
	bool changed:1;
};

struct mail_duplicate_db {
	struct mail_user *user;
	char *path;
	struct dotlock_settings dotlock_set;

	unsigned int transaction_count;
};

static const struct dotlock_settings default_mail_duplicate_dotlock_set = {
	.timeout = 20,
	.stale_timeout = 10,
};

static int
mail_duplicate_cmp(const struct mail_duplicate *d1,
		   const struct mail_duplicate *d2)
{
	return (d1->id_size == d2->id_size &&
		memcmp(d1->id, d2->id, d1->id_size) == 0 &&
		strcasecmp(d1->user, d2->user) == 0) ? 0 : 1;
}

static unsigned int mail_duplicate_hash(const struct mail_duplicate *d)
{
	/* a char* hash function from ASU -- from glib */
        const unsigned char *s = d->id, *end = s + d->id_size;
	unsigned int g, h = 0;

	while (s != end) {
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL) != 0) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h ^ strcase_hash(d->user);
}

static int
mail_duplicate_read_records(struct mail_duplicate_transaction *trans,
			    struct istream *input,
			    unsigned int record_size)
{
	const unsigned char *data;
	struct mail_duplicate_record_header hdr;
	size_t size;
	unsigned int change_count;

	change_count = 0;
	while (i_stream_read_bytes(input, &data, &size, record_size) > 0) {
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
			e_error(trans->db->user->event,
				"broken mail_duplicate file %s", trans->path);
			return -1;
		}

		if (i_stream_read_bytes(input, &data, &size,
					hdr.id_size + hdr.user_size) <= 0) {
			e_error(trans->db->user->event,
				"unexpected end of file in %s", trans->path);
			return -1;
		}

		if ((time_t)hdr.stamp >= ioloop_time) {
			/* still valid, save it */
			struct mail_duplicate *d;
			void *new_id;

			new_id = p_malloc(trans->pool, hdr.id_size);
			memcpy(new_id, data, hdr.id_size);

			d = p_new(trans->pool, struct mail_duplicate, 1);
			d->id = new_id;
			d->id_size = hdr.id_size;
			d->user = p_strndup(trans->pool,
					    data + hdr.id_size, hdr.user_size);
			d->time = hdr.stamp;
			hash_table_update(trans->hash, d, d);
		} else {
                        change_count++;
		}
		i_stream_skip(input, hdr.id_size + hdr.user_size);
	}

	if (hash_table_count(trans->hash) *
	    COMPRESS_PERCENTAGE / 100 > change_count)
		trans->changed = TRUE;
	return 0;
}

static int mail_duplicate_read(struct mail_duplicate_transaction *trans)
{
	struct istream *input;
	struct mail_duplicate_file_header hdr;
	const unsigned char *data;
	size_t size;
	int fd;
	unsigned int record_size = 0;

	fd = open(trans->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		e_error(trans->db->user->event,
			"open(%s) failed: %m", trans->path);
		return -1;
	}

	/* <timestamp> <id_size> <user_size> <id> <user> */
	input = i_stream_create_fd(fd, DUPLICATE_BUFSIZE);
	if (i_stream_read_bytes(input, &data, &size, sizeof(hdr)) > 0) {
		memcpy(&hdr, data, sizeof(hdr));
		if (hdr.version == 0 || hdr.version > DUPLICATE_VERSION + 10) {
			/* FIXME: backwards compatibility with v1.0 */
			record_size = sizeof(time_t) + sizeof(uint32_t)*2;
		} else if (hdr.version == DUPLICATE_VERSION) {
			record_size = sizeof(struct mail_duplicate_record_header);
			i_stream_skip(input, sizeof(hdr));
		}
	}

	if (record_size == 0 ||
	    mail_duplicate_read_records(trans, input, record_size) < 0)
		i_unlink_if_exists(trans->path);

	i_stream_unref(&input);
	if (close(fd) < 0) {
		e_error(trans->db->user->event,
			"close(%s) failed: %m", trans->path);
	}
	return 0;
}

struct mail_duplicate_transaction *
mail_duplicate_transaction_begin(struct mail_duplicate_db *db)
{
	struct mail_duplicate_transaction *trans;
	pool_t pool;

	db->transaction_count++;

	pool = pool_alloconly_create("mail_duplicates", 10240);

	trans = p_new(pool, struct mail_duplicate_transaction, 1);
	trans->pool = pool;
	trans->db = db
;
	if (db->path == NULL) {
		/* Duplicate database disabled; return dummy transaction */
		return trans;
	}

	trans->path = p_strdup(pool, db->path);
	trans->new_fd = file_dotlock_open(&db->dotlock_set, trans->path, 0,
					 &trans->dotlock);
	if (trans->new_fd != -1)
		;
	else if (errno != EAGAIN) {
		e_error(db->user->event,
			"file_dotlock_open(%s) failed: %m", trans->path);
	} else {
		e_error(db->user->event,
			"Creating lock file for %s timed out in %u secs",
			trans->path, db->dotlock_set.timeout);
	}
	hash_table_create(&trans->hash, pool, 0,
			  mail_duplicate_hash, mail_duplicate_cmp);

	(void)mail_duplicate_read(trans);
	return trans;
}

static void
mail_duplicate_transaction_free(struct mail_duplicate_transaction **_trans)
{
	struct mail_duplicate_transaction *trans = *_trans;

	if (trans == NULL)
		return;
	*_trans = NULL;

	i_assert(trans->db->transaction_count > 0);
	trans->db->transaction_count--;

	if (trans->dotlock != NULL)
		file_dotlock_delete(&trans->dotlock);

	hash_table_destroy(&trans->hash);
	pool_unref(&trans->pool);
}

enum mail_duplicate_check_result
mail_duplicate_check(struct mail_duplicate_transaction *trans,
		     const void *id, size_t id_size, const char *user)
{
	struct mail_duplicate d;

	if (trans->path == NULL) {
		/* Duplicate database disabled */
		return MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND;
	}

	d.id = id;
	d.id_size = id_size;
	d.user = user;

	if (hash_table_lookup(trans->hash, &d) != NULL)
		return MAIL_DUPLICATE_CHECK_RESULT_EXISTS;

	return MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND;
}

void mail_duplicate_mark(struct mail_duplicate_transaction *trans,
			 const void *id, size_t id_size,
			 const char *user, time_t timestamp)
{
	struct mail_duplicate *d;
	void *new_id;

	if (trans->path == NULL) {
		/* Duplicate database disabled */
		return;
	}

	new_id = p_malloc(trans->pool, id_size);
	memcpy(new_id, id, id_size);

	d = p_new(trans->pool, struct mail_duplicate, 1);
	d->id = new_id;
	d->id_size = id_size;
	d->user = p_strdup(trans->pool, user);
	d->time = timestamp;

	trans->changed = TRUE;
	hash_table_update(trans->hash, d, d);
}

void mail_duplicate_transaction_commit(
	struct mail_duplicate_transaction **_trans)
{
	struct mail_duplicate_transaction *trans = *_trans;
	struct mail_duplicate_file_header hdr;
	struct mail_duplicate_record_header rec;
	struct ostream *output;
        struct hash_iterate_context *iter;
	struct mail_duplicate *d;

	if (trans == NULL)
		return;
	*_trans = NULL;

	if (!trans->changed || trans->new_fd == -1) {
		mail_duplicate_transaction_free(&trans);
		return;
	}

	i_assert(trans->path != NULL);

	i_zero(&hdr);
	hdr.version = DUPLICATE_VERSION;

	output = o_stream_create_fd_file(trans->new_fd, 0, FALSE);
	o_stream_cork(output);
	o_stream_nsend(output, &hdr, sizeof(hdr));

	i_zero(&rec);
	iter = hash_table_iterate_init(trans->hash);
	while (hash_table_iterate(iter, trans->hash, &d, &d)) {
		rec.stamp = d->time;
		rec.id_size = d->id_size;
		rec.user_size = strlen(d->user);

		o_stream_nsend(output, &rec, sizeof(rec));
		o_stream_nsend(output, d->id, rec.id_size);
		o_stream_nsend(output, d->user, rec.user_size);
	}
	hash_table_iterate_deinit(&iter);

	if (o_stream_finish(output) < 0) {
		e_error(trans->db->user->event, "write(%s) failed: %s",
			trans->path, o_stream_get_error(output));
		o_stream_unref(&output);
		mail_duplicate_transaction_free(&trans);
		return;
	}
	o_stream_unref(&output);

	if (file_dotlock_replace(&trans->dotlock, 0) < 0) {
		e_error(trans->db->user->event,
			"file_dotlock_replace(%s) failed: %m", trans->path);
	}
	mail_duplicate_transaction_free(&trans);
}

void mail_duplicate_transaction_rollback(
	struct mail_duplicate_transaction **_trans)
{
	mail_duplicate_transaction_free(_trans);
}

struct mail_duplicate_db *
mail_duplicate_db_init(struct mail_user *user, const char *name)
{
	struct mail_duplicate_db *db;
	const struct mail_storage_settings *mail_set;
	const char *home = NULL;

	if (mail_user_get_home(user, &home) <= 0) {
		e_error(user->event, "User %s doesn't have home dir set, "
			"disabling duplicate database", user->username);
	}

	db = i_new(struct mail_duplicate_db, 1);
	db->user = user;
	db->path = home == NULL ? NULL :
		i_strconcat(home, "/.dovecot.", name, NULL);
	db->dotlock_set = default_mail_duplicate_dotlock_set;

	mail_set = mail_user_set_get_storage_set(user);
	db->dotlock_set.use_excl_lock = mail_set->dotlock_use_excl;
	db->dotlock_set.nfs_flush = mail_set->mail_nfs_storage;
	return db;
}

void mail_duplicate_db_deinit(struct mail_duplicate_db **_db)
{
	struct mail_duplicate_db *db = *_db;

	*_db = NULL;

	i_assert(db->transaction_count == 0);

	i_free(db->path);
	i_free(db);
}
