/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hex-binary.h"
#include "mkdir-parents.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "home-expand.h"
#include "file-create-locked.h"
#include "file-dotlock.h"
#include "md5.h"
#include "hash.h"
#include "mail-user.h"
#include "mail-storage-settings.h"
#include "mail-duplicate.h"

#include <fcntl.h>
#include <unistd.h>

#define COMPRESS_PERCENTAGE 10
#define DUPLICATE_BUFSIZE 4096
#define DUPLICATE_VERSION 2

#define DUPLICATE_LOCK_FNAME_PREFIX "duplicate.lock."

#define DUPLICATE_LOCK_TIMEOUT_SECS 65
#define DUPLICATE_LOCK_WARN_SECS 4
#define DUPLICATE_LOCK_MAX_LOCKS 100

enum mail_duplicate_lock_result {
	MAIL_DUPLICATE_LOCK_OK,
	MAIL_DUPLICATE_LOCK_IO_ERROR,
	MAIL_DUPLICATE_LOCK_TIMEOUT,
	MAIL_DUPLICATE_LOCK_TOO_MANY,
	MAIL_DUPLICATE_LOCK_DEADLOCK,
};

struct mail_duplicate_lock {
	int fd;
	char *path;
	struct file_lock *lock;
	struct timeval start_time;
};

struct mail_duplicate {
	const void *id;
	unsigned int id_size;

	const char *user;
	time_t time;
	struct mail_duplicate_lock lock;

	bool marked:1;
	bool changed:1;
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
	ino_t db_ino;
	struct event *event;

	HASH_TABLE(struct mail_duplicate *, struct mail_duplicate *) hash;
	const char *path;
	unsigned int id_lock_count;

	bool changed:1;
};

struct mail_duplicate_db {
	struct mail_user *user;
	struct event *event;
	char *path;
	char *lock_dir;
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

static enum mail_duplicate_lock_result
duplicate_lock_failed(struct mail_duplicate_transaction *trans,
		      struct mail_duplicate *dup, const char *error)
{
	struct mail_duplicate_lock *lock = &dup->lock;
	enum mail_duplicate_lock_result result;
	int diff;

	i_assert(lock->fd == -1);
	i_assert(lock->lock == NULL);

	if (errno == EDEADLK) {
		/* deadlock */
		result = MAIL_DUPLICATE_LOCK_DEADLOCK;
	} else if (errno != EAGAIN) {
		/* not a lock timeout */
		result = MAIL_DUPLICATE_LOCK_IO_ERROR;
	} else {
		diff = timeval_diff_msecs(&ioloop_timeval,
					  &lock->start_time);
		error = t_strdup_printf("Lock timeout in %d.%03d secs",
					diff/1000, diff%1000);
		result = MAIL_DUPLICATE_LOCK_TIMEOUT;
	}

	e_error(trans->event, "Failed to lock %s: %s", lock->path, error);
	i_free_and_null(lock->path);
	i_zero(lock);
	return result;
}

static bool mail_duplicate_is_locked(struct mail_duplicate *dup)
{
	struct mail_duplicate_lock *lock = &dup->lock;

	return (lock->lock != NULL);
}

static enum mail_duplicate_lock_result
mail_duplicate_lock(struct mail_duplicate_transaction *trans,
		    struct mail_duplicate *dup)
{
	struct file_create_settings lock_set = {
		.lock_timeout_secs = DUPLICATE_LOCK_TIMEOUT_SECS,
		.lock_settings = {
			.lock_method = FILE_LOCK_METHOD_FCNTL,
			.allow_deadlock = TRUE,
		},
	};
	struct mail_duplicate_db *db = trans->db;
	struct mail_duplicate_lock *lock = &dup->lock;
	const char *error;
	unsigned char id_md5[MD5_RESULTLEN];
	bool created;
	int diff;

	if (mail_duplicate_is_locked(dup)) {
		e_debug(trans->event, "Duplicate ID already locked");
		return MAIL_DUPLICATE_LOCK_OK;
	}
	if (trans->id_lock_count >= DUPLICATE_LOCK_MAX_LOCKS) {
		e_debug(trans->event, "Too many duplicate IDs locked");
		return MAIL_DUPLICATE_LOCK_TOO_MANY;
	}

	i_assert(db->lock_dir != NULL);

	lock->start_time = ioloop_timeval;
	md5_get_digest(dup->id, dup->id_size, id_md5);
	lock->path = i_strdup_printf("%s/"DUPLICATE_LOCK_FNAME_PREFIX"%s",
				     db->lock_dir,
				     binary_to_hex(id_md5, sizeof(id_md5)));

	e_debug(trans->event, "Lock duplicate ID (path=%s)", lock->path);

	lock->fd = file_create_locked(lock->path, &lock_set, &lock->lock,
				      &created, &error);
	if (lock->fd == -1 && errno == ENOENT) {
		/* parent directory missing - create it */
		if (mkdir_parents(db->lock_dir, 0700) < 0 && errno != EEXIST) {
			error = t_strdup_printf(
				"mkdir_parents(%s) failed: %m", db->lock_dir);
		} else {
			lock->fd = file_create_locked(lock->path,
						      &lock_set, &lock->lock,
						      &created, &error);
		}
	}
	if (lock->fd == -1)
		return duplicate_lock_failed(trans, dup, error);

	diff = timeval_diff_msecs(&ioloop_timeval, &lock->start_time);
	if (diff >= (DUPLICATE_LOCK_WARN_SECS * 1000)) {
		e_warning(trans->event, "Locking %s took %d.%03d secs",
			  lock->path, diff/1000, diff%1000);
	}

	i_assert(mail_duplicate_is_locked(dup));
	trans->id_lock_count++;
	return MAIL_DUPLICATE_LOCK_OK;
}

static void
mail_duplicate_unlock(struct mail_duplicate_transaction *trans,
		      struct mail_duplicate *dup)
{
	int orig_errno = errno;

	if (dup->lock.path != NULL) {
		struct mail_duplicate_lock *lock = &dup->lock;

		e_debug(trans->event, "Unlock duplicate ID (path=%s)",
			lock->path);
		i_unlink(lock->path);
		file_lock_free(&lock->lock);
		i_close_fd(&lock->fd);
		i_free_and_null(lock->path);
		i_zero(lock);

		i_assert(trans->id_lock_count > 0);
		trans->id_lock_count--;
	}

	errno = orig_errno;
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
			hdr.stamp = time_to_uint32_trunc(stamp);
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
			e_error(trans->event,
				"broken mail_duplicate file %s", trans->path);
			return -1;
		}

		if (i_stream_read_bytes(input, &data, &size,
					hdr.id_size + hdr.user_size) <= 0) {
			e_error(trans->event,
				"unexpected end of file in %s", trans->path);
			return -1;
		}

		struct mail_duplicate dup_q, *dup;

		dup_q.id = data;
		dup_q.id_size = hdr.id_size;
		dup_q.user = t_strndup(data + hdr.id_size, hdr.user_size);

		dup = hash_table_lookup(trans->hash, &dup_q);
		if ((time_t)hdr.stamp < ioloop_time) {
                        change_count++;
			if (dup != NULL && !dup->changed)
				dup->marked = FALSE;
		} else {
			if (dup == NULL) {
				void *new_id;

				new_id = p_malloc(trans->pool, hdr.id_size);
				memcpy(new_id, data, hdr.id_size);

				dup = p_new(trans->pool,
					    struct mail_duplicate, 1);
				dup->id = new_id;
				dup->id_size = hdr.id_size;
				dup->user = p_strdup(trans->pool, dup_q.user);
				hash_table_update(trans->hash, dup, dup);
			}
			if (!dup->changed) {
				dup->marked = TRUE;
				dup->time = hdr.stamp;
			}
		}
		i_stream_skip(input, hdr.id_size + hdr.user_size);
	}

	if (hash_table_count(trans->hash) *
	    COMPRESS_PERCENTAGE / 100 > change_count)
		trans->changed = TRUE;
	return 0;
}

static int
mail_duplicate_read_db_from_fd(struct mail_duplicate_transaction *trans, int fd)
{
	struct istream *input;
	struct mail_duplicate_file_header hdr;
	const unsigned char *data;
	size_t size;
	struct stat st;
	unsigned int record_size = 0;

	if (fstat(fd, &st) < 0) {
		e_error(trans->event,
			"stat(%s) failed: %m", trans->path);
		return -1;
	}
	trans->db_ino = st.st_ino;

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

	if (record_size == 0)
		i_unlink_if_exists(trans->path);
	else T_BEGIN {
		if (mail_duplicate_read_records(trans, input, record_size) < 0)
			i_unlink_if_exists(trans->path);
	} T_END;

	i_stream_unref(&input);
	return 0;
}

static int mail_duplicate_read_db_file(struct mail_duplicate_transaction *trans)
{
	int fd, ret;

	e_debug(trans->event, "Reading %s", trans->path);

	fd = open(trans->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		e_error(trans->event,
			"open(%s) failed: %m", trans->path);
		return -1;
	}

	ret = mail_duplicate_read_db_from_fd(trans, fd);

	if (close(fd) < 0) {
		e_error(trans->event,
			"close(%s) failed: %m", trans->path);
	}
	return ret;
}

static void mail_duplicate_read(struct mail_duplicate_transaction *trans)
{
	struct mail_duplicate_db *db = trans->db;
	int new_fd;
	struct dotlock *dotlock;

	new_fd = file_dotlock_open(&db->dotlock_set, trans->path, 0, &dotlock);
	if (new_fd != -1)
		;
	else if (errno != EAGAIN) {
		e_error(trans->event,
			"file_dotlock_open(%s) failed: %m", trans->path);
	} else {
		e_error(trans->event,
			"Creating lock file for %s timed out in %u secs",
			trans->path, db->dotlock_set.timeout);
	}

	(void)mail_duplicate_read_db_file(trans);

	if (dotlock != NULL)
		file_dotlock_delete(&dotlock);
}

static void mail_duplicate_update(struct mail_duplicate_transaction *trans)
{
	struct stat st;

	if (stat(trans->path, &st) < 0) {
		if (errno == ENOENT) {
			e_debug(trans->event, "DB file not created yet");
		} else {
			e_error(trans->event,
				"stat(%s) failed: %m", trans->path);
		}
	} else if (trans->db_ino == st.st_ino) {
		e_debug(trans->event, "DB file not changed");
	} else {
		e_debug(trans->event, "DB file changed: "
			"Updating duplicate records from DB file");

		mail_duplicate_read(trans);
	}
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
	trans->db = db;

	trans->event = event_create(db->event);
	event_set_append_log_prefix(trans->event, "transaction: ");

	if (db->path == NULL) {
		/* Duplicate database disabled; return dummy transaction */
		e_debug(trans->event, "Transaction begin (dummy)");
		return trans;
	}

	e_debug(trans->event, "Transaction begin; lock %s", db->path);

	trans->path = p_strdup(pool, db->path);
	hash_table_create(&trans->hash, pool, 0,
			  mail_duplicate_hash, mail_duplicate_cmp);

	mail_duplicate_read(trans);

	return trans;
}

static void
mail_duplicate_transaction_free(struct mail_duplicate_transaction **_trans)
{
	struct mail_duplicate_transaction *trans = *_trans;
	struct hash_iterate_context *iter;
	struct mail_duplicate *d;

	if (trans == NULL)
		return;
	*_trans = NULL;

	e_debug(trans->event, "Transaction free");

	i_assert(trans->db->transaction_count > 0);
	trans->db->transaction_count--;

	if (hash_table_is_created(trans->hash)) {
		iter = hash_table_iterate_init(trans->hash);
		while (hash_table_iterate(iter, trans->hash, &d, &d))
			mail_duplicate_unlock(trans, d);
		hash_table_iterate_deinit(&iter);
		hash_table_destroy(&trans->hash);
	}
	i_assert(trans->id_lock_count == 0);

	event_unref(&trans->event);
	pool_unref(&trans->pool);
}

static struct mail_duplicate *
mail_duplicate_get(struct mail_duplicate_transaction *trans,
		   const void *id, size_t id_size, const char *user)
{
	struct mail_duplicate dup_q, *dup;

	dup_q.id = id;
	dup_q.id_size = id_size;
	dup_q.user = user;

	dup = hash_table_lookup(trans->hash, &dup_q);
	if (dup == NULL) {
		dup = p_new(trans->pool, struct mail_duplicate, 1);
		dup->id = p_memdup(trans->pool, id, id_size);
		dup->id_size = id_size;
		dup->user = p_strdup(trans->pool, user);
		dup->time = (time_t)-1;

		hash_table_insert(trans->hash, dup, dup);
	}

	return dup;
}

enum mail_duplicate_check_result
mail_duplicate_check(struct mail_duplicate_transaction *trans,
		     const void *id, size_t id_size, const char *user)
{
	struct mail_duplicate *dup;

	if (trans->path == NULL) {
		/* Duplicate database disabled */
		e_debug(trans->event, "Check ID (dummy)");
		return MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND;
	}

	dup = mail_duplicate_get(trans, id, id_size, user);

	switch (mail_duplicate_lock(trans, dup)) {
	case MAIL_DUPLICATE_LOCK_OK:
		break;
	case MAIL_DUPLICATE_LOCK_IO_ERROR:
		e_debug(trans->event,
			"Check ID: I/O error occurred while locking");
		return MAIL_DUPLICATE_CHECK_RESULT_IO_ERROR;
	case MAIL_DUPLICATE_LOCK_TIMEOUT:
		e_debug(trans->event,
			"Check ID: lock timed out");
		return MAIL_DUPLICATE_CHECK_RESULT_LOCK_TIMEOUT;
	case MAIL_DUPLICATE_LOCK_TOO_MANY:
		e_debug(trans->event,
			"Check ID: too many IDs locked");
		return MAIL_DUPLICATE_CHECK_RESULT_TOO_MANY_LOCKS;
	case MAIL_DUPLICATE_LOCK_DEADLOCK:
		e_debug(trans->event,
			"Check ID: deadlock detected while locking");
		return MAIL_DUPLICATE_CHECK_RESULT_DEADLOCK;
	}

	mail_duplicate_update(trans);
	if (dup->marked) {
		e_debug(trans->event, "Check ID: found");
		return MAIL_DUPLICATE_CHECK_RESULT_EXISTS;
	}

	e_debug(trans->event, "Check ID: not found");
	return MAIL_DUPLICATE_CHECK_RESULT_NOT_FOUND;
}

void mail_duplicate_mark(struct mail_duplicate_transaction *trans,
			 const void *id, size_t id_size,
			 const char *user, time_t timestamp)
{
	struct mail_duplicate *dup;

	if (trans->path == NULL) {
		/* Duplicate database disabled */
		e_debug(trans->event, "Mark ID (dummy)");
		return;
	}

	e_debug(trans->event, "Mark ID");

	dup = mail_duplicate_get(trans, id, id_size, user);

	/* Must already be checked and locked */
	i_assert(mail_duplicate_is_locked(dup));

	dup->time = timestamp;
	dup->marked = TRUE;
	dup->changed = TRUE;

	trans->changed = TRUE;
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
	int new_fd;
	struct dotlock *dotlock;

	if (trans == NULL)
		return;
	*_trans = NULL;

	if (trans->path == NULL) {
		e_debug(trans->event, "Commit (dummy)");
		mail_duplicate_transaction_free(&trans);
		return;
	}
	if (!trans->changed) {
		e_debug(trans->event, "Commit; no changes");
		mail_duplicate_transaction_free(&trans);
		return;
	}

	struct mail_duplicate_db *db = trans->db;

	i_assert(trans->path != NULL);
	e_debug(trans->event, "Commit; overwrite %s", trans->path);

	new_fd = file_dotlock_open(&db->dotlock_set, trans->path, 0, &dotlock);
	if (new_fd != -1)
		;
	else if (errno != EAGAIN) {
		e_error(trans->event,
			"file_dotlock_open(%s) failed: %m",
			trans->path);
		mail_duplicate_transaction_free(&trans);
		return;
	} else {
		e_error(trans->event,
			"Creating lock file for %s timed out in %u secs",
			trans->path, db->dotlock_set.timeout);
		mail_duplicate_transaction_free(&trans);
		return;
	}

	i_zero(&hdr);
	hdr.version = DUPLICATE_VERSION;

	output = o_stream_create_fd_file(new_fd, 0, FALSE);
	o_stream_cork(output);
	o_stream_nsend(output, &hdr, sizeof(hdr));

	i_zero(&rec);
	iter = hash_table_iterate_init(trans->hash);
	while (hash_table_iterate(iter, trans->hash, &d, &d)) {
		if (d->marked) {
			rec.stamp = time_to_uint32_trunc(d->time);
			rec.id_size = d->id_size;
			rec.user_size = strlen(d->user);

			o_stream_nsend(output, &rec, sizeof(rec));
			o_stream_nsend(output, d->id, rec.id_size);
			o_stream_nsend(output, d->user, rec.user_size);
		}
	}
	hash_table_iterate_deinit(&iter);

	if (o_stream_finish(output) < 0) {
		e_error(trans->event, "write(%s) failed: %s",
			trans->path, o_stream_get_error(output));
		o_stream_unref(&output);
		mail_duplicate_transaction_free(&trans);
		return;
	}
	o_stream_unref(&output);

	if (file_dotlock_replace(&dotlock, 0) < 0) {
		e_error(trans->event,
			"file_dotlock_replace(%s) failed: %m", trans->path);
	}

	iter = hash_table_iterate_init(trans->hash);
	while (hash_table_iterate(iter, trans->hash, &d, &d))
		mail_duplicate_unlock(trans, d);
	hash_table_iterate_deinit(&iter);

	mail_duplicate_transaction_free(&trans);
}

void mail_duplicate_transaction_rollback(
	struct mail_duplicate_transaction **_trans)
{
	struct mail_duplicate_transaction *trans = *_trans;

	if (trans == NULL)
		return;
	*_trans = NULL;

	if (trans->path == NULL)
		e_debug(trans->event, "Rollback (dummy)");
	else
		e_debug(trans->event, "Rollback");

	mail_duplicate_transaction_free(&trans);
}

struct mail_duplicate_db *
mail_duplicate_db_init(struct mail_user *user, const char *name)
{
	struct mail_duplicate_db *db;
	const struct mail_storage_settings *mail_set;
	const char *home = NULL;
	const char *lock_dir;

	db = i_new(struct mail_duplicate_db, 1);

	db->event = event_create(user->event);
	event_set_append_log_prefix(db->event, "duplicate db: ");

	e_debug(db->event, "Initialize");

	db->user = user;

	if (mail_user_get_home(user, &home) <= 0) {
		e_error(db->event, "User %s doesn't have home dir set, "
			"disabling duplicate database", user->username);
		return db;
	}

	i_assert(home != NULL);

	db->path = i_strconcat(home, "/.dovecot.", name, NULL);
	db->dotlock_set = default_mail_duplicate_dotlock_set;

	lock_dir = mail_user_get_volatile_dir(user);
	if (lock_dir == NULL)
		lock_dir = home;
	db->lock_dir = i_strconcat(lock_dir, "/.dovecot.", name, ".locks",
				   NULL);

	mail_set = mail_user_set_get_storage_set(user);
	db->dotlock_set.use_excl_lock = mail_set->dotlock_use_excl;
	db->dotlock_set.nfs_flush = mail_set->mail_nfs_storage;

	return db;
}

void mail_duplicate_db_deinit(struct mail_duplicate_db **_db)
{
	struct mail_duplicate_db *db = *_db;

	*_db = NULL;

	e_debug(db->event, "Cleanup");

	i_assert(db->transaction_count == 0);

	event_unref(&db->event);
	i_free(db->path);
	i_free(db->lock_dir);
	i_free(db);
}
