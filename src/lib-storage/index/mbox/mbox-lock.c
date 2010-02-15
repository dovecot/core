/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "restrict-access.h"
#include "nfs-workarounds.h"
#include "mail-index-private.h"
#include "mbox-storage.h"
#include "istream-raw-mbox.h"
#include "mbox-file.h"
#include "mbox-lock.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <grp.h>

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

enum mbox_lock_type {
	MBOX_LOCK_DOTLOCK,
	MBOX_LOCK_DOTLOCK_TRY,
	MBOX_LOCK_FCNTL,
	MBOX_LOCK_FLOCK,
	MBOX_LOCK_LOCKF,

	MBOX_LOCK_COUNT
};

enum mbox_dotlock_op {
	MBOX_DOTLOCK_OP_LOCK,
	MBOX_DOTLOCK_OP_UNLOCK,
	MBOX_DOTLOCK_OP_TOUCH
};

struct mbox_lock_context {
	struct mbox_mailbox *mbox;
	int lock_status[MBOX_LOCK_COUNT];
	bool checked_file;

	int lock_type;
	bool dotlock_last_stale;
	bool fcntl_locked;
	bool using_privileges;
};

struct mbox_lock_data {
	enum mbox_lock_type type;
	const char *name;
	int (*func)(struct mbox_lock_context *ctx, int lock_type,
		    time_t max_wait_time);
};

static int mbox_lock_dotlock(struct mbox_lock_context *ctx, int lock_type,
			     time_t max_wait_time);
static int mbox_lock_dotlock_try(struct mbox_lock_context *ctx, int lock_type,
				 time_t max_wait_time);
static int mbox_lock_fcntl(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time);
#ifdef HAVE_FLOCK
static int mbox_lock_flock(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time);
#else
#  define mbox_lock_flock NULL
#endif
#ifdef HAVE_LOCKF
static int mbox_lock_lockf(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time);
#else
#  define mbox_lock_lockf NULL
#endif

static struct mbox_lock_data lock_data[] = {
	{ MBOX_LOCK_DOTLOCK, "dotlock", mbox_lock_dotlock },
	{ MBOX_LOCK_DOTLOCK_TRY, "dotlock_try", mbox_lock_dotlock_try },
	{ MBOX_LOCK_FCNTL, "fcntl", mbox_lock_fcntl },
	{ MBOX_LOCK_FLOCK, "flock", mbox_lock_flock },
	{ MBOX_LOCK_LOCKF, "lockf", mbox_lock_lockf },
	{ 0, NULL, NULL }
};

static int mbox_lock_list(struct mbox_lock_context *ctx, int lock_type,
			  time_t max_wait_time, int idx);
static int mbox_unlock_files(struct mbox_lock_context *ctx);

static void mbox_read_lock_methods(const char *str, const char *env,
				   enum mbox_lock_type *locks)
{
        enum mbox_lock_type type;
	const char *const *lock;
	int i, dest;

	for (lock = t_strsplit(str, " "), dest = 0; *lock != NULL; lock++) {
		for (type = 0; lock_data[type].name != NULL; type++) {
			if (strcasecmp(*lock, lock_data[type].name) == 0) {
				type = lock_data[type].type;
				break;
			}
		}
		if (lock_data[type].name == NULL)
			i_fatal("%s: Invalid value %s", env, *lock);
		if (lock_data[type].func == NULL) {
			i_fatal("%s: Support for lock type %s "
				"not compiled into binary", env, *lock);
		}

		for (i = 0; i < dest; i++) {
			if (locks[i] == type)
				i_fatal("%s: Duplicated value %s", env, *lock);
		}

		/* @UNSAFE */
		locks[dest++] = type;
	}
	locks[dest] = (enum mbox_lock_type)-1;
}

static void mbox_init_lock_settings(struct mbox_storage *storage)
{
	enum mbox_lock_type read_locks[MBOX_LOCK_COUNT+1];
	enum mbox_lock_type write_locks[MBOX_LOCK_COUNT+1];
	int r, w;

	mbox_read_lock_methods(storage->set->mbox_read_locks,
			       "mbox_read_locks", read_locks);
	mbox_read_lock_methods(storage->set->mbox_write_locks,
			       "mbox_write_locks", write_locks);

	/* check that read/write list orders match. write_locks must contain
	   at least read_locks and possibly more. */
	for (r = w = 0; write_locks[w] != (enum mbox_lock_type)-1; w++) {
		if (read_locks[r] == (enum mbox_lock_type)-1)
			break;
		if (read_locks[r] == write_locks[w])
			r++;
	}
	if (read_locks[r] != (enum mbox_lock_type)-1) {
		i_fatal("mbox read/write lock list settings are invalid. "
			"Lock ordering must be the same with both, "
			"and write locks must contain all read locks "
			"(and possibly more)");
	}

	storage->read_locks = p_new(storage->storage.pool,
				    enum mbox_lock_type, MBOX_LOCK_COUNT+1);
	memcpy(storage->read_locks, read_locks,
	       sizeof(*storage->read_locks) * (MBOX_LOCK_COUNT+1));

	storage->write_locks = p_new(storage->storage.pool,
				     enum mbox_lock_type, MBOX_LOCK_COUNT+1);
	memcpy(storage->write_locks, write_locks,
	       sizeof(*storage->write_locks) * (MBOX_LOCK_COUNT+1));

        storage->lock_settings_initialized = TRUE;
}

static int mbox_file_open_latest(struct mbox_lock_context *ctx, int lock_type)
{
	struct mbox_mailbox *mbox = ctx->mbox;
	struct stat st;

	if (ctx->checked_file || lock_type == F_UNLCK)
		return 0;

	if (mbox->mbox_fd != -1) {
		/* we could flush NFS file handle cache here if we wanted to
		   be sure that the file is latest, but mbox files get rarely
		   deleted and the flushing might cause errors (e.g. EBUSY for
		   trying to flush a /var/mail mountpoint) */
		if (nfs_safe_stat(mbox->box.path, &st) < 0) {
			if (errno == ENOENT)
				mailbox_set_deleted(&mbox->box);
			else
				mbox_set_syscall_error(mbox, "stat()");
			return -1;
		}

		if (st.st_ino != mbox->mbox_ino ||
		    !CMP_DEV_T(st.st_dev, mbox->mbox_dev))
			mbox_file_close(mbox);
	}

	if (mbox->mbox_fd == -1) {
		if (mbox_file_open(mbox) < 0)
			return -1;
	}

	ctx->checked_file = TRUE;
	return 0;
}

static bool dotlock_callback(unsigned int secs_left, bool stale, void *context)
{
        struct mbox_lock_context *ctx = context;
	enum mbox_lock_type *lock_types;
	int i;

	if (ctx->using_privileges)
		restrict_access_drop_priv_gid();

	if (stale && !ctx->dotlock_last_stale) {
		/* get next index we wish to try locking. it's the one after
		   dotlocking. */
		lock_types = ctx->lock_type == F_WRLCK ||
			(ctx->lock_type == F_UNLCK &&
			 ctx->mbox->mbox_lock_type == F_WRLCK) ?
			ctx->mbox->storage->write_locks :
			ctx->mbox->storage->read_locks;

		for (i = 0; lock_types[i] != (enum mbox_lock_type)-1; i++) {
			if (lock_types[i] == MBOX_LOCK_DOTLOCK)
				break;
		}

		if (lock_types[i] != (enum mbox_lock_type)-1 &&
		    lock_types[i+1] != (enum mbox_lock_type)-1) {
			i++;
			if (mbox_lock_list(ctx, ctx->lock_type, 0, i) <= 0) {
				/* we couldn't get fd lock -
				   it's really locked */
				ctx->dotlock_last_stale = TRUE;
				return FALSE;
			}
			(void)mbox_lock_list(ctx, F_UNLCK, 0, i);
		}
	}
	ctx->dotlock_last_stale = stale;

	index_storage_lock_notify(&ctx->mbox->box, stale ?
				  MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE :
				  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
				  secs_left);
	if (ctx->using_privileges) {
		if (restrict_access_use_priv_gid() < 0) {
			/* shouldn't get here */
			return FALSE;
		}
	}
	return TRUE;
}

static int mbox_dotlock_privileged_op(struct mbox_mailbox *mbox,
				      struct dotlock_settings *set,
				      enum mbox_dotlock_op op)
{
	const char *dir, *fname;
	int ret = -1, orig_dir_fd, orig_errno;

	orig_dir_fd = open(".", O_RDONLY);
	if (orig_dir_fd == -1) {
		mail_storage_set_critical(&mbox->storage->storage,
					  "open(.) failed: %m");
		return -1;
	}

	/* allow dotlocks to be created only for files we can read while we're
	   unprivileged. to make sure there are no race conditions we first
	   have to chdir to the mbox file's directory and then use relative
	   paths. unless this is done, users could:
	    - create *.lock files to any directory writable by the
	      privileged group
	    - DoS other users by dotlocking their mailboxes infinitely
	*/
	fname = strrchr(mbox->box.path, '/');
	if (fname == NULL) {
		/* already relative */
		fname = mbox->box.path;
	} else {
		dir = t_strdup_until(mbox->box.path, fname);
		if (chdir(dir) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"chdir(%s) failed: %m", dir);
			(void)close(orig_dir_fd);
			return -1;
		}
		fname++;
	}
	if (op == MBOX_DOTLOCK_OP_LOCK) {
		if (access(fname, R_OK) < 0) {
			mail_storage_set_critical(&mbox->storage->storage,
				"access(%s) failed: %m", mbox->box.path);
			return -1;
		}
	}

	if (restrict_access_use_priv_gid() < 0) {
		(void)close(orig_dir_fd);
		return -1;
	}

	switch (op) {
	case MBOX_DOTLOCK_OP_LOCK:
		/* we're now privileged - avoid doing as much as possible */
		ret = file_dotlock_create(set, fname, 0, &mbox->mbox_dotlock);
		if (ret > 0)
			mbox->mbox_used_privileges = TRUE;
		else if (ret < 0 && errno == EACCES) {
			const char *errmsg =
				eacces_error_get_creating("file_dotlock_create",
							  fname);
			mail_storage_set_critical(&mbox->storage->storage,
						  "%s", errmsg);
		} else {
			mbox_set_syscall_error(mbox, "file_dotlock_create()");
		}
		break;
	case MBOX_DOTLOCK_OP_UNLOCK:
		/* we're now privileged - avoid doing as much as possible */
		ret = file_dotlock_delete(&mbox->mbox_dotlock);
		if (ret < 0)
			mbox_set_syscall_error(mbox, "file_dotlock_delete()");
		mbox->mbox_used_privileges = FALSE;
		break;
	case MBOX_DOTLOCK_OP_TOUCH:
		ret = file_dotlock_touch(mbox->mbox_dotlock);
		if (ret < 0)
			mbox_set_syscall_error(mbox, "file_dotlock_touch()");
		break;
	}

	orig_errno = errno;
	restrict_access_drop_priv_gid();

	if (fchdir(orig_dir_fd) < 0) {
		mail_storage_set_critical(&mbox->storage->storage,
			"fchdir() failed: %m");
	}
	(void)close(orig_dir_fd);
	errno = orig_errno;
	return ret;
}

static void
mbox_dotlock_log_eacces_error(struct mbox_mailbox *mbox, const char *path)
{
	const char *dir, *errmsg;
	struct stat st;
	const struct group *group;
	int orig_errno = errno;

	errmsg = eacces_error_get_creating("file_dotlock_create", path);
	dir = strrchr(path, '/');
	dir = dir == NULL ? "." : t_strdup_until(path, dir);
	if (!mbox->box.inbox) {
		mail_storage_set_critical(&mbox->storage->storage,
			"%s (not INBOX -> no privileged locking)", errmsg);
	} else if (!mbox->mbox_privileged_locking) {
		dir = mailbox_list_get_path(mbox->box.list, NULL,
					    MAILBOX_LIST_PATH_TYPE_DIR);
		mail_storage_set_critical(&mbox->storage->storage,
			"%s (under root dir %s -> no privileged locking)",
			errmsg, dir);
	} else if (stat(dir, &st) == 0 &&
		   (st.st_mode & 02) == 0 && /* not world-writable */
		   (st.st_mode & 020) != 0) { /* group-writable */
		group = getgrgid(st.st_gid);
		mail_storage_set_critical(&mbox->storage->storage,
			"%s (set mail_privileged_group=%s)", errmsg,
			group == NULL ? dec2str(st.st_gid) : group->gr_name);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
			"%s (nonstandard permissions in %s)", errmsg, dir);
	}
	errno = orig_errno;
}

static int
mbox_lock_dotlock_int(struct mbox_lock_context *ctx, int lock_type, bool try)
{
	struct mbox_mailbox *mbox = ctx->mbox;
	struct dotlock_settings set;
	int ret;

	if (lock_type == F_UNLCK) {
		if (!mbox->mbox_dotlocked)
			return 1;

		if (!mbox->mbox_used_privileges) {
			if (file_dotlock_delete(&mbox->mbox_dotlock) <= 0) {
				mbox_set_syscall_error(mbox,
						       "file_dotlock_delete()");
			}
		} else {
			ctx->using_privileges = TRUE;
			(void)mbox_dotlock_privileged_op(mbox, NULL,
							 MBOX_DOTLOCK_OP_UNLOCK);
			ctx->using_privileges = FALSE;
		}
                mbox->mbox_dotlocked = FALSE;
		return 1;
	}

	if (mbox->mbox_dotlocked)
		return 1;

        ctx->dotlock_last_stale = -1;

	memset(&set, 0, sizeof(set));
	set.use_excl_lock = mbox->storage->storage.set->dotlock_use_excl;
	set.nfs_flush = mbox->storage->storage.set->mail_nfs_storage;
	set.timeout = mbox->storage->set->mbox_lock_timeout;
	set.stale_timeout = mbox->storage->set->mbox_dotlock_change_timeout;
	set.callback = dotlock_callback;
	set.context = ctx;

	ret = file_dotlock_create(&set, mbox->box.path, 0,
				  &mbox->mbox_dotlock);
	if (ret >= 0) {
		/* success / timeout */
	} else if (errno == EACCES && restrict_access_have_priv_gid() &&
		   mbox->mbox_privileged_locking) {
		/* try again, this time with extra privileges */
		ret = mbox_dotlock_privileged_op(mbox, &set,
						 MBOX_DOTLOCK_OP_LOCK);
	} else if (errno == EACCES)
		mbox_dotlock_log_eacces_error(mbox, mbox->box.path);
	else
		mbox_set_syscall_error(mbox, "file_dotlock_create()");

	if (ret < 0) {
		if ((ENOSPACE(errno) || errno == EACCES) && try)
			return 1;
		return -1;
	}
	if (ret == 0) {
		mail_storage_set_error(&mbox->storage->storage,
			MAIL_ERROR_TEMP, MAIL_ERRSTR_LOCK_TIMEOUT);
		return 0;
	}
	mbox->mbox_dotlocked = TRUE;

	if (mbox_file_open_latest(ctx, lock_type) < 0)
		return -1;
	return 1;
}

static int mbox_lock_dotlock(struct mbox_lock_context *ctx, int lock_type,
			     time_t max_wait_time ATTR_UNUSED)
{
	return mbox_lock_dotlock_int(ctx, lock_type, FALSE);
}

static int mbox_lock_dotlock_try(struct mbox_lock_context *ctx, int lock_type,
				 time_t max_wait_time ATTR_UNUSED)
{
	return mbox_lock_dotlock_int(ctx, lock_type, TRUE);
}

#ifdef HAVE_FLOCK
static int mbox_lock_flock(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time)
{
	time_t now, last_notify;
	unsigned int next_alarm;

	if (mbox_file_open_latest(ctx, lock_type) < 0)
		return -1;

	if (lock_type == F_UNLCK && ctx->mbox->mbox_fd == -1)
		return 1;

	if (lock_type == F_WRLCK)
		lock_type = LOCK_EX;
	else if (lock_type == F_RDLCK)
		lock_type = LOCK_SH;
	else
		lock_type = LOCK_UN;

	if (max_wait_time == 0) {
		/* usually we're waiting here, but if we came from
		   mbox_lock_dotlock(), we just want to try locking */
		lock_type |= LOCK_NB;
	} else {
		now = time(NULL);
		if (now >= max_wait_time)
			alarm(1);
		else
			alarm(I_MIN(max_wait_time - now, 5));
	}

        last_notify = 0;
	while (flock(ctx->mbox->mbox_fd, lock_type) < 0) {
		if (errno != EINTR) {
			if (errno == EWOULDBLOCK && max_wait_time == 0) {
				/* non-blocking lock trying failed */
				return 0;
			}
			alarm(0);
			mbox_set_syscall_error(ctx->mbox, "flock()");
			return -1;
		}

		now = time(NULL);
		if (now >= max_wait_time) {
			alarm(0);
			return 0;
		}

		/* notify locks once every 5 seconds.
		   try to use rounded values. */
		next_alarm = (max_wait_time - now) % 5;
		if (next_alarm == 0)
			next_alarm = 5;
		alarm(next_alarm);

		index_storage_lock_notify(&ctx->mbox->box,
					  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
					  max_wait_time - now);
	}

	alarm(0);
	return 1;
}
#endif

#ifdef HAVE_LOCKF
static int mbox_lock_lockf(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time)
{
	time_t now, last_notify;
	unsigned int next_alarm;

	if (mbox_file_open_latest(ctx, lock_type) < 0)
		return -1;

	if (lock_type == F_UNLCK && ctx->mbox->mbox_fd == -1)
		return 1;

	if (lock_type == F_UNLCK)
		lock_type = F_ULOCK;
	else if (max_wait_time == 0) {
		/* usually we're waiting here, but if we came from
		   mbox_lock_dotlock(), we just want to try locking */
		lock_type = F_TLOCK;
	} else {
		now = time(NULL);
		if (now >= max_wait_time)
			alarm(1);
		else
			alarm(I_MIN(max_wait_time - now, 5));
		lock_type = F_LOCK;
	}

        last_notify = 0;
	while (lockf(ctx->mbox->mbox_fd, lock_type, 0) < 0) {
		if (errno != EINTR) {
			if ((errno == EACCES || errno == EAGAIN) &&
			    max_wait_time == 0) {
				/* non-blocking lock trying failed */
				return 0;
			}
			alarm(0);
			mbox_set_syscall_error(ctx->mbox, "lockf()");
			return -1;
		}

		now = time(NULL);
		if (now >= max_wait_time) {
			alarm(0);
			return 0;
		}

		/* notify locks once every 5 seconds.
		   try to use rounded values. */
		next_alarm = (max_wait_time - now) % 5;
		if (next_alarm == 0)
			next_alarm = 5;
		alarm(next_alarm);

		index_storage_lock_notify(&ctx->mbox->box,
					  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
					  max_wait_time - now);
	}

	alarm(0);
	return 1;
}
#endif

static int mbox_lock_fcntl(struct mbox_lock_context *ctx, int lock_type,
			   time_t max_wait_time)
{
	struct flock fl;
	time_t now;
	unsigned int next_alarm;
	int wait_type;

	if (mbox_file_open_latest(ctx, lock_type) < 0)
		return -1;

	if (lock_type == F_UNLCK && ctx->mbox->mbox_fd == -1)
		return 1;

	memset(&fl, 0, sizeof(fl));
	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (max_wait_time == 0) {
		/* usually we're waiting here, but if we came from
		   mbox_lock_dotlock(), we just want to try locking */
		wait_type = F_SETLK;
	} else {
		wait_type = F_SETLKW;
		now = time(NULL);
		if (now >= max_wait_time)
			alarm(1);
		else
			alarm(I_MIN(max_wait_time - now, 5));
	}

	while (fcntl(ctx->mbox->mbox_fd, wait_type, &fl) < 0) {
		if (errno != EINTR) {
			if ((errno == EACCES || errno == EAGAIN) &&
			    wait_type == F_SETLK) {
				/* non-blocking lock trying failed */
				return 0;
			}
			alarm(0);
			if (errno != EACCES) {
				mbox_set_syscall_error(ctx->mbox, "fcntl()");
				return -1;
			}
			mail_storage_set_critical(&ctx->mbox->storage->storage,
				"fcntl() failed with mbox file %s: "
				"File is locked by another process (EACCES)",
				ctx->mbox->box.path);
			return -1;
		}

		now = time(NULL);
		if (now >= max_wait_time) {
			alarm(0);
			return 0;
		}

		/* notify locks once every 5 seconds.
		   try to use rounded values. */
		next_alarm = (max_wait_time - now) % 5;
		if (next_alarm == 0)
			next_alarm = 5;
		alarm(next_alarm);

		index_storage_lock_notify(&ctx->mbox->box,
					  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
					  max_wait_time - now);
	}

	alarm(0);
	ctx->fcntl_locked = TRUE;
	return 1;
}

static int mbox_lock_list(struct mbox_lock_context *ctx, int lock_type,
			  time_t max_wait_time, int idx)
{
	enum mbox_lock_type *lock_types;
        enum mbox_lock_type type;
	int i, ret = 0, lock_status;

	ctx->lock_type = lock_type;

	lock_types = lock_type == F_WRLCK ||
		(lock_type == F_UNLCK && ctx->mbox->mbox_lock_type == F_WRLCK) ?
		ctx->mbox->storage->write_locks :
		ctx->mbox->storage->read_locks;
	for (i = idx; lock_types[i] != (enum mbox_lock_type)-1; i++) {
		type = lock_types[i];
		lock_status = lock_type != F_UNLCK;

		if (ctx->lock_status[type] == lock_status)
			continue;
		ctx->lock_status[type] = lock_status;

		ret = lock_data[type].func(ctx, lock_type, max_wait_time);
		if (ret <= 0)
			break;
	}
	return ret;
}

static int mbox_update_locking(struct mbox_mailbox *mbox, int lock_type,
			       bool *fcntl_locked_r)
{
	struct mbox_lock_context ctx;
	time_t max_wait_time;
	int ret, i;
	bool drop_locks;

	*fcntl_locked_r = FALSE;

        index_storage_lock_notify_reset(&mbox->box);

	if (!mbox->storage->lock_settings_initialized)
                mbox_init_lock_settings(mbox->storage);

	if (mbox->mbox_fd == -1 && mbox->mbox_file_stream != NULL) {
		/* read-only mbox stream. no need to lock. */
		i_assert(mbox->box.backend_readonly);
		mbox->mbox_lock_type = lock_type;
		return 1;
	}

	max_wait_time = time(NULL) + mbox->storage->set->mbox_lock_timeout;

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;

	if (mbox->mbox_lock_type == F_WRLCK) {
		/* dropping to shared lock. first drop those that we
		   don't remove completely. */
		const enum mbox_lock_type *read_locks =
                        mbox->storage->read_locks;

		for (i = 0; i < MBOX_LOCK_COUNT; i++)
			ctx.lock_status[i] = 1;
		for (i = 0; read_locks[i] != (enum mbox_lock_type)-1; i++)
			ctx.lock_status[read_locks[i]] = 0;
		drop_locks = TRUE;
	} else {
		drop_locks = FALSE;
	}

	mbox->mbox_lock_type = lock_type;
	ret = mbox_lock_list(&ctx, lock_type, max_wait_time, 0);
	if (ret <= 0) {
		if (!drop_locks)
			(void)mbox_unlock_files(&ctx);
		if (ret == 0) {
			mail_storage_set_error(&mbox->storage->storage,
				MAIL_ERROR_TEMP, MAIL_ERRSTR_LOCK_TIMEOUT);
		}
		return ret;
	}

	if (drop_locks) {
		/* dropping to shared lock: drop the locks that are only
		   in write list */
		const enum mbox_lock_type *read_locks =
                        mbox->storage->read_locks;
		const enum mbox_lock_type *write_locks =
			mbox->storage->write_locks;

		memset(ctx.lock_status, 0, sizeof(ctx.lock_status));
		for (i = 0; write_locks[i] != (enum mbox_lock_type)-1; i++)
			ctx.lock_status[write_locks[i]] = 1;
		for (i = 0; read_locks[i] != (enum mbox_lock_type)-1; i++)
			ctx.lock_status[read_locks[i]] = 0;

		mbox->mbox_lock_type = F_WRLCK;
		(void)mbox_lock_list(&ctx, F_UNLCK, 0, 0);
		mbox->mbox_lock_type = F_RDLCK;
	}

	*fcntl_locked_r = ctx.fcntl_locked;
	return 1;
}

int mbox_lock(struct mbox_mailbox *mbox, int lock_type,
	      unsigned int *lock_id_r)
{
	const char *path = mbox->box.path;
	int mbox_fd = mbox->mbox_fd;
	bool fcntl_locked;
	int ret;

	/* allow only unlock -> shared/exclusive or exclusive -> shared */
	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);
	i_assert(lock_type == F_RDLCK || mbox->mbox_lock_type != F_RDLCK);

	/* mbox must be locked before index */
	i_assert(mbox->box.index->lock_type != F_WRLCK);

	if (mbox->mbox_lock_type == F_UNLCK) {
		ret = mbox_update_locking(mbox, lock_type, &fcntl_locked);
		if (ret <= 0)
			return ret;

		if (mbox->storage->storage.set->mail_nfs_storage) {
			if (fcntl_locked) {
				nfs_flush_attr_cache_fd_locked(path, mbox_fd);
				nfs_flush_read_cache_locked(path, mbox_fd);
			} else {
				nfs_flush_attr_cache_unlocked(path);
				nfs_flush_read_cache_unlocked(path, mbox_fd);
			}
		}

		mbox->mbox_lock_id += 2;
	}

	if (lock_type == F_RDLCK) {
		mbox->mbox_shared_locks++;
		*lock_id_r = mbox->mbox_lock_id;
	} else {
		mbox->mbox_excl_locks++;
		*lock_id_r = mbox->mbox_lock_id + 1;
	}
	if (mbox->mbox_stream != NULL)
		istream_raw_mbox_set_locked(mbox->mbox_stream);
	return 1;
}

static int mbox_unlock_files(struct mbox_lock_context *ctx)
{
	int ret = 0;

	if (mbox_lock_list(ctx, F_UNLCK, 0, 0) < 0)
		ret = -1;

	ctx->mbox->mbox_lock_id += 2;
	ctx->mbox->mbox_lock_type = F_UNLCK;
	return ret;
}

int mbox_unlock(struct mbox_mailbox *mbox, unsigned int lock_id)
{
	struct mbox_lock_context ctx;
	bool fcntl_locked;
	int i;

	i_assert(mbox->mbox_lock_id == (lock_id & ~1));

	if (lock_id & 1) {
		/* dropping exclusive lock */
		i_assert(mbox->mbox_excl_locks > 0);
		if (--mbox->mbox_excl_locks > 0)
			return 0;
		if (mbox->mbox_shared_locks > 0) {
			/* drop to shared lock */
			if (mbox_update_locking(mbox, F_RDLCK,
						&fcntl_locked) < 0)
				return -1;
			return 0;
		}
	} else {
		/* dropping shared lock */
		i_assert(mbox->mbox_shared_locks > 0);
		if (--mbox->mbox_shared_locks > 0)
			return 0;
		if (mbox->mbox_excl_locks > 0)
			return 0;
	}
	/* all locks gone */

	/* make sure we don't read the stream while unlocked */
	if (mbox->mbox_stream != NULL)
		istream_raw_mbox_set_unlocked(mbox->mbox_stream);

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;

	for (i = 0; i < MBOX_LOCK_COUNT; i++)
		ctx.lock_status[i] = 1;

	return mbox_unlock_files(&ctx);
}

void mbox_dotlock_touch(struct mbox_mailbox *mbox)
{
	if (mbox->mbox_dotlock == NULL)
		return;

	if (!mbox->mbox_used_privileges)
		(void)file_dotlock_touch(mbox->mbox_dotlock);
	else {
		(void)mbox_dotlock_privileged_op(mbox, NULL,
						 MBOX_DOTLOCK_OP_TOUCH);
	}
}
