/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_FLOCK
#  include <sys/file.h>
#endif

/* 0.1 .. 0.2msec */
#define LOCK_RANDOM_USLEEP_TIME (100000 + (unsigned int)rand() % 100000)

/* lock methods to use in wanted order */
#define DEFAULT_LOCK_METHODS "dotlock fcntl"
/* lock timeout */
#define DEFAULT_LOCK_TIMEOUT 300
/* assume stale dotlock if mbox file hasn't changed for n seconds */
#define DEFAULT_DOTLOCK_CHANGE_TIMEOUT 30

struct dotlock_context {
	struct mail_index *index;
        enum mail_lock_type lock_type;
	int last_stale;
};

static int lock_settings_initialized = FALSE;
static int use_dotlock, use_fcntl_lock, use_flock, fcntl_before_flock;
static int use_read_dotlock, lock_timeout, dotlock_change_timeout;

static void mbox_init_lock_settings(void)
{
	const char *str;
	const char *const *lock;

        use_dotlock = use_fcntl_lock = use_flock = fcntl_before_flock = FALSE;

	str = getenv("MBOX_LOCKS");
	if (str == NULL) str = DEFAULT_LOCK_METHODS;
	for (lock = t_strsplit(str, " "); *lock != NULL; lock++) {
		if (strcasecmp(*lock, "dotlock") == 0)
			use_dotlock = TRUE;
		else if (strcasecmp(*lock, "fcntl") == 0) {
			use_fcntl_lock = TRUE;
			fcntl_before_flock = use_flock == FALSE;
		} else if (strcasecmp(*lock, "flock") == 0)
			use_flock = TRUE;
		else
			i_fatal("MBOX_LOCKS: Invalid value %s", *lock);
	}

	use_read_dotlock = getenv("MBOX_READ_DOTLOCK") != NULL;

	str = getenv("MBOX_LOCK_TIMEOUT");
	lock_timeout = str == NULL ? DEFAULT_LOCK_TIMEOUT : atoi(str);

	str = getenv("MBOX_DOTLOCK_CHANGE_TIMEOUT");
	dotlock_change_timeout = str == NULL ?
		DEFAULT_DOTLOCK_CHANGE_TIMEOUT : atoi(str);

        lock_settings_initialized = TRUE;
}

#ifdef HAVE_FLOCK
static int mbox_lock_flock(struct mail_index *index,
			   enum mail_lock_type lock_type, time_t max_wait_time)
{
	time_t now, last_notify;

	if (lock_type == MAIL_LOCK_EXCLUSIVE)
		lock_type = LOCK_EX;
	else if (lock_type == MAIL_LOCK_SHARED)
		lock_type = LOCK_SH;
	else
		lock_type = LOCK_UN;

        last_notify = 0;
	while (flock(index->mbox_fd, lock_type | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
                        mbox_set_syscall_error(index, "flock()");
			return FALSE;
		}

		if (max_wait_time == 0)
			return FALSE;

		now = time(NULL);
		if (now >= max_wait_time) {
			index->mailbox_lock_timeout = TRUE;
			index_set_error(index, "Timeout while waiting for "
					"release of flock() lock for mbox file "
					"%s", index->mailbox_path);
			return FALSE;
		}

		if (now != last_notify && index->lock_notify_cb != NULL) {
			last_notify = now;
			index->lock_notify_cb(MAIL_LOCK_NOTIFY_MAILBOX_ABORT,
					      max_wait_time - now,
					      index->lock_notify_context);
		}

		usleep(LOCK_RANDOM_USLEEP_TIME);
	}

	return TRUE;
}
#endif

static int mbox_lock_fcntl(struct mail_index *index,
			   enum mail_lock_type lock_type, time_t max_wait_time)
{
	struct flock fl;
	time_t now;
	int wait_type;

	fl.l_type = MAIL_LOCK_TO_FLOCK(lock_type);
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

        wait_type = max_wait_time == 0 ? F_SETLK : F_SETLKW;
	while (fcntl(index->mbox_fd, wait_type, &fl) < 0) {
		if (errno != EINTR) {
			if (errno != EAGAIN && errno != EACCES)
				mbox_set_syscall_error(index, "fcntl()");
			return FALSE;
		}

		now = time(NULL);
		if (max_wait_time != 0 && now >= max_wait_time) {
			index->mailbox_lock_timeout = TRUE;
			index_set_error(index, "Timeout while waiting for "
					"release of fcntl() lock for mbox file "
					"%s", index->mailbox_path);
			return FALSE;
		}

		if (index->lock_notify_cb != NULL) {
			index->lock_notify_cb(MAIL_LOCK_NOTIFY_MAILBOX_ABORT,
					      max_wait_time - now,
					      index->lock_notify_context);
		}
	}
	return TRUE;
}

static int mbox_file_locks(struct mail_index *index,
			   enum mail_lock_type lock_type, time_t max_wait_time)
{
	struct stat st;

	/* now we need to have the file itself locked. open it if needed. */
	if (stat(index->mailbox_path, &st) < 0)
		return mbox_set_syscall_error(index, "stat()");

	if (st.st_dev != index->mbox_dev || st.st_ino != index->mbox_ino)
		mbox_file_close_fd(index);

	if (index->mbox_fd == -1) {
		if (!mbox_file_open(index)) {
			(void)mbox_unlock(index);
			return FALSE;
		}
	}

	if (use_fcntl_lock && fcntl_before_flock) {
		if (!mbox_lock_fcntl(index, lock_type, max_wait_time))
			return FALSE;
	}
#ifdef HAVE_FLOCK
	if (use_flock) {
		if (!mbox_lock_flock(index, lock_type, max_wait_time))
			return FALSE;
	}
#endif
	if (use_fcntl_lock && !fcntl_before_flock) {
		if (!mbox_lock_fcntl(index, lock_type, max_wait_time))
			return FALSE;
	}
	return TRUE;
}

static int mbox_file_unlock(struct mail_index *index)
{
	int failed = FALSE;

#ifdef HAVE_FLOCK
	if (use_flock && !mbox_lock_flock(index, MAIL_LOCK_UNLOCK, 0))
		failed = TRUE;
#endif
	if (use_fcntl_lock &&
	    !mbox_lock_fcntl(index, MAIL_LOCK_UNLOCK, 0))
		failed = TRUE;

	return !failed;
}

static int dotlock_callback(unsigned int secs_left, int stale, void *context)
{
	struct dotlock_context *ctx = context;

	if (stale && !ctx->last_stale) {
		if (!mbox_file_locks(ctx->index, ctx->lock_type, 0)) {
			/* we couldn't get fcntl/flock - it's really locked */
			ctx->last_stale = TRUE;
			return FALSE;
		}
		(void)mbox_file_unlock(ctx->index);
	}
	ctx->last_stale = stale;

	ctx->index->lock_notify_cb(stale ? MAIL_LOCK_NOTIFY_MAILBOX_OVERRIDE :
				   MAIL_LOCK_NOTIFY_MAILBOX_ABORT,
				   secs_left, ctx->index->lock_notify_context);
	return TRUE;
}

int mbox_lock(struct mail_index *index, enum mail_lock_type lock_type)
{
	time_t max_wait_time;
	int ret;

	/* index must be locked before mbox file, to avoid deadlocks */
	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* allow only unlock -> shared/exclusive or exclusive -> shared */
	i_assert(lock_type == MAIL_LOCK_SHARED ||
		 lock_type == MAIL_LOCK_EXCLUSIVE);
	i_assert(lock_type != MAIL_LOCK_EXCLUSIVE ||
		 index->mbox_lock_type != MAIL_LOCK_SHARED);

	if (index->mbox_lock_type == lock_type)
		return TRUE;

	if (!lock_settings_initialized)
                mbox_init_lock_settings();

	max_wait_time = time(NULL) + lock_timeout;

	/* make .lock file first to protect overwriting the file */
	if (use_dotlock && index->mbox_dotlock.ino == 0) {
		struct dotlock_context ctx;

		ctx.index = index;
		ctx.lock_type = lock_type;
		ctx.last_stale = -1;

		ret = file_lock_dotlock(index->mailbox_path,
					lock_type == MAIL_LOCK_SHARED &&
					!use_read_dotlock, lock_timeout,
					dotlock_change_timeout,
					dotlock_callback, &ctx,
					&index->mbox_dotlock);

		if (ret < 0) {
			mbox_set_syscall_error(index, "file_lock_dotlock()");
			return FALSE;
		}
		if (ret == 0) {
			index_set_error(index, "Timeout while waiting for "
					"release of dotlock for mbox %s",
					index->mailbox_path);
			index->mailbox_lock_timeout = TRUE;
			return FALSE;
		}
	}

	index->mbox_lock_type = lock_type;
	if (!mbox_file_locks(index, index->mbox_lock_type, max_wait_time)) {
		(void)mbox_unlock(index);
		return FALSE;
	}

	return TRUE;
}

int mbox_unlock(struct mail_index *index)
{
	int failed;

	index->mbox_lock_counter++;

	if (index->mbox_lock_type == MAIL_LOCK_UNLOCK)
		return TRUE;

	failed = FALSE;
	if (index->mbox_fd != -1) {
		if (!mbox_file_unlock(index))
			failed = TRUE;
	}

	if (index->mbox_dotlock.ino != 0) {
		if (file_unlock_dotlock(index->mailbox_path,
					&index->mbox_dotlock) <= 0) {
                        mbox_set_syscall_error(index, "file_unlock_dotlock()");
			failed = TRUE;
		}
                index->mbox_dotlock.ino = 0;
	}

	/* make sure we don't keep mmap() between locks - there could have
	   been changes to file size which would break things. or actually
	   it'd break only if file was shrinked+grown back to exact size,
	   but still possible :) */
	mbox_file_close_stream(index);

	index->mbox_lock_type = MAIL_LOCK_UNLOCK;
	return !failed;
}
