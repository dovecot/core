/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-lock.h"

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
        struct index_mailbox *ibox;
        int lock_type;
	int last_stale;
};

static int lock_settings_initialized = FALSE;
static int use_dotlock, use_fcntl_lock, use_flock, fcntl_before_flock;
static int use_read_dotlock, lock_timeout, dotlock_change_timeout;

static int mbox_unlock_files(struct index_mailbox *ibox);

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
static int mbox_lock_flock(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time)
{
	time_t now, last_notify;

	if (lock_type == F_WRLCK)
		lock_type = LOCK_EX;
	else if (lock_type == F_RDLCK)
		lock_type = LOCK_SH;
	else
		lock_type = LOCK_UN;

        last_notify = 0;
	while (flock(ibox->mbox_fd, lock_type | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
			mbox_set_syscall_error(ibox, "flock()");
			return -1;
		}

		if (max_wait_time == 0)
			return 0;

		now = time(NULL);
		if (now >= max_wait_time)
			return 0;

		if (now != last_notify) {
			index_storage_lock_notify(ibox,
				MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
				max_wait_time - now);
		}

		usleep(LOCK_RANDOM_USLEEP_TIME);
	}

	return 1;
}
#endif

static int mbox_lock_fcntl(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time)
{
	struct flock fl;
	time_t now;
	int wait_type;

	fl.l_type = lock_type;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

        wait_type = max_wait_time == 0 ? F_SETLK : F_SETLKW;
	while (fcntl(ibox->mbox_fd, wait_type, &fl) < 0) {
		if (errno != EINTR) {
			if (errno != EAGAIN && errno != EACCES)
				mbox_set_syscall_error(ibox, "fcntl()");
			return -1;
		}

		now = time(NULL);
		if (max_wait_time != 0 && now >= max_wait_time)
			return 0;

		index_storage_lock_notify(ibox,
					  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
					  max_wait_time - now);
	}

	return 1;
}

static int mbox_file_locks(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time)
{
	struct stat st;
	int ret;

	/* now we need to have the file itself locked. open it if needed. */
	if (stat(ibox->path, &st) < 0) {
		mbox_set_syscall_error(ibox, "stat()");
		return -1;
	}

	if (st.st_dev != ibox->mbox_dev || st.st_ino != ibox->mbox_ino)
		mbox_file_close(ibox);

	if (ibox->mbox_fd == -1) {
		if (mbox_file_open(ibox) < 0) {
			(void)mbox_unlock_files(ibox);
			return -1;
		}
	}

	if (use_fcntl_lock && fcntl_before_flock) {
		ret = mbox_lock_fcntl(ibox, lock_type, max_wait_time);
		if (ret <= 0)
			return ret;
	}
#ifdef HAVE_FLOCK
	if (use_flock) {
		ret = mbox_lock_flock(ibox, lock_type, max_wait_time);
		if (ret <= 0)
			return ret;
	}
#endif
	if (use_fcntl_lock && !fcntl_before_flock) {
		ret = mbox_lock_fcntl(ibox, lock_type, max_wait_time);
		if (ret <= 0)
			return ret;
	}
	return 1;
}

static int mbox_file_unlock(struct index_mailbox *ibox)
{
	int ret = 0;

#ifdef HAVE_FLOCK
	if (use_flock && mbox_lock_flock(ibox, F_UNLCK, 0) < 0)
		ret = -1;
#endif
	if (use_fcntl_lock && mbox_lock_fcntl(ibox, F_UNLCK, 0) < 0)
		ret = -1;

	return ret;
}

static int dotlock_callback(unsigned int secs_left, int stale, void *context)
{
	struct dotlock_context *ctx = context;

	if (stale && !ctx->last_stale) {
		if (mbox_file_locks(ctx->ibox, ctx->lock_type, 0) <= 0) {
			/* we couldn't get fcntl/flock - it's really locked */
			ctx->last_stale = TRUE;
			return FALSE;
		}
		(void)mbox_file_unlock(ctx->ibox);
	}
	ctx->last_stale = stale;

	index_storage_lock_notify(ctx->ibox, stale ?
				  MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE :
				  MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT,
				  secs_left);
	return TRUE;
}

int mbox_lock(struct index_mailbox *ibox, int lock_type,
	      unsigned int *lock_id_r)
{
	time_t max_wait_time;
	int ret;

	/* allow only unlock -> shared/exclusive or exclusive -> shared */
	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);
	i_assert(lock_type == F_RDLCK || ibox->mbox_lock_type != F_RDLCK);

	if (ibox->mbox_lock_type == lock_type) {
		ibox->mbox_locks++;
		return 1;
	}

        index_storage_lock_notify_reset(ibox);

	if (!lock_settings_initialized)
                mbox_init_lock_settings();

	max_wait_time = time(NULL) + lock_timeout;

	/* make .lock file first to protect overwriting the file */
	if (use_dotlock && ibox->mbox_dotlock.ino == 0) {
		struct dotlock_context ctx;

		ctx.ibox = ibox;
		ctx.lock_type = lock_type;
		ctx.last_stale = -1;

		ret = file_lock_dotlock(ibox->path, NULL,
					lock_type == F_RDLCK &&
					!use_read_dotlock, lock_timeout,
					dotlock_change_timeout, 0,
					dotlock_callback, &ctx,
					&ibox->mbox_dotlock);

		if (ret < 0) {
			mbox_set_syscall_error(ibox, "file_lock_dotlock()");
			return -1;
		}
		if (ret == 0) {
			mail_storage_set_error(ibox->box.storage,
				"Timeout while waiting for lock");
			return 0;
		}
	}

	ibox->mbox_lock_type = lock_type;
	ret = mbox_file_locks(ibox, ibox->mbox_lock_type, max_wait_time);
	if (ret <= 0) {
		(void)mbox_unlock_files(ibox);
		if (ret == 0) {
			mail_storage_set_error(ibox->box.storage,
				"Timeout while waiting for lock");
		}
		return ret;
	}

	*lock_id_r = ++ibox->mbox_lock_id;
	return 1;
}

static int mbox_unlock_files(struct index_mailbox *ibox)
{
	int ret = 0;

	if (ibox->mbox_fd != -1) {
		if (mbox_file_unlock(ibox) < 0)
			ret = -1;
	}

	if (ibox->mbox_dotlock.ino != 0) {
		if (file_unlock_dotlock(ibox->path, &ibox->mbox_dotlock) <= 0) {
			mbox_set_syscall_error(ibox, "file_unlock_dotlock()");
			ret = -1;
		}
                ibox->mbox_dotlock.ino = 0;
	}

	/* make sure we don't keep mmap() between locks */
	mbox_file_close_stream(ibox);

	ibox->mbox_lock_id++;
	ibox->mbox_lock_type = F_UNLCK;
	return ret;
}

int mbox_unlock(struct index_mailbox *ibox, unsigned int lock_id)
{
	i_assert(ibox->mbox_lock_id == lock_id);

	if (--ibox->mbox_locks > 0)
		return 0;

	return mbox_unlock_files(ibox);
}
