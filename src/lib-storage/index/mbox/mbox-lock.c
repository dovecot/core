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
#define DEFAULT_READ_LOCK_METHODS "fcntl"
#define DEFAULT_WRITE_LOCK_METHODS "dotlock fcntl"
/* lock timeout */
#define DEFAULT_LOCK_TIMEOUT 300
/* assume stale dotlock if mbox file hasn't changed for n seconds */
#define DEFAULT_DOTLOCK_CHANGE_TIMEOUT 30

struct dotlock_context {
        struct index_mailbox *ibox;
        int lock_type;
	int last_stale;
};

enum mbox_lock_type {
	MBOX_LOCK_DOTLOCK,
	MBOX_LOCK_FCNTL,
	MBOX_LOCK_FLOCK,
	MBOX_LOCK_LOCKF,

	MBOX_LOCK_COUNT
};

struct mbox_lock_data {
	enum mbox_lock_type type;
	const char *name;
	int (*func)(struct index_mailbox *ibox, int lock_type,
		    time_t max_wait_time);
};

static int mbox_lock_fcntl(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time);
#ifdef HAVE_FLOCK
static int mbox_lock_flock(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time);
#else
#  define mbox_lock_flock NULL
#endif
#ifdef HAVE_LOCKF
static int mbox_lock_lockf(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time);
#else
#  define mbox_lock_lockf NULL
#endif

struct mbox_lock_data lock_data[] = {
	{ MBOX_LOCK_DOTLOCK, "dotlock", NULL },
	{ MBOX_LOCK_FCNTL, "fcntl", mbox_lock_fcntl },
	{ MBOX_LOCK_FLOCK, "flock", mbox_lock_flock },
	{ MBOX_LOCK_LOCKF, "lockf", mbox_lock_lockf },
	{ 0, NULL, NULL }
};

static int lock_settings_initialized = FALSE;
static enum mbox_lock_type read_locks[MBOX_LOCK_COUNT+1];
static enum mbox_lock_type write_locks[MBOX_LOCK_COUNT+1];
static int lock_timeout, dotlock_change_timeout;

static int mbox_unlock_files(struct index_mailbox *ibox);

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
		if (lock_data[type].func == NULL && type != MBOX_LOCK_DOTLOCK) {
			i_fatal("%s: Support for lock type %s "
				"not compiled into binary", env, *lock);
		}

		for (i = 0; i < dest; i++) {
			if (locks[i] == type)
				i_fatal("%s: Duplicated value %s", env, *lock);
		}

		if (type == MBOX_LOCK_DOTLOCK && dest != 0)
			i_fatal("%s: dotlock must be first in the list", *lock);

		/* @UNSAFE */
		locks[dest++] = type;
	}
	locks[dest] = (enum mbox_lock_type)-1;
}

static void mbox_init_lock_settings(void)
{
	const char *str;

	str = getenv("MBOX_READ_LOCKS");
	if (str == NULL) str = DEFAULT_READ_LOCK_METHODS;
	mbox_read_lock_methods(str, "MBOX_READ_LOCKS", read_locks);

	str = getenv("MBOX_WRITE_LOCKS");
	if (str == NULL) str = DEFAULT_WRITE_LOCK_METHODS;
	mbox_read_lock_methods(str, "MBOX_WRITE_LOCKS", write_locks);

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

#ifdef HAVE_LOCKF
static int mbox_lock_lockf(struct index_mailbox *ibox, int lock_type,
			   time_t max_wait_time)
{
	time_t now, last_notify;

	if (lock_type != F_UNLCK)
		lock_type = F_TLOCK;
	else
		lock_type = F_ULOCK;

        last_notify = 0;
	while (lockf(ibox->mbox_fd, lock_type, 0) < 0) {
		if (errno != EAGAIN) {
			mbox_set_syscall_error(ibox, "lockf()");
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
	enum mbox_lock_type *lock_types;
	struct stat st;
	int i, ret;

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

	lock_types = lock_type == F_WRLCK ? write_locks : read_locks;
	for (i = 0; lock_types[i] != (enum mbox_lock_type)-1; i++) {
		if (lock_data[lock_types[i]].type != MBOX_LOCK_DOTLOCK) {
			ret = lock_data[lock_types[i]].func(ibox, lock_type,
							    max_wait_time);
			if (ret <= 0)
				return ret;
		}
	}
	return 1;
}

static int mbox_file_unlock(struct index_mailbox *ibox)
{
	enum mbox_lock_type *lock_types;
	int i, ret = 0;

	lock_types = ibox->mbox_lock_type == F_WRLCK ? write_locks : read_locks;
	for (i = 0; lock_types[i] != (enum mbox_lock_type)-1; i++) {
		if (lock_data[lock_types[i]].type != MBOX_LOCK_DOTLOCK) {
			if (lock_data[lock_types[i]].func(ibox, F_UNLCK, 0) < 0)
				ret = -1;
		}
	}

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
	if (((lock_type == F_RDLCK && read_locks[0] == MBOX_LOCK_DOTLOCK) ||
	     (lock_type == F_WRLCK && write_locks[0] == MBOX_LOCK_DOTLOCK)) &&
	    ibox->mbox_dotlock.ino == 0) {
		struct dotlock_context ctx;

		ctx.ibox = ibox;
		ctx.lock_type = lock_type;
		ctx.last_stale = -1;

		ret = file_lock_dotlock(ibox->path, NULL, FALSE, lock_timeout,
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
	ibox->mbox_locks++;
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
