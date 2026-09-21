/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "file-lock-proc.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Maximum number of locks parsed from /proc/locks. This is just a sanity
   limit to avoid using a lot of memory on a system with a huge number of
   locks. */
#define PROC_LOCKS_MAX_COUNT 100000
/* Maximum length of a single /proc/locks line. */
#define PROC_LOCKS_MAX_LINE_LEN 512
/* Maximum number of lock holders described in the returned string. */
#define PROC_LOCKS_MAX_REPORT_COUNT 10

static int proc_lock_parse_id(const char *str, unsigned int *id_r)
{
	const char *endp;

	/* "123:" */
	if (str_parse_uint(str, id_r, &endp) < 0)
		return -1;
	return strcmp(endp, ":") == 0 ? 0 : -1;
}

/* Indexed by enum proc_lock_class. NULL for the classes that aren't written
   to /proc/locks. */
static const char *const proc_lock_class_names[] = {
	NULL,
	"POSIX",
	"FLOCK",
	"OFDLCK",
};
static_assert_array_size(proc_lock_class_names, PROC_LOCK_CLASS_COUNT);

static void
proc_lock_parse_class(const char *str, enum proc_lock_class *lock_class_r)
{
	for (unsigned int i = 0; i < N_ELEMENTS(proc_lock_class_names); i++) {
		if (proc_lock_class_names[i] != NULL &&
		    strcmp(proc_lock_class_names[i], str) == 0) {
			*lock_class_r = (enum proc_lock_class)i;
			return;
		}
	}
	*lock_class_r = PROC_LOCK_CLASS_UNKNOWN;
}

static int proc_lock_parse_pid(const char *str, pid_t *pid_r)
{
	/* The kernel writes -1 for OFD locks, which str_to_pid() doesn't
	   accept. It writes 0 if the owner isn't visible in our PID
	   namespace. */
	if (strcmp(str, "-1") == 0) {
		*pid_r = -1;
		return 0;
	}
	return str_to_pid(str, pid_r);
}

static int proc_lock_parse_node(const char *str, struct proc_lock *lock)
{
	const char *const *args = t_strsplit(str, ":");

	/* "major:minor:inode", with major and minor in hex. The kernel
	   writes "<none>:0" for locks that have no inode. */
	if (str_array_length(args) != 3)
		return -1;
	if (str_to_uint_hex(args[0], &lock->dev_major) < 0 ||
	    str_to_uint_hex(args[1], &lock->dev_minor) < 0 ||
	    str_to_ino(args[2], &lock->ino) < 0)
		return -1;
	return 0;
}

static int proc_lock_parse_range(const char *start, const char *end,
				 struct proc_lock *lock)
{
	if (str_to_uoff(start, &lock->start) < 0)
		return -1;
	if (strcmp(end, "EOF") == 0)
		lock->end = UOFF_T_MAX;
	else if (str_to_uoff(end, &lock->end) < 0)
		return -1;
	return 0;
}

int file_lock_proc_parse_line(const char *line, struct proc_lock *lock_r)
{
	const char *const *args = t_strsplit_spaces(line, " ");
	struct proc_lock lock;

	i_zero(&lock);
	/* "id: [-> ]POSIX/FLOCK/OFDLCK ADVISORY/... READ/WRITE pid
	   major:minor:inode range-start range-end". A lock that is still
	   waiting to be granted is written with a "->" prefix and with the
	   id of the lock that is blocking it. */
	if (str_array_length(args) < 1)
		return -1;
	if (proc_lock_parse_id(args[0], &lock.id) < 0)
		return -1;
	args++;

	if (args[0] != NULL && strcmp(args[0], "->") == 0) {
		lock.waiter = TRUE;
		args++;
	}
	if (str_array_length(args) < 7)
		return -1;

	proc_lock_parse_class(args[0], &lock.lock_class);
	lock.write = strcmp(args[2], "READ") != 0;
	if (proc_lock_parse_pid(args[3], &lock.pid) < 0 ||
	    proc_lock_parse_node(args[4], &lock) < 0 ||
	    proc_lock_parse_range(args[5], args[6], &lock) < 0)
		return -1;

	*lock_r = lock;
	return 0;
}

int file_lock_proc_parse(struct istream *input, ARRAY_TYPE(proc_lock) *locks)
{
	const char *line;
	struct proc_lock lock;
	bool parsed;

	while (array_count(locks) < PROC_LOCKS_MAX_COUNT &&
	       (line = i_stream_read_next_line(input)) != NULL) {
		T_BEGIN {
			parsed = file_lock_proc_parse_line(line, &lock) == 0;
		} T_END;
		if (parsed)
			array_push_back(locks, &lock);
	}
	return input->stream_errno == 0 ? 0 : -1;
}

static int proc_locks_read(ARRAY_TYPE(proc_lock) *locks)
{
	struct istream *input;
	int fd, ret;

	fd = open("/proc/locks", O_RDONLY);
	if (fd == -1)
		return -1;

	input = i_stream_create_fd_autoclose(&fd, PROC_LOCKS_MAX_LINE_LEN);
	ret = file_lock_proc_parse(input, locks);
	i_stream_destroy(&input);
	return ret;
}

static bool
proc_lock_class_matches(enum proc_lock_class lock_class,
			enum file_lock_method lock_method)
{
	switch (lock_method) {
	case FILE_LOCK_METHOD_FCNTL:
		/* OFD locks conflict with POSIX record locks */
		return lock_class == PROC_LOCK_CLASS_POSIX ||
			lock_class == PROC_LOCK_CLASS_OFD;
	case FILE_LOCK_METHOD_FLOCK:
		return lock_class == PROC_LOCK_CLASS_FLOCK;
	case FILE_LOCK_METHOD_DOTLOCK:
		/* dotlocks don't show up in /proc/locks */
		break;
	}
	return FALSE;
}

static bool
proc_lock_type_conflicts(const struct proc_lock *lock, int lock_type)
{
	/* two read locks never conflict with each other */
	return lock->write || lock_type != F_RDLCK;
}

static bool
proc_lock_range_conflicts(const struct proc_lock *lock,
			  uoff_t start, uoff_t end)
{
	/* the ranges are inclusive */
	return lock->start <= end && start <= lock->end;
}

static bool proc_lock_match_node(const struct proc_lock *lock,
				 const struct stat *st)
{
	return lock->dev_major == major(st->st_dev) &&
		lock->dev_minor == minor(st->st_dev) &&
		lock->ino == st->st_ino;
}

static bool
proc_lock_conflicts(const struct proc_lock *lock, const struct stat *st,
		    enum file_lock_method lock_method, int lock_type,
		    uoff_t start, uoff_t end)
{
	if (lock->waiter || lock->pid <= 0)
		return FALSE;

	return proc_lock_class_matches(lock->lock_class, lock_method) &&
		proc_lock_type_conflicts(lock, lock_type) &&
		proc_lock_range_conflicts(lock, start, end) &&
		proc_lock_match_node(lock, st);
}

static void
proc_lock_append_description(string_t *str, const struct proc_lock *lock)
{
	str_printfa(str, "%s lock held by pid %ld",
		    lock->write ? "WRITE" : "READ", (long)lock->pid);
	if (lock->pid == getpid())
		str_append(str, " (BUG: this is our own process)");
}

const char *file_lock_proc_find(int lock_fd ATTR_UNUSED,
				enum file_lock_method lock_method ATTR_UNUSED,
				int lock_type ATTR_UNUSED,
				uoff_t start ATTR_UNUSED,
				uoff_t len ATTR_UNUSED)
{
	/* do anything except Linux support this? don't bother trying it for
	   OSes we don't know about. */
#ifdef __linux__
	static bool have_proc_locks = TRUE;
	ARRAY_TYPE(proc_lock) locks;
	const struct proc_lock *lock;
	struct stat st;
	string_t *str;
	unsigned int count = 0;
	uoff_t end = len == 0 ? UOFF_T_MAX : start + len - 1;

	if (!have_proc_locks)
		return "";
	if (fstat(lock_fd, &st) < 0)
		return "";

	i_array_init(&locks, 64);
	if (proc_locks_read(&locks) < 0 && array_count(&locks) == 0) {
		have_proc_locks = FALSE;
		array_free(&locks);
		return "";
	}

	str = t_str_new(64);
	array_foreach(&locks, lock) {
		if (!proc_lock_conflicts(lock, &st, lock_method, lock_type,
					 start, end))
			continue;
		if (count == PROC_LOCKS_MAX_REPORT_COUNT) {
			str_append(str, ", ...");
			break;
		}
		str_append(str, count == 0 ? " (" : ", ");
		proc_lock_append_description(str, lock);
		count++;
	}
	array_free(&locks);
	if (count == 0)
		return "";
	str_append_c(str, ')');
	return str_c(str);
#else
	return "";
#endif
}
