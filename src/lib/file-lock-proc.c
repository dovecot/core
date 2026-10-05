/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "path-util.h"
#include "istream.h"
#include "file-lock-proc.h"

#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

/* Maximum number of locks parsed from /proc/locks. This is just a sanity
   limit to avoid using a lot of memory on a system with a huge number of
   locks. */
#define PROC_LOCKS_MAX_COUNT 100000
/* Maximum length of a single /proc/locks line. */
#define PROC_LOCKS_MAX_LINE_LEN 512
/* Maximum number of lock holders described in the returned string. */
#define PROC_LOCKS_MAX_REPORT_COUNT 10
/* Maximum number of lock waiters followed while looking for a deadlock. */
#define PROC_LOCKS_MAX_DEADLOCK_DEPTH 16

ARRAY_DEFINE_TYPE(proc_lock_p, const struct proc_lock *);

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
	i_assert(args[0] != NULL);

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

static const struct proc_lock *
proc_locks_find_holder(const ARRAY_TYPE(proc_lock) *locks, unsigned int id)
{
	const struct proc_lock *lock;

	/* The kernel writes a waiting lock request with the id of the lock
	   that is blocking it. */
	array_foreach(locks, lock) {
		if (lock->id == id && !lock->waiter)
			return lock;
	}
	return NULL;
}

static bool
proc_locks_walk_waiters(const ARRAY_TYPE(proc_lock) *locks, pid_t pid,
			pid_t target_pid, unsigned int depth,
			ARRAY_TYPE(proc_lock_link) *chain)
{
	const struct proc_lock *waiter, *holder;
	struct proc_lock_link link;

	if (depth >= PROC_LOCKS_MAX_DEADLOCK_DEPTH)
		return FALSE;

	array_foreach(locks, waiter) {
		if (!waiter->waiter || waiter->pid != pid)
			continue;
		holder = proc_locks_find_holder(locks, waiter->id);
		if (holder == NULL || holder->pid <= 0)
			continue;

		link.waiter = waiter;
		link.holder = holder;
		array_push_back(chain, &link);
		if (holder->pid == target_pid)
			return TRUE;
		/* holder->pid == pid would be a deadlock within that process
		   alone - not the one we're looking for. */
		if (holder->pid != pid &&
		    proc_locks_walk_waiters(locks, holder->pid, target_pid,
					    depth + 1, chain))
			return TRUE;
		array_delete(chain, array_count(chain) - 1, 1);
	}
	return FALSE;
}

bool file_lock_proc_find_deadlock(const ARRAY_TYPE(proc_lock) *locks,
				  pid_t pid, pid_t target_pid,
				  ARRAY_TYPE(proc_lock_link) *chain)
{
	return proc_locks_walk_waiters(locks, pid, target_pid, 0, chain);
}

/* Returns the process name from /proc/<pid>/comm, or NULL if it can't be
   read. */
static const char *proc_lock_get_process_name(pid_t pid)
{
	char buf[64];
	const char *path;
	ssize_t ret;
	int fd;

	path = t_strdup_printf("/proc/%ld/comm", (long)pid);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return NULL;
	ret = read(fd, buf, sizeof(buf) - 1);
	i_close_fd(&fd);
	if (ret <= 0)
		return NULL;
	buf[ret] = '\0';
	/* t_strcut() returns buf itself if there is no newline */
	return t_strdup(t_strcut(buf, '\n'));
}

static void proc_lock_append_pid(string_t *str, pid_t pid)
{
	const char *name = proc_lock_get_process_name(pid);

	str_printfa(str, "pid %ld", (long)pid);
	if (name != NULL && name[0] != '\0')
		str_printfa(str, " (%s)", str_sanitize(name, 32));
}

/* Returns the path of the file that pid has locked, or NULL if it can't be
   found. This requires being able to read the other process's /proc/<pid>/fd,
   which typically works only within the same UID. */
static const char *
proc_lock_find_path(pid_t pid, const struct proc_lock *lock)
{
	const char *dir_path, *dest, *error;
	const struct dirent *d;
	struct stat st;
	string_t *path;
	size_t prefix_len;
	DIR *dir;

	if (pid <= 0)
		return NULL;
	dir_path = t_strdup_printf("/proc/%ld/fd", (long)pid);
	dir = opendir(dir_path);
	if (dir == NULL)
		return NULL;

	path = t_str_new(64);
	str_printfa(path, "%s/", dir_path);
	prefix_len = str_len(path);

	dest = NULL;
	for (errno = 0; dest == NULL && (d = readdir(dir)) != NULL; errno = 0) {
		if (d->d_name[0] == '.')
			continue;
		str_truncate(path, prefix_len);
		str_append(path, d->d_name);
		if (stat(str_c(path), &st) < 0 ||
		    !proc_lock_match_node(lock, &st))
			continue;
		if (t_readlink(str_c(path), &dest, &error) < 0)
			dest = NULL;
	}
	if (errno != 0)
		i_error("readdir(%s) failed: %m", dir_path);
	if (closedir(dir) < 0)
		i_error("closedir(%s) failed: %m", dir_path);
	return dest;
}

static void
proc_lock_append_file(string_t *str, pid_t pid, const struct proc_lock *lock)
{
	const char *path = proc_lock_find_path(pid, lock);

	if (path != NULL)
		str_append(str, str_sanitize(path, 256));
	else {
		str_printfa(str, "device %02x:%02x inode %llu",
			    lock->dev_major, lock->dev_minor,
			    (unsigned long long)lock->ino);
	}
}

static void
proc_locks_append_deadlock(string_t *str,
			   const ARRAY_TYPE(proc_lock_link) *chain,
			   int lock_fd, int lock_type,
			   const struct proc_lock *holder)
{
	const struct proc_lock_link *link;
	const char *path, *error;

	str_append(str, " - Possible deadlock: ");
	proc_lock_append_pid(str, getpid());
	str_printfa(str, " is waiting for a %s lock on ",
		    lock_type == F_RDLCK ? "READ" : "WRITE");
	if (t_readlink(t_strdup_printf("/proc/self/fd/%d", lock_fd),
		       &path, &error) == 0)
		str_append(str, str_sanitize(path, 256));
	else
		proc_lock_append_file(str, getpid(), holder);
	str_append(str, " held by ");
	proc_lock_append_pid(str, holder->pid);

	array_foreach(chain, link) {
		str_printfa(str, ", which is waiting for a %s lock on ",
			    link->waiter->write ? "WRITE" : "READ");
		proc_lock_append_file(str, link->waiter->pid, link->waiter);
		str_append(str, " held by ");
		proc_lock_append_pid(str, link->holder->pid);
	}
}

static bool
proc_lock_conflicts(const struct proc_lock *lock, const struct stat *st,
		    enum file_lock_method lock_method, int lock_type,
		    uoff_t start, uoff_t end)
{
	if (lock->waiter)
		return FALSE;

	return proc_lock_class_matches(lock->lock_class, lock_method) &&
		proc_lock_type_conflicts(lock, lock_type) &&
		proc_lock_range_conflicts(lock, start, end) &&
		proc_lock_match_node(lock, st);
}

static void
proc_lock_append_description(string_t *str, const struct proc_lock *lock)
{
	const char *type = lock->write ? "WRITE" : "READ";

	if (lock->pid > 0) {
		str_printfa(str, "%s lock held by ", type);
		proc_lock_append_pid(str, lock->pid);
		if (lock->pid == getpid())
			str_append(str, " (BUG: this is our own process)");
	} else if (lock->pid == 0) {
		/* The kernel writes 0 if the owner isn't visible in our PID
		   namespace, or if the owner process is already gone. */
		str_printfa(str,
			    "%s lock held by an unknown process (another PID namespace?)",
			    type);
	} else {
		/* The kernel writes -1 for open file description locks,
		   which aren't owned by any specific process. */
		str_printfa(str,
			    "%s open file description lock held by an unknown process",
			    type);
	}
}

static void
proc_locks_append_holders(string_t *str,
			  const ARRAY_TYPE(proc_lock_p) *holders)
{
	const struct proc_lock *lock;
	unsigned int count = 0;

	array_foreach_elem(holders, lock) {
		if (count == PROC_LOCKS_MAX_REPORT_COUNT) {
			str_append(str, ", ...");
			break;
		}
		str_append(str, count == 0 ? " (" : ", ");
		proc_lock_append_description(str, lock);
		count++;
	}
	str_append_c(str, ')');
}

static void
proc_locks_append_any_deadlock(string_t *str,
			       const ARRAY_TYPE(proc_lock) *locks,
			       const ARRAY_TYPE(proc_lock_p) *holders,
			       int lock_fd, int lock_type)
{
	ARRAY_TYPE(proc_lock_link) chain;
	const struct proc_lock *holder;

	t_array_init(&chain, 8);
	array_foreach_elem(holders, holder) {
		if (holder->pid <= 0)
			continue;
		array_clear(&chain);
		if (file_lock_proc_find_deadlock(locks, holder->pid, getpid(),
						 &chain)) {
			proc_locks_append_deadlock(str, &chain, lock_fd,
						   lock_type, holder);
			break;
		}
	}
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
	ARRAY_TYPE(proc_lock_p) holders;
	const struct proc_lock *lock;
	struct stat st;
	string_t *str;
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

	t_array_init(&holders, 8);
	array_foreach(&locks, lock) {
		if (proc_lock_conflicts(lock, &st, lock_method, lock_type,
					start, end))
			array_push_back(&holders, &lock);
	}
	if (array_count(&holders) == 0) {
		array_free(&locks);
		return "";
	}

	str = t_str_new(128);
	proc_locks_append_holders(str, &holders);
	proc_locks_append_any_deadlock(str, &locks, &holders,
				       lock_fd, lock_type);
	array_free(&locks);
	return str_c(str);
#else
	return "";
#endif
}
