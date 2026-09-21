/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "istream.h"
#include "file-lock-proc.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

const char *file_lock_proc_find(int lock_fd ATTR_UNUSED)
{
	/* do anything except Linux support this? don't bother trying it for
	   OSes we don't know about. */
#ifdef __linux__
	static bool have_proc_locks = TRUE;
	struct stat st;
	char node_buf[MAX_INT_STRLEN * 3 + 2];
	struct istream *input;
	const char *line, *lock_type = "";
	pid_t pid = 0;
	int fd;

	if (!have_proc_locks)
		return "";

	if (fstat(lock_fd, &st) < 0)
		return "";
	i_snprintf(node_buf, sizeof(node_buf), "%02x:%02x:%llu",
		   major(st.st_dev), minor(st.st_dev),
		   (unsigned long long)st.st_ino);
	fd = open("/proc/locks", O_RDONLY);
	if (fd == -1) {
		have_proc_locks = FALSE;
		return "";
	}
	input = i_stream_create_fd_autoclose(&fd, 512);
	while (pid == 0 && (line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		const char *const *args = t_strsplit_spaces(line, " ");

		/* number: FLOCK/POSIX ADVISORY READ/WRITE pid
		   major:minor:inode region-start region-end */
		if (str_array_length(args) < 8) {
			; /* don't continue from within a T_BEGIN {...} T_END */
		} else if (strcmp(args[5], node_buf) == 0) {
			lock_type = strcmp(args[3], "READ") == 0 ?
				"READ" : "WRITE";
			if (str_to_pid(args[4], &pid) < 0)
				pid = 0;
		}
	} T_END;
	i_stream_destroy(&input);
	if (pid == 0) {
		/* not found */
		return "";
	}
	if (pid == getpid())
		return " (BUG: lock is held by our own process)";
	return t_strdup_printf(" (%s lock held by pid %ld)", lock_type, (long)pid);
#else
	return "";
#endif
}
