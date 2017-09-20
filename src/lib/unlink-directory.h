#ifndef UNLINK_DIRECTORY_H
#define UNLINK_DIRECTORY_H

enum unlink_directory_flags {
	/* After unlinking all files, rmdir() the directory itself */
	UNLINK_DIRECTORY_FLAG_RMDIR		= 0x01,
	/* Don't unlink any files beginning with "." */
	UNLINK_DIRECTORY_FLAG_SKIP_DOTFILES	= 0x02,
	/* Don't recurse into subdirectories */
	UNLINK_DIRECTORY_FLAG_FILES_ONLY	= 0x04
};

/* Unlink directory and/or everything under it.
   Returns 1 if successful, 0 if error is ENOENT, -1 if other error.
   The returned error message contains the exact syscall that failed,
   e.g. "open(path) failed: Permission denied"
   In case of ENOENT error, error message is also set. */
int unlink_directory(const char *dir, enum unlink_directory_flags flags,
		     const char **error_r);

#endif
