/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "maildir-index.h"

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

/* Clean files from tmp/ if they're older than 36 hours */
#define MAILDIR_CLEANUP_TIME (60 * 60 * 36)

void maildir_clean_tmp(const char *dir)
{
	time_t cleanup_time = ioloop_time - MAILDIR_CLEANUP_TIME;
	DIR *dirp;
	struct dirent *d;
	struct stat st;
	const char *path;

	dirp = opendir(dir);
	if (dirp == NULL) {
		i_error("opendir(%s) failed: %m", dir);
		return;
	}

	while ((d = readdir(dirp)) != NULL) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;

		t_push();
		path = t_strconcat(dir, "/", d->d_name, NULL);
		if (stat(path, &st) < 0) {
			if (errno != ENOENT)
				i_error("stat(%s) failed: %m", path);
		} else if (st.st_mtime < cleanup_time &&
			   st.st_atime < cleanup_time &&
			   !S_ISDIR(st.st_mode)) {
			if (unlink(path) < 0 && errno != ENOENT)
				i_error("unlink(%s) failed: %m", path);
		}
		t_pop();
	}

	if (closedir(dirp) < 0)
		i_error("closedir(%s) failed: %m", dir);
}
