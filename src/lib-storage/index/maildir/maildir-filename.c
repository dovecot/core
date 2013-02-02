/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "hostpid.h"
#include "maildir-storage.h"
#include "maildir-filename.h"

const char *maildir_filename_generate(void)
{
	static struct timeval last_tv = { 0, 0 };
	struct timeval tv;

	/* use secs + usecs to guarantee uniqueness within this process. */
	if (timeval_cmp(&ioloop_timeval, &last_tv) > 0)
		tv = ioloop_timeval;
	else {
		tv = last_tv;
		if (++tv.tv_usec == 1000000) {
			tv.tv_sec++;
			tv.tv_usec = 0;
		}
	}
	last_tv = tv;

	return t_strdup_printf("%s.M%sP%s.%s",
			       dec2str(tv.tv_sec), dec2str(tv.tv_usec),
			       my_pid, my_hostname);
}

bool maildir_filename_get_size(const char *fname, char type, uoff_t *size_r)
{
	uoff_t size = 0;

	for (; *fname != '\0'; fname++) {
		i_assert(*fname != '/');
		if (*fname == ',' && fname[1] == type && fname[2] == '=') {
			fname += 3;
			break;
		}
	}

	if (*fname == '\0')
		return FALSE;

	while (*fname >= '0' && *fname <= '9') {
		size = size * 10 + (*fname - '0');
		fname++;
	}

	if (*fname != MAILDIR_INFO_SEP &&
	    *fname != MAILDIR_EXTRA_SEP &&
	    *fname != '\0')
		return FALSE;

	*size_r = size;
	return TRUE;
}

/* a char* hash function from ASU -- from glib */
unsigned int maildir_filename_base_hash(const char *s)
{
	unsigned int g, h = 0;

	while (*s != MAILDIR_INFO_SEP && *s != '\0') {
		i_assert(*s != '/');
		h = (h << 4) + *s;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}

		s++;
	}

	return h;
}

int maildir_filename_base_cmp(const char *fname1, const char *fname2)
{
	while (*fname1 == *fname2 && *fname1 != MAILDIR_INFO_SEP &&
	       *fname1 != '\0') {
		i_assert(*fname1 != '/');
		fname1++; fname2++;
	}

	if ((*fname1 == '\0' || *fname1 == MAILDIR_INFO_SEP) &&
	    (*fname2 == '\0' || *fname2 == MAILDIR_INFO_SEP))
		return 0;
	return *fname1 - *fname2;
}

static bool maildir_fname_get_usecs(const char *fname, int *usecs_r)
{
	int usecs = 0;

	/* Assume we already read the timestamp. Next up is
	   ".<uniqueness>.<host>". Find usecs inside the uniqueness. */
	if (*fname != '.')
		return FALSE;

	fname++;
	while (*fname != '\0' && *fname != '.' && *fname != MAILDIR_INFO_SEP) {
		if (*fname++ == 'M') {
			while (*fname >= '0' && *fname <= '9') {
				usecs = usecs * 10 + (*fname - '0');
				fname++;
			}
			*usecs_r = usecs;
			return TRUE;
		}
	}
	return FALSE;
}

int maildir_filename_sort_cmp(const char *fname1, const char *fname2)
{
	const char *s1, *s2;
	time_t secs1 = 0, secs2 = 0;
	int ret, usecs1, usecs2;

	/* sort primarily by the timestamp in file name */
	for (s1 = fname1; *s1 >= '0' && *s1 <= '9'; s1++)
		secs1 = secs1 * 10 + (*s1 - '0');
	for (s2 = fname2; *s2 >= '0' && *s2 <= '9'; s2++)
		secs2 = secs2 * 10 + (*s2 - '0');

	ret = (int)((long)secs1 - (long)secs2);
	if (ret == 0) {
		/* sort secondarily by microseconds, if they exist */
		if (maildir_fname_get_usecs(s1, &usecs1) &&
		    maildir_fname_get_usecs(s2, &usecs2))
			ret = usecs1 - usecs2;

		if (ret == 0) {
			/* fallback to comparing the base file name */
			ret = maildir_filename_base_cmp(s1, s2);
		}
	}
	return ret;
}
