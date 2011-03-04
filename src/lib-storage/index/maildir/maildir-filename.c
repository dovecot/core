/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "time-util.h"
#include "hostpid.h"
#include "maildir-storage.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"

#include <stdlib.h>

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

void maildir_filename_get_flags(struct maildir_keywords_sync_ctx *ctx,
				const char *fname, enum mail_flags *flags_r,
				ARRAY_TYPE(keyword_indexes) *keywords_r)
{
	const char *info;

	array_clear(keywords_r);
	*flags_r = 0;

	info = strrchr(fname, MAILDIR_INFO_SEP);
	if (info == NULL || info[1] != '2' || info[2] != MAILDIR_FLAGS_SEP)
		return;

	for (info += 3; *info != '\0' && *info != MAILDIR_FLAGS_SEP; info++) {
		switch (*info) {
		case 'R': /* replied */
			*flags_r |= MAIL_ANSWERED;
			break;
		case 'S': /* seen */
			*flags_r |= MAIL_SEEN;
			break;
		case 'T': /* trashed */
			*flags_r |= MAIL_DELETED;
			break;
		case 'D': /* draft */
			*flags_r |= MAIL_DRAFT;
			break;
		case 'F': /* flagged */
			*flags_r |= MAIL_FLAGGED;
			break;
		default:
			if (*info >= MAILDIR_KEYWORD_FIRST &&
			    *info <= MAILDIR_KEYWORD_LAST) {
				int idx;

				idx = maildir_keywords_char_idx(ctx, *info);
				if (idx < 0) {
					/* unknown keyword. */
					break;
				}

				array_append(keywords_r,
					     (unsigned int *)&idx, 1);
				break;
			}

			/* unknown flag - ignore */
			break;
		}
	}
}

static int char_cmp(const void *p1, const void *p2)
{
	const unsigned char *c1 = p1, *c2 = p2;

	return *c1 - *c2;
}

static void
maildir_filename_append_keywords(struct maildir_keywords_sync_ctx *ctx,
				 ARRAY_TYPE(keyword_indexes) *keywords,
				 string_t *fname)
{
	const unsigned int *indexes;
	unsigned int i, count, start = str_len(fname);
	char chr;

	indexes = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		chr = maildir_keywords_idx_char(ctx, indexes[i]);
		if (chr != '\0')
			str_append_c(fname, chr);
	}

	qsort(str_c_modifiable(fname) + start, str_len(fname) - start, 1,
	      char_cmp);
}

const char *maildir_filename_set_flags(struct maildir_keywords_sync_ctx *ctx,
				       const char *fname, enum mail_flags flags,
				       ARRAY_TYPE(keyword_indexes) *keywords)
{
	string_t *flags_str;
	enum mail_flags flags_left;
	const char *info, *oldflags;
	int nextflag;

	/* remove the old :info from file name, and get the old flags */
	info = strrchr(fname, MAILDIR_INFO_SEP);
	if (info != NULL && strrchr(fname, '/') > info)
		info = NULL;

	oldflags = "";
	if (info != NULL) {
		fname = t_strdup_until(fname, info);
		if (info[1] == '2' && info[2] == MAILDIR_FLAGS_SEP)
			oldflags = info+3;
	}

	/* insert the new flags between old flags. flags must be sorted by
	   their ASCII code. unknown flags are kept. */
	flags_str = t_str_new(256);
	str_append(flags_str, fname);
	str_append(flags_str, MAILDIR_FLAGS_FULL_SEP);
	flags_left = flags;
	for (;;) {
		/* skip all known flags */
		while (*oldflags == 'D' || *oldflags == 'F' ||
		       *oldflags == 'R' || *oldflags == 'S' ||
		       *oldflags == 'T' ||
		       (*oldflags >= MAILDIR_KEYWORD_FIRST &&
			*oldflags <= MAILDIR_KEYWORD_LAST))
			oldflags++;

		nextflag = *oldflags == '\0' || *oldflags == MAILDIR_FLAGS_SEP ?
			256 : (unsigned char) *oldflags;

		if ((flags_left & MAIL_DRAFT) && nextflag > 'D') {
			str_append_c(flags_str, 'D');
			flags_left &= ~MAIL_DRAFT;
		}
		if ((flags_left & MAIL_FLAGGED) && nextflag > 'F') {
			str_append_c(flags_str, 'F');
			flags_left &= ~MAIL_FLAGGED;
		}
		if ((flags_left & MAIL_ANSWERED) && nextflag > 'R') {
			str_append_c(flags_str, 'R');
			flags_left &= ~MAIL_ANSWERED;
		}
		if ((flags_left & MAIL_SEEN) && nextflag > 'S') {
			str_append_c(flags_str, 'S');
			flags_left &= ~MAIL_SEEN;
		}
		if ((flags_left & MAIL_DELETED) && nextflag > 'T') {
			str_append_c(flags_str, 'T');
			flags_left &= ~MAIL_DELETED;
		}

		if (keywords != NULL && array_is_created(keywords) &&
		    nextflag > MAILDIR_KEYWORD_FIRST) {
			maildir_filename_append_keywords(ctx, keywords,
							 flags_str);
			keywords = NULL;
		}

		if (*oldflags == '\0' || *oldflags == MAILDIR_FLAGS_SEP)
			break;

		str_append_c(flags_str, *oldflags);
		oldflags++;
	}

	if (*oldflags == MAILDIR_FLAGS_SEP) {
		/* another flagset, we don't know about these, just keep them */
		while (*oldflags != '\0')
			str_append_c(flags_str, *oldflags++);
	}

	return str_c(flags_str);
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
unsigned int maildir_filename_base_hash(const void *p)
{
        const unsigned char *s = p;
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

int maildir_filename_base_cmp(const void *p1, const void *p2)
{
	const char *fname1 = p1, *fname2 = p2;

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
