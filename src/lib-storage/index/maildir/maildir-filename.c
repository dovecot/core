/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "hostpid.h"
#include "maildir-storage.h"
#include "maildir-keywords.h"
#include "maildir-filename.h"

#include <stdlib.h>

const char *maildir_generate_tmp_filename(const struct timeval *tv)
{
	static unsigned int create_count = 0;
	static time_t first_stamp = 0;

	if (first_stamp == 0 || first_stamp == ioloop_time) {
		/* it's possible that within last second another process had
		   the same PID as us. Use usecs to make sure we don't create
		   duplicate base name. */
		first_stamp = ioloop_time;
		return t_strdup_printf("%s.P%sQ%uM%s.%s",
				       dec2str(tv->tv_sec), my_pid,
				       create_count++,
				       dec2str(tv->tv_usec), my_hostname);
	} else {
		/* Don't bother with usecs. Saves a bit space :) */
		return t_strdup_printf("%s.P%sQ%u.%s",
				       dec2str(tv->tv_sec), my_pid,
				       create_count++, my_hostname);
	}
}

int maildir_filename_get_flags(struct maildir_keywords_sync_ctx *ctx,
			       const char *fname, enum mail_flags *flags_r,
                               ARRAY_TYPE(keyword_indexes) *keywords_r)
{
	const char *info;

	array_clear(keywords_r);
	*flags_r = 0;

	info = strchr(fname, MAILDIR_INFO_SEP);
	if (info == NULL || info[1] != '2' || info[2] != MAILDIR_FLAGS_SEP)
		return 0;

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

	return 1;
}

static int char_cmp(const void *p1, const void *p2)
{
	const unsigned char *c1 = p1, *c2 = p2;

	return *c1 - *c2;
}

static void
maildir_filename_append_keywords(struct maildir_keywords_sync_ctx *ctx,
				 ARRAY_TYPE(keyword_indexes) *keywords,
				 string_t *str)
{
	const unsigned int *indexes;
	unsigned int i, count, start = str_len(str);
	char chr;

	indexes = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		chr = maildir_keywords_idx_char(ctx, indexes[i]);
		if (chr != '\0')
			str_append_c(str, chr);
	}

	qsort(str_c_modifiable(str) + start, str_len(str) - start, 1, char_cmp);
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
unsigned int maildir_hash(const void *p)
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

int maildir_cmp(const void *p1, const void *p2)
{
	const char *s1 = p1, *s2 = p2;

	while (*s1 == *s2 && *s1 != MAILDIR_INFO_SEP && *s1 != '\0') {
		i_assert(*s1 != '/');
		s1++; s2++;
	}
	if ((*s1 == '\0' || *s1 == MAILDIR_INFO_SEP) &&
	    (*s2 == '\0' || *s2 == MAILDIR_INFO_SEP))
		return 0;
	return *s1 - *s2;
}
