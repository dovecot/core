/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "maildir-storage.h"
#include "maildir-keywords.h"
#include "maildir-filename-flags.h"


void maildir_filename_flags_get(struct maildir_keywords_sync_ctx *ctx,
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

				array_push_back(keywords_r,
						(unsigned int *)&idx);
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
	unsigned int i, count;
	size_t start = str_len(fname);
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

static const char * ATTR_NULL(1, 4)
maildir_filename_flags_full_set(struct maildir_keywords_sync_ctx *ctx,
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

		if ((flags_left & MAIL_DRAFT) != 0 && nextflag > 'D') {
			str_append_c(flags_str, 'D');
			flags_left &= ~MAIL_DRAFT;
		}
		if ((flags_left & MAIL_FLAGGED) != 0 && nextflag > 'F') {
			str_append_c(flags_str, 'F');
			flags_left &= ~MAIL_FLAGGED;
		}
		if ((flags_left & MAIL_ANSWERED) != 0 && nextflag > 'R') {
			str_append_c(flags_str, 'R');
			flags_left &= ~MAIL_ANSWERED;
		}
		if ((flags_left & MAIL_SEEN) != 0 && nextflag > 'S') {
			str_append_c(flags_str, 'S');
			flags_left &= ~MAIL_SEEN;
		}
		if ((flags_left & MAIL_DELETED) != 0 && nextflag > 'T') {
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

const char *maildir_filename_flags_set(const char *fname, enum mail_flags flags)
{
	return maildir_filename_flags_full_set(NULL, fname, flags, NULL);
}

const char *maildir_filename_flags_kw_set(struct maildir_keywords_sync_ctx *ctx,
					  const char *fname, enum mail_flags flags,
					  ARRAY_TYPE(keyword_indexes) *keywords)
{
	return maildir_filename_flags_full_set(ctx, fname, flags, keywords);
}
