/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>

extern MailIndex maildir_index;

MailFlags maildir_filename_get_flags(const char *fname, MailFlags default_flags)
{
	const char *info;
	MailFlags flags;

	info = strchr(fname, ':');
	if (info == NULL || info[1] != '2' || info[2] != ',')
		return default_flags;

	flags = 0;
	for (info += 3; *info != '\0'; info++) {
		switch (*info) {
		case 'R': /* replied */
			flags |= MAIL_ANSWERED;
			break;
		case 'S': /* seen */
			flags |= MAIL_SEEN;
			break;
		case 'T': /* trashed */
			flags |= MAIL_DELETED;
			break;
		case 'D': /* draft */
			flags |= MAIL_DRAFT;
			break;
		case 'F': /* flagged */
			flags |= MAIL_FLAGGED;
			break;
		default:
			if (*info >= 'a' && *info <= 'z') {
				/* custom flag */
				flags |= 1 << (MAIL_CUSTOM_FLAG_1_BIT +
					       *info-'a');
				break;
			}

			/* unknown flag - ignore */
			break;
		}
	}

	return flags;
}

const char *maildir_filename_set_flags(const char *fname, MailFlags flags)
{
	const char *info, *oldflags;
	char *flags_buf, *p;
	int i, nextflag;

	/* remove the old :info from file name, and get the old flags */
	info = strrchr(fname, ':');
	if (info != NULL && strrchr(fname, '/') > info)
		info = NULL;

	oldflags = "";
	if (info != NULL) {
		fname = t_strdup_until(fname, info);
		if (info[1] == '2' && info[2] == ',')
			oldflags = info+3;
	}

	/* insert the new flags between old flags. flags must be sorted by
	   their ASCII code. unknown flags are kept. */
	flags_buf = t_malloc(MAIL_FLAGS_COUNT+strlen(oldflags)+1);
	p = flags_buf;

	for (;;) {
		/* skip all known flags */
		while (*oldflags == 'D' || *oldflags == 'F' ||
		       *oldflags == 'R' || *oldflags == 'S' ||
		       *oldflags == 'T' ||
		       (*oldflags >= 'a' && *oldflags <= 'z'))
			oldflags++;

		nextflag = *oldflags == '\0' ? 256 :
			(unsigned char) *oldflags;

		if ((flags & MAIL_DRAFT) && nextflag > 'D') {
			*p++ = 'D';
			flags &= ~MAIL_DRAFT;
		}
		if ((flags & MAIL_FLAGGED) && nextflag > 'F') {
			*p++ = 'F';
			flags &= ~MAIL_FLAGGED;
		}
		if ((flags & MAIL_ANSWERED) && nextflag > 'R') {
			*p++ = 'R';
			flags &= ~MAIL_ANSWERED;
		}
		if ((flags & MAIL_SEEN) && nextflag > 'S') {
			*p++ = 'S';
			flags &= ~MAIL_SEEN;
		}
		if ((flags & MAIL_DELETED) && nextflag > 'T') {
			*p++ = 'T';
			flags &= ~MAIL_DELETED;
		}

		if ((flags & MAIL_CUSTOM_FLAGS_MASK) && nextflag > 'a') {
			for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
				if (flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT)))
					*p++ = 'a' + i;
			}
			flags &= ~MAIL_CUSTOM_FLAGS_MASK;
		}

		if (*oldflags == '\0')
			break;

		*p++ = *oldflags++;
	}

	*p = '\0';

	return t_strconcat(fname, ":2,", flags_buf, NULL);
}

MailIndex *maildir_index_alloc(const char *dir)
{
	MailIndex *index;
	int len;

	i_assert(dir != NULL);

	index = i_new(MailIndex, 1);
	memcpy(index, &maildir_index, sizeof(MailIndex));

	index->fd = -1;
	index->dir = i_strdup(dir);

	len = strlen(index->dir);
	if (index->dir[len-1] == '/')
		index->dir[len-1] = '\0';

	return (MailIndex *) index;
}

static void maildir_index_free(MailIndex *index)
{
	mail_index_close(index);
	i_free(index->dir);
	i_free(index);
}

static int maildir_index_update_flags(MailIndex *index, MailIndexRecord *rec,
				      unsigned int seq, MailFlags flags,
				      int external_change)
{
	MailIndexUpdate *update;
	const char *old_fname, *new_fname;
	const char *old_path, *new_path;

	/* we need to update the flags in the file name */
	old_fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (old_fname == NULL) {
		index_data_set_corrupted(index->data, "Missing location field "
					 "for record %u", rec->uid);
		return FALSE;
	}

	new_fname = maildir_filename_set_flags(old_fname, flags);

	if (strcmp(old_fname, new_fname) != 0) {
		old_path = t_strconcat(index->dir, "/cur/", old_fname, NULL);
		new_path = t_strconcat(index->dir, "/cur/", new_fname, NULL);

		/* minor problem: new_path is overwritten if it exists.. */
		if (rename(old_path, new_path) < 0) {
			if (errno == ENOSPC)
				index->nodiskspace = TRUE;

			index_set_error(index, "maildir flags update: "
					"rename(%s, %s) failed: %m",
					old_path, new_path);
			return FALSE;
		}

		/* update the filename in index */
		update = index->update_begin(index, rec);
		index->update_field(update, FIELD_TYPE_LOCATION, new_fname, 0);

		if (!index->update_end(update))
			return FALSE;
	}

	if (!mail_index_update_flags(index, rec, seq, flags, external_change))
		return FALSE;

	return TRUE;
}

MailIndex maildir_index = {
	mail_index_open,
	mail_index_open_or_create,
	maildir_index_free,
	mail_index_set_lock,
	mail_index_try_lock,
	maildir_index_rebuild,
	mail_index_fsck,
	maildir_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	mail_index_lookup_field,
	mail_index_lookup_field_raw,
	maildir_open_mail,
	mail_index_expunge,
	maildir_index_update_flags,
	mail_index_append_begin,
	mail_index_append_end,
	mail_index_update_begin,
	mail_index_update_end,
	mail_index_update_field,
	mail_index_update_field_raw,
	mail_index_get_last_error,
	mail_index_is_diskspace_error,
	mail_index_is_inconsistency_error,

	MAIL_INDEX_PRIVATE_FILL
};
