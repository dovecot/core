/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "temp-string.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"

#include <stdio.h>
#include <sys/stat.h>

extern MailIndex maildir_index;

MailFlags maildir_filename_get_flags(const char *fname, MailFlags default_flags)
{
	const char *info;
	MailFlags flags;

	info = strchr(fname, ':');
	if (info == NULL || info[1] != '2' || info[2] != ',')
		return default_flags;

	flags = 0;
	for (info += 3; *info != '\0' && *info != ','; info++) {
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
	TempString *flags_str;
	const char *info, *oldflags;
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
	flags_str = t_string_new(256);
	t_string_append(flags_str, fname);
	t_string_append(flags_str, ":2,");
	for (;;) {
		/* skip all known flags */
		while (*oldflags == 'D' || *oldflags == 'F' ||
		       *oldflags == 'R' || *oldflags == 'S' ||
		       *oldflags == 'T' ||
		       (*oldflags >= 'a' && *oldflags <= 'z'))
			oldflags++;

		nextflag = *oldflags == '\0' || *oldflags == ',' ? 256 :
			(unsigned char) *oldflags;

		if ((flags & MAIL_DRAFT) && nextflag > 'D') {
			t_string_append_c(flags_str, 'D');
			flags &= ~MAIL_DRAFT;
		}
		if ((flags & MAIL_FLAGGED) && nextflag > 'F') {
			t_string_append_c(flags_str, 'F');
			flags &= ~MAIL_FLAGGED;
		}
		if ((flags & MAIL_ANSWERED) && nextflag > 'R') {
			t_string_append_c(flags_str, 'R');
			flags &= ~MAIL_ANSWERED;
		}
		if ((flags & MAIL_SEEN) && nextflag > 'S') {
			t_string_append_c(flags_str, 'S');
			flags &= ~MAIL_SEEN;
		}
		if ((flags & MAIL_DELETED) && nextflag > 'T') {
			t_string_append_c(flags_str, 'T');
			flags &= ~MAIL_DELETED;
		}

		if ((flags & MAIL_CUSTOM_FLAGS_MASK) && nextflag > 'a') {
			for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
				if (flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT)))
					t_string_append_c(flags_str, 'a' + i);
			}
			flags &= ~MAIL_CUSTOM_FLAGS_MASK;
		}

		if (*oldflags == '\0' || *oldflags == ',')
			break;

		t_string_append_c(flags_str, *oldflags);
		oldflags++;
	}

	if (*oldflags == ',') {
		/* another flagset, we don't know about these, just keep them */
		while (*oldflags != '\0')
			t_string_append_c(flags_str, *oldflags++);
	}

	return flags_str->str;
}

MailIndex *maildir_index_alloc(const char *dir)
{
	MailIndex *index;

	i_assert(dir != NULL);

	index = i_new(MailIndex, 1);
	memcpy(index, &maildir_index, sizeof(MailIndex));

	mail_index_init(index, dir);
	return index;
}

static void maildir_index_free(MailIndex *index)
{
	mail_index_close(index);
	i_free(index->dir);
	i_free(index);
}

static time_t maildir_get_internal_date(MailIndex *index, MailIndexRecord *rec)
{
	struct stat st;
	const char *fname;
	time_t date;

	/* try getting it from cache */
	date = mail_get_internal_date(index, rec);
	if (date != (time_t)-1)
		return date;

	/* stat() gives it */
	fname = index->lookup_field(index, rec, DATA_FIELD_LOCATION);
	if (fname == NULL) {
		index_data_set_corrupted(index->data,
			"Missing location field for record %u", rec->uid);
		return (time_t)-1;
	}

	if (stat(fname, &st) < 0) {
		index_file_set_syscall_error(index, fname, "stat()");
		return (time_t)-1;
	}

	return st.st_mtime;
}

static int maildir_index_update_flags(MailIndex *index, MailIndexRecord *rec,
				      unsigned int seq, MailFlags flags,
				      int external_change)
{
	MailIndexUpdate *update;
	const char *old_fname, *new_fname;
	const char *old_path, *new_path;

	/* we need to update the flags in the file name */
	old_fname = index->lookup_field(index, rec, DATA_FIELD_LOCATION);
	if (old_fname == NULL) {
		index_data_set_corrupted(index->data,
			"Missing location field for record %u", rec->uid);
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
		index->update_field(update, DATA_FIELD_LOCATION, new_fname, 0);

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
        mail_index_set_lock_notify_callback,
	maildir_index_rebuild,
	mail_index_fsck,
	maildir_index_sync,
	mail_index_get_header,
	mail_index_lookup,
	mail_index_next,
        mail_index_lookup_uid_range,
	mail_index_lookup_field,
	mail_index_lookup_field_raw,
	mail_index_cache_fields_later,
	maildir_open_mail,
	maildir_get_internal_date,
	mail_index_expunge,
	maildir_index_update_flags,
	mail_index_append_begin,
	mail_index_append_end,
	mail_index_update_begin,
	mail_index_update_end,
	mail_index_update_field,
	mail_index_update_field_raw,
	mail_index_get_last_error,
	mail_index_get_last_error_text,

	MAIL_INDEX_PRIVATE_FILL
};
