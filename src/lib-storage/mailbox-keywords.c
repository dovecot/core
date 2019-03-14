/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"
#include "mail-storage-private.h"

static struct mail_keywords *
mailbox_keywords_create_skip(struct mailbox *box,
			     const char *const keywords[])
{
	struct mail_keywords *kw;

	T_BEGIN {
		ARRAY(const char *) valid_keywords;
		const char *error;

		t_array_init(&valid_keywords, 32);
		for (; *keywords != NULL; keywords++) {
			if (mailbox_keyword_is_valid(box, *keywords, &error))
				array_push_back(&valid_keywords, keywords);
		}
		array_append_zero(&valid_keywords); /* NULL-terminate */
		kw = mail_index_keywords_create(box->index, keywords);
	} T_END;
	return kw;
}

static bool
mailbox_keywords_are_valid(struct mailbox *box, const char *const keywords[],
			   const char **error_r)
{
	unsigned int i;

	for (i = 0; keywords[i] != NULL; i++) {
		if (!mailbox_keyword_is_valid(box, keywords[i], error_r))
			return FALSE;
	}
	return TRUE;
}

int mailbox_keywords_create(struct mailbox *box, const char *const keywords[],
			    struct mail_keywords **keywords_r)
{
	const char *error, *empty_keyword_list = NULL;

	i_assert(box->opened);

	if (keywords == NULL)
		keywords = &empty_keyword_list;
	if (!mailbox_keywords_are_valid(box, keywords, &error)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS, error);
		return -1;
	}

	*keywords_r = mail_index_keywords_create(box->index, keywords);
	return 0;
}

struct mail_keywords *
mailbox_keywords_create_valid(struct mailbox *box,
			      const char *const keywords[])
{
	const char *empty_keyword_list = NULL;
	const char *error;

	i_assert(box->opened);

	if (keywords == NULL)
		keywords = &empty_keyword_list;
	if (mailbox_keywords_are_valid(box, keywords, &error))
		return mail_index_keywords_create(box->index, keywords);
	else {
		/* found invalid keywords, do this the slow way */
		return mailbox_keywords_create_skip(box, keywords);
	}
}

struct mail_keywords *
mailbox_keywords_create_from_indexes(struct mailbox *box,
				     const ARRAY_TYPE(keyword_indexes) *idx)
{
	i_assert(box->opened);

	return mail_index_keywords_create_from_indexes(box->index, idx);
}

struct mail_keywords *mailbox_keywords_merge(struct mail_keywords *keywords1,
					     struct mail_keywords *keywords2)
{
	ARRAY_TYPE(keyword_indexes) keywords_merged;

	i_assert(keywords1->index == keywords2->index);

	t_array_init(&keywords_merged, keywords1->count + keywords2->count);
	/* duplicates are dropped by mail_index_keywords_create() */
	array_append(&keywords_merged, keywords1->idx, keywords1->count);
	array_append(&keywords_merged, keywords2->idx, keywords2->count);
	return mail_index_keywords_create_from_indexes(keywords1->index,
						       &keywords_merged);
}

void mailbox_keywords_ref(struct mail_keywords *keywords)
{
	mail_index_keywords_ref(keywords);
}

void mailbox_keywords_unref(struct mail_keywords **keywords)
{
	mail_index_keywords_unref(keywords);
}

bool mailbox_keyword_is_valid(struct mailbox *box, const char *keyword,
			      const char **error_r)
{
	unsigned int i, idx;

	i_assert(box->opened);

	/* if it already exists, skip validity checks */
	if (mail_index_keyword_lookup(box->index, keyword, &idx))
		return TRUE;

	if (*keyword == '\0') {
		*error_r = "Empty keywords not allowed";
		return FALSE;
	}
	if (box->disallow_new_keywords) {
		*error_r = "Can't create new keywords";
		return FALSE;
	}

	/* these are IMAP-specific restrictions, but for now IMAP is all we
	   care about */
	for (i = 0; keyword[i] != '\0'; i++) {
		if (!IS_ATOM_CHAR(keyword[i])) {
			if ((unsigned char)keyword[i] < 0x80)
				*error_r = "Invalid characters in keyword";
			else
				*error_r = "8bit characters in keyword";
			return FALSE;
		}
	}
	if (i > box->storage->set->mail_max_keyword_length) {
		*error_r = "Keyword length too long";
		return FALSE;
	}
	return TRUE;
}
