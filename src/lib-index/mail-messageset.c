/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-hash.h"
#include "mail-modifylog.h"
#include "mail-messageset.h"

static unsigned int get_next_number(const char **str)
{
	unsigned int num;

	num = 0;
	while (**str != '\0') {
		if (**str < '0' || **str > '9')
			break;

		num = num*10 + **str - '0';
		(*str)++;
	}

	return num;
}

static int mail_index_foreach(MailIndex *index,
			      unsigned int seq, unsigned int seq2,
			      MsgsetForeachFunc func, void *context,
			      const char **error)
{
	MailIndexRecord *rec;
	const unsigned int *expunges;
	unsigned int expunges_before;
	int expunges_found;

	if (seq > seq2) {
		/* Second sequence can't be smaller than first - we could swap
		   them but I think it's a bug in client if it does this,
		   and better complain about it immediately than later let
		   them wonder why it doesn't work with other imapds.. */
		*error = t_strdup_printf("Invalid messageset range: %u > %u",
					 seq, seq2);
		return -2;
	}

	/* get list of expunged messages in our range. the expunges_before
	   can be used to calculate the current real sequence position */
	expunges = mail_modifylog_seq_get_expunges(index->modifylog, seq, seq2,
						   &expunges_before);
	i_assert(expunges_before < seq);
	expunges_found = *expunges != '\0';

	/* Reset index errors, since we later rely on it to check if failed */
	index_reset_error(index);

	/* get the first non-expunged message. note that if all messages
	   were expunged in the range, this points outside wanted range. */
	rec = index->lookup(index, seq - expunges_before);
	for (; rec != NULL; seq++) {
		/* skip expunged sequences */
		i_assert(rec->uid != 0);

		while (*expunges != 0 && *expunges < rec->uid) {
			expunges++;
			seq++;
		}
		i_assert(*expunges != rec->uid);

		if (seq > seq2)
			break;

		if (!func(index, rec, seq, context))
			return 0;

		rec = index->next(index, rec);
	}

	if (rec == NULL && index->get_last_error(index) != NULL) {
		/* error occured */
		return -1;
	}

	return !expunges_found && seq > seq2 ? 1 : 2;
}

int mail_index_messageset_foreach(MailIndex *index, const char *messageset,
				  unsigned int messages_count,
				  MsgsetForeachFunc func, void *context,
				  const char **error)
{
	const char *input;
	unsigned int seq, seq2;
	int ret, all_found;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*error = NULL;
	if (messages_count == 0) {
		/* no messages in mailbox */
		return 1;
	}

	all_found = TRUE;
	input = messageset;
	while (*input != '\0') {
		if (*input == '*') {
			/* last message */
			seq = messages_count;
			input++;
		} else {
			seq = get_next_number(&input);
			if (seq == 0) {
				*error = t_strconcat("Invalid messageset: ",
						     messageset, NULL);
				return -2;
			}
		}

		if (*input != ':')
			seq2 = seq;
		else {
			/* first:last range */
			input++;

			if (*input != '*') {
				seq2 = get_next_number(&input);
				if (seq2 == 0) {
					*error = t_strconcat("Invalid "
							     "messageset: ",
							     messageset, NULL);
					return -2;
				}

				if (seq2 > messages_count) {
					/* too large .. ignore silently */
					seq2 = messages_count;
				}
			} else {
				seq2 = messages_count;
				input++;
			}
		}

		if (*input == ',')
			input++;
		else if (*input != '\0') {
			*error = t_strdup_printf("Unexpected char '%c' "
						 "with messageset: %s",
						 *input, messageset);
			return -2;
		}

		if (seq > messages_count) {
			/* too large .. ignore silently */
		} else {
			ret = mail_index_foreach(index, seq, seq2,
						 func, context, error);
			if (ret <= 0)
				return ret;
			if (ret == 2)
				all_found = FALSE;
		}
	}

	return all_found ? 1 : 2;
}

static int mail_index_uid_foreach(MailIndex *index,
				  unsigned int uid, unsigned int uid2,
				  unsigned int max_sequence,
				  MsgsetForeachFunc func, void *context,
				  const char **error)
{
	MailIndexRecord *rec;
	off_t pos;
	const unsigned int *expunges;
	unsigned int seq;
	int expunges_found;

	if (uid > uid2) {
		/* not allowed - see mail_index_foreach() */
		*error = t_strdup_printf("Invalid uidset range: %u > %u",
					 uid, uid2);
		return -2;
	}

	/* get list of expunged messages in our range. */
	expunges = mail_modifylog_uid_get_expunges(index->modifylog, uid, uid2);
	expunges_found = *expunges != '\0';

	/* skip expunged messages at the beginning */
	while (*expunges == uid) {
		expunges++;

		if (++uid == uid2) {
			/* all were expunged */
			return 2;
		}
	}

	/* since we skipped the known expunged messages at the beginning
	   and our UIDs are contiguously allocated, the first hash lookup
	   _should_ work.. */
	pos = mail_hash_lookup_uid(index->hash, uid);
	if (pos != 0) {
		if (pos + sizeof(MailIndexRecord) > index->mmap_length) {
			/* hash is corrupted */
			index_set_error(index, "Corrupted hash for index %s: "
					"lookup returned offset outside range",
					index->filepath);

			if (!mail_hash_rebuild(index->hash))
				return -1;

			/* lets try again */
			pos = mail_hash_lookup_uid(index->hash, uid);
			if (pos + sizeof(MailIndexRecord) > index->mmap_length)
				return -1;
		}

		rec = (MailIndexRecord *) ((char *) index->mmap_base + pos);
	} else {
		/* ..however if for any reason it doesn't,
		   still handle it properly */
		if (uid == uid2)
			return 2;

		rec = index->lookup_uid_range(index, uid+1, uid2);
		if (rec == NULL)
			return 2;
	}

	seq = index->get_sequence(index, rec);
	while (rec != NULL && rec->uid <= uid2 && seq <= max_sequence) {
		uid = rec->uid;
		while (*expunges != 0 && *expunges < rec->uid) {
			expunges++;
			seq++;
		}
		i_assert(*expunges != rec->uid);

		if (!func(index, rec, seq, context))
			return 0;

		seq++;
		rec = index->next(index, rec);
	}

	if (rec == NULL && index->get_last_error(index) != NULL) {
		/* error occured */
		return -1;
	}

	return !expunges_found && uid == uid2 ? 1 : 2;
}

int mail_index_uidset_foreach(MailIndex *index, const char *uidset,
			      unsigned int messages_count,
			      MsgsetForeachFunc func, void *context,
			      const char **error)
{
	MailIndexRecord *rec;
	const char *input;
	unsigned int uid, uid2;
	int ret, all_found;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*error = NULL;
	if (messages_count == 0) {
		/* no messages in mailbox */
		return 1;
	}

	all_found = TRUE;
	input = uidset;
	while (*input != '\0') {
		if (*input == '*') {
			/* last message */
			rec = index->lookup(index, messages_count);
			uid = rec == NULL ? 0 : rec->uid;
			input++;
		} else {
			uid = get_next_number(&input);
			if (uid == 0) {
				*error = t_strconcat("Invalid uidset: ",
						     uidset, NULL);
				return -2;
			}
		}

		if (*input != ':')
			uid2 = uid;
		else {
			/* first:last range */
			input++;

			if (*input != '*') {
				uid2 = get_next_number(&input);
				if (uid2 == 0) {
					*error = t_strconcat("Invalid uidset: ",
							     uidset, NULL);
					return -2;
				}
			} else {
				uid2 = index->header->next_uid-1;
				input++;
			}
		}

		if (*input == ',')
			input++;
		else if (*input != '\0') {
			*error = t_strdup_printf("Unexpected char '%c' with "
						 "uidset: %s", *input, uidset);
			return -2;
		}

		if (uid >= index->header->next_uid) {
			/* too large .. ignore silently */
		} else {
			ret = mail_index_uid_foreach(index, uid, uid2,
						     messages_count,
						     func, context, error);
			if (ret <= 0)
				return ret;
			if (ret == 2)
				all_found = FALSE;
		}
	}

	return all_found ? 1 : 2;
}
