/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "index-messageset.h"

static unsigned int get_next_number(const char **str)
{
	unsigned int num;

	num = 0;
	while (**str != '\0') {
		if (**str < '0' || **str > '9')
			break;

		num = num*10 + (**str - '0');
		(*str)++;
	}

	return num;
}

static int mail_index_foreach(struct mail_index *index,
			      unsigned int seq, unsigned int seq2,
			      MsgsetForeachFunc func, void *context)
{
	struct mail_index_record *rec;
	const struct modify_log_expunge *expunges;
	unsigned int idx_seq, expunges_before, temp;
	int expunges_found;

	if (seq > seq2) {
		/* swap, as specified by latest IMAP4rev1 spec */
		temp = seq;
		seq = seq2;
		seq2 = temp;
	}

	/* get list of expunged messages in our range. the expunges_before
	   can be used to calculate the current real sequence position */
	expunges = mail_modifylog_seq_get_expunges(index->modifylog, seq, seq2,
						   &expunges_before);
	if (expunges == NULL)
		return -1;

	i_assert(expunges_before < seq);
	expunges_found = expunges->uid1 != 0;

	/* Reset index errors, since we later rely on it to check if failed */
	index_reset_error(index);

	/* get the first non-expunged message. note that if all messages
	   were expunged in the range, this points outside wanted range. */
	idx_seq = seq - expunges_before;
	rec = index->lookup(index, idx_seq);
	for (; rec != NULL; seq++, idx_seq++) {
		/* skip expunged sequences */
		i_assert(rec->uid != 0);

		while (expunges->uid1 != 0 && expunges->uid1 < rec->uid) {
			i_assert(expunges->uid2 < rec->uid);

			seq += expunges->seq_count;
			expunges++;
		}
		i_assert(!(expunges->uid1 <= rec->uid &&
			   expunges->uid2 >= rec->uid));

		if (seq > seq2)
			break;

		t_push();
		if (!func(index, rec, seq, idx_seq, context)) {
			t_pop();
			return 0;
		}
		t_pop();

		rec = index->next(index, rec);
	}

	if (rec == NULL &&
	    index->get_last_error(index) != MAIL_INDEX_ERROR_NONE) {
		/* error occured */
		return -1;
	}

	return !expunges_found && seq > seq2 ? 1 : 2;
}

static int mail_index_messageset_foreach(struct mail_index *index,
					 const char *messageset,
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
		*error = "No messages in mailbox";
		return -2;
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

		if (seq > messages_count || seq2 > messages_count) {
			/* non-existent messages requested */
			if (seq <= messages_count)
				seq = seq2;
			*error = t_strdup_printf("Message sequence %u "
						 "larger than mailbox size %u",
						 seq, messages_count);
			return -2;
		}

		t_push();
		ret = mail_index_foreach(index, seq, seq2, func, context);
		t_pop();
		if (ret <= 0)
			return ret;
		if (ret == 2)
			all_found = FALSE;
	}

	return all_found ? 1 : 2;
}

static int mail_index_uid_foreach(struct mail_index *index,
				  unsigned int uid, unsigned int uid2,
				  MsgsetForeachFunc func, void *context)
{
	struct mail_index_record *rec;
	const struct modify_log_expunge *expunges;
	unsigned int client_seq, idx_seq, expunges_before, temp;
	int expunges_found;

	if (uid > uid2) {
		/* swap, as specified by latest IMAP4rev1 spec */
		temp = uid;
		uid = uid2;
		uid2 = temp;
	}

	/* get list of expunged messages in our range. */
	expunges = mail_modifylog_uid_get_expunges(index->modifylog, uid, uid2,
						   &expunges_before);
	if (expunges == NULL)
		return -1;

	expunges_found = expunges->uid1 != 0;

	rec = index->lookup_uid_range(index, uid, uid2, &idx_seq);
	if (rec == NULL)
		return expunges_found ? 2 : 1;

	client_seq = idx_seq + expunges_before;
	while (rec != NULL && rec->uid <= uid2) {
		while (expunges->uid1 != 0 && expunges->uid1 < rec->uid) {
			i_assert(expunges->uid2 < rec->uid);

			client_seq += expunges->seq_count;
			expunges++;
		}
		i_assert(!(expunges->uid1 <= rec->uid &&
			   expunges->uid2 >= rec->uid));

		t_push();
		if (!func(index, rec, client_seq, idx_seq, context)) {
			t_pop();
			return 0;
		}
		t_pop();

		client_seq++; idx_seq++;
		rec = index->next(index, rec);
	}

	if (rec == NULL &&
	    index->get_last_error(index) != MAIL_INDEX_ERROR_NONE) {
		/* error occured */
		return -1;
	}

	return expunges_found ? 2 : 1;
}

static int mail_index_uidset_foreach(struct mail_index *index,
				     const char *uidset,
				     unsigned int messages_count,
				     MsgsetForeachFunc func, void *context,
				     const char **error)
{
	struct mail_index_record *rec;
	const char *input;
	unsigned int uid, uid2;
	int ret, all_found;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*error = NULL;

	all_found = TRUE;
	input = uidset;
	while (*input != '\0') {
		if (*input == '*') {
			/* last message */
			if (messages_count == 0)
				uid = 0;
			else {
				rec = index->lookup(index, messages_count);
				uid = rec == NULL ? 0 : rec->uid;
			}
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

		t_push();
		ret = mail_index_uid_foreach(index, uid, uid2,
					     func, context);
		t_pop();
		if (ret <= 0)
			return ret;
		if (ret == 2)
			all_found = FALSE;
	}

	return all_found ? 1 : 2;
}

int index_messageset_foreach(struct index_mailbox *ibox,
			     const char *messageset, int uidset,
			     MsgsetForeachFunc func, void *context)
{
	const char *error;
	int ret;

	if (uidset) {
		ret = mail_index_uidset_foreach(ibox->index, messageset,
						ibox->synced_messages_count,
						func, context, &error);
	} else {
		ret = mail_index_messageset_foreach(ibox->index, messageset,
						    ibox->synced_messages_count,
						    func, context, &error);
	}

	if (ret < 0) {
		if (ret == -2) {
			/* user error */
			mail_storage_set_syntax_error(ibox->box.storage,
						      "%s", error);
		} else {
			mail_storage_set_index_error(ibox);
		}
	}

	return ret;
}
