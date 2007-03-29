/* Copyright (C) 2002-2006 Timo Sirainen */

/* Implementation of draft-ietf-imapext-thread-12 threading algorithm

   Message threads are permanently stored using mail-hash API. The links
   are built according to normal threading rules. Base subject grouping
   however isn't saved, so it needs to be done the slow way.

   We do this permanent storing and optimization only when we're threading
   all messages, which is what pretty much all the webmails do. Otherwise
   we'd need to have separate thread trees for each search query, which
   isn't practical.

   The nodes are stored sorted by their sent_date/UID as specified by the
   threading rules, so no further sorting is required to be done. Dummy nodes
   are sorted by their children, and since their children are also sorted, it
   practically means that they need to be moved whenever their first child
   is changed.

   Adding new messages to the hash is easy and fast. Removing messages
   however might cause changes all over the thread tree. Luckily this is
   rare so we can just optimize the common cases. This is done with reference
   counts:

   A node is created for each seen Message-ID. We also store the dummy ones
   for which no actual message exists. Each time a Message-ID is seen in the
   In-Reply-To or References headers, the Message-ID node's reference count
   is increased.

   Expunging then decreases reference counts for each Message-ID. There are
   two rare problematic cases when expunging:

   1) Duplicate Message-IDs
   2) Broken parent-child relationships:
        a) different messages describe them differently in their References
	   headers
	b) loops

   For these cases expunging a message affecting these may cause larger
   thread reorganizations. We mark these with expunge_rebuilds flag, so that
   if the problematic message is expunged, we'll just rebuild everything.

   When a message is expunged, either its reference count drops to zero in
   which case it's removed completely, otherwise it's turned into a dummy
   node.

   Typically when reference count drops to zero it means it the node has no
   children. One special case is however a thread with:
     [1:dummy] [2:dummy] [3:ref 1, 2] [4:ref 2]
   When 3 is removed, 1's refcount drops to zero but 2 is still referenced
   by 4. In this case the 2's parent must be updated.

   When we open the mail-hash, we check that no messages have been expunged
   from mailbox which haven't also been removed from the hash. If they have,
   we rebuild the thread tree. Otherwise we add the new messages to the hash
   and then send the results to client.
*/

#include "common.h"
#include "array.h"
#include "crc32.h"
#include "ostream.h"
#include "str.h"
#include "message-id.h"
#include "imap-base-subject.h"
#include "mail-storage.h"
#include "mail-search.h"
#include "imap-thread.h"

/* FIXME: the mailbox accessing API needs some cleaning up. we shouldn't be
   including all kinds of private headers */
#include "../lib-storage/index/index-storage.h"
#include "mail-hash.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"

#include <stdlib.h>

#define IMAP_THREAD_CONTEXT(obj) \
	MODULE_CONTEXT(obj, imap_thread_storage_module)

/* how much memory to allocate initially. these are very rough
   approximations. */
#define APPROX_MSG_EXTRA_COUNT 10
#define APPROX_MSGID_SIZE 45

/* Try to buffer this much data before sending it to output stream. */
#define OUTPUT_BUF_SIZE 2048

#define HDR_MESSAGE_ID "message-id"
#define HDR_IN_REPLY_TO "in-reply-to"
#define HDR_REFERENCES "references"
#define HDR_SUBJECT "subject"

struct msgid_rec {
	const char *msgid;
	uint32_t msgid_crc32;
};

struct mail_thread_rec {
	struct mail_hash_record rec;

	uint32_t refcount:31;
	uint32_t expunge_rebuilds:1;

	uint32_t msgid_crc32;
	uint32_t sent_date;

	uint32_t parent_idx;
	uint32_t first_child_idx;
	uint32_t next_idx;
};

struct mail_thread_moved_rec {
	struct mail_thread_rec rec;
	/* first_child_idx and its siblings are in moved_recs */
	unsigned int moved_children:1;
};

struct mail_thread_root_rec {
	uint32_t idx;
	uint32_t uid;
	uint32_t sent_date;

	/* a linked list of roots which belong to the same thread */
	struct mail_thread_root_rec *next;

	/* another record has this record in its next-pointer.
	   this record isn't a root anymore. */
	unsigned int nonroot:1;
	/* idx points to moved_recs */
	unsigned int moved:1;
	/* subject contained a Re: or Fwd: */
	unsigned int reply:1;
};
#define ROOT_REC_IS_DUMMY(rec) \
	((rec)->uid == 0)

struct thread_context {
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;
	struct mailbox *box;
	struct ostream *output;
	enum mail_thread_type thread_type;

	struct mail *tmp_mail;
	struct mail_thread_rec tmp_rec;

	struct mail_search_arg tmp_search_arg;
	struct mail_search_seqset seqset;

	/* Hash record idx -> Message-ID */
	ARRAY_DEFINE(msgid_map, const char *);
	pool_t msgid_pool;
	struct mail_hash *msgid_hash;

	pool_t subject_pool;
	struct hash_table *subject_hash;
	ARRAY_DEFINE(roots, struct mail_thread_root_rec *);
	ARRAY_DEFINE(moved_recs, struct mail_thread_moved_rec);
	uint32_t *alt_dates;

	unsigned int cmp_match_count;
	uint32_t cmp_last_idx;

	unsigned int id_is_uid:1;
	unsigned int failed:1;
};

struct imap_thread_mailbox {
	union mailbox_module_context module_ctx;
	struct mail_hash *msgid_hash;

	/* set only temporarily while needed */
	struct thread_context *ctx;
};

static void (*next_hook_mailbox_opened)(struct mailbox *box);

static MODULE_CONTEXT_DEFINE_INIT(imap_thread_storage_module,
				  &mail_storage_module_register);

static void imap_thread_hash_init(struct mailbox *box, bool create);

static int mail_thread_input(struct thread_context *ctx, struct mail *mail);
static int mail_thread_finish(struct thread_context *ctx);

static int unlink_child(struct thread_context *ctx, uint32_t child_idx,
			uint32_t new_parent_idx);

static void mail_thread_deinit(struct imap_thread_mailbox *tbox,
			       struct thread_context *ctx)
{
	i_free(ctx->alt_dates);

	if (ctx->msgid_hash != tbox->msgid_hash)
		mail_hash_free(&ctx->msgid_hash);
	else
		mail_hash_unlock(ctx->msgid_hash);

	if (ctx->subject_hash != NULL) {
		hash_destroy(ctx->subject_hash);
		pool_unref(ctx->subject_pool);
	}

	array_free(&ctx->msgid_map);
	pool_unref(ctx->msgid_pool);
}

static uint32_t crc32_str_nonzero(const char *str)
{
	uint32_t value = crc32_str(str);
	return value == 0 ? 1 : value;
}

static int
mail_thread_rec_idx(struct thread_context *ctx, uint32_t idx,
		    const struct mail_thread_rec **rec_r)
{
	const void *value;

	if (mail_hash_lookup_idx(ctx->msgid_hash, idx, &value) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	*rec_r = value;
	return 0;
}

static unsigned int mail_thread_hash_key(const void *key)
{
	const struct msgid_rec *key_rec = key;

	return key_rec->msgid_crc32;
}

static int
mail_thread_find_child_msgid(struct thread_context *ctx, uint32_t parent_uid,
			     uint32_t msgid_crc32, const char **msgid_r)
{
	const char *msgids, *msgid, *found_msgid = NULL;
	int ret;

	if ((ret = mail_set_uid(ctx->tmp_mail, parent_uid)) < 0)
		return -1;
	if (ret == 0) {
		*msgid_r = NULL;
		return 0;
	}

	msgids = mail_get_first_header(ctx->tmp_mail, HDR_IN_REPLY_TO);
	msgid = msgids == NULL ? NULL : message_id_get_next(&msgids);
	if (msgid != NULL) {
		if (crc32_str_nonzero(msgid) == msgid_crc32)
			found_msgid = msgid;
	}

	msgids = mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES);
	if (msgids == NULL) {
		*msgid_r = found_msgid;
		return 0;
	}

	while ((msgid = message_id_get_next(&msgids)) != NULL) {
		if (crc32_str_nonzero(msgid) == msgid_crc32) {
			if (found_msgid != NULL &&
			    strcmp(found_msgid, msgid) != 0) {
				/* hash collisions, we can't figure this out */
				return -1;
			}
			found_msgid = msgid;
		}
	}

	*msgid_r = found_msgid;
	return 0;
}

static const char *
mail_thread_children_get_parent_msgid(struct thread_context *ctx,
				      const struct mail_thread_rec *parent_rec)
{
	const struct mail_thread_rec *child_rec;
	const char *msgid;
	uint32_t idx;

	for (idx = parent_rec->first_child_idx; idx != 0; ) {
		if (mail_thread_rec_idx(ctx, idx, &child_rec) < 0)
			return NULL;
		idx = child_rec->next_idx;

		if (child_rec->rec.uid == 0) {
			if (idx != 0)
				continue;

			/* only dummies in this level. go deeper. */
			return mail_thread_children_get_parent_msgid(ctx,
								     child_rec);
		}

		/* each non-dummy child must have a valid In-Reply-To or
		   References header pointing to the parent, otherwise it
		   wouldn't be our child */
		if (parent_rec->msgid_crc32 == 0) {
			mail_hash_set_corrupted(ctx->msgid_hash,
				"msgid_crc32=0 node has children");
			return NULL;
		}

		if (mail_thread_find_child_msgid(ctx, child_rec->rec.uid,
						 parent_rec->msgid_crc32,
						 &msgid) == 0)
			return msgid;
	}
	return NULL;
}

static const char *
mail_thread_rec_get_msgid(struct thread_context *ctx,
			  const struct mail_thread_rec *rec, uint32_t idx)
{
	const char *msgids, *msgid, **p;

	p = array_idx_modifiable(&ctx->msgid_map, idx);
	if (*p != NULL)
		return *p;

	if (rec->rec.uid != 0) {
		/* we can get the Message-ID directly */
		if (mail_set_uid(ctx->tmp_mail, rec->rec.uid) <= 0)
			return NULL;

		msgids = mail_get_first_header(ctx->tmp_mail, HDR_MESSAGE_ID);
		if (msgids == NULL)
			return NULL;

		msgid = message_id_get_next(&msgids);
	} else {
		/* fallback to finding from children's references */
		msgid = mail_thread_children_get_parent_msgid(ctx, rec);
	}

	if (msgid == NULL)
		return NULL;

	*p = p_strdup(ctx->msgid_pool, msgid);
	return *p;
}

static bool mail_thread_hash_cmp(const void *key, const void *data,
				 struct imap_thread_mailbox *tbox)
{
	struct thread_context *ctx = tbox->ctx;
	const struct msgid_rec *key_rec = key;
	const struct mail_thread_rec *rec = data;
	const char *msgid;

	if (key_rec->msgid_crc32 != rec->msgid_crc32)
		return FALSE;

	ctx->cmp_match_count++;
	ctx->cmp_last_idx = mail_hash_value_idx(ctx->msgid_hash, rec);

	/* either a match or a collision, need to look closer */
	msgid = mail_thread_rec_get_msgid(ctx, rec, ctx->cmp_last_idx);
	if (msgid == NULL) {
		/* we couldn't figure out the Message-ID for whatever reason.
		   we'll need to fallback to rebuilding the whole thread */
		ctx->failed = TRUE;
		return FALSE;
	}
	return strcmp(msgid, key_rec->msgid) == 0;
}

static unsigned int mail_thread_hash_rec(const void *p)
{
	const struct mail_thread_rec *rec = p;

	return rec->msgid_crc32;
}

static int
resize_callback(struct mail_hash *tmp_hash, uint32_t first_changed_idx,
		const uint32_t *map, unsigned int map_size, void *context)
{
	struct thread_context *ctx = context;
	const struct mail_hash_header *hdr;
	const struct mail_thread_rec *rec;
	struct mail_thread_rec tmp_rec;
	const void *value;
	uint32_t idx;

	hdr = mail_hash_get_header(tmp_hash);
	for (idx = first_changed_idx; idx <= hdr->record_count; idx++) {
		if (mail_hash_lookup_idx(tmp_hash, idx, &value) < 0)
			return -1;
		rec = value;

		i_assert(!MAIL_HASH_RECORD_IS_DELETED(&rec->rec));

		if (rec->parent_idx >= map_size ||
		    rec->first_child_idx >= map_size ||
		    rec->next_idx >= map_size) {
			mail_hash_set_corrupted(ctx->msgid_hash,
						"invalid indexes");
			return -1;
		}

		tmp_rec = *rec;
		tmp_rec.parent_idx = map[rec->parent_idx];
		tmp_rec.first_child_idx = map[rec->first_child_idx];
		tmp_rec.next_idx = map[rec->next_idx];
		if (mail_hash_update_idx(tmp_hash, idx, &tmp_rec) < 0)
			return -1;
	}
	return 0;
}

static int
imap_thread_context_init(struct imap_thread_mailbox *tbox,
			 struct client *client, const char *charset,
			 struct mail_search_arg *search_args)
{
	struct thread_context *ctx = tbox->ctx;
	struct mailbox_status status;
	const struct mail_hash_header *hdr;
	unsigned int count;
	uint32_t last_seq = 0, last_uid = 0;

	if (mailbox_get_status(client->mailbox,
			       STATUS_MESSAGES | STATUS_UIDNEXT, &status) < 0)
		return -1;

	last_seq = status.messages;
	last_uid = status.uidnext - 1;

	/* Each search condition requires their own separate thread index.
	   Pretty much all the clients use only "search all" threading, so
	   we don't need to worry about anything else. */
	if (search_args->next != NULL) {
		/* too difficult to figure out if we could optimize this.
		   we most likely couldn't. */
		ctx->msgid_hash = NULL;
	} else if (search_args->type == SEARCH_ALL) {
		/* optimize */
	} else if (search_args->type == SEARCH_SEQSET &&
		   search_args->value.seqset->seq1 == 1) {
		/* If we're searching 1..n, we might be able to optimize
		   this. This is at least useful for testing incremental
		   index updates if nothing else. :) */
		last_seq = search_args->value.seqset->seq2;
		last_uid = 0;
	} else {
		ctx->msgid_hash = NULL;
	}

	if (ctx->msgid_hash != NULL) {
		if (mail_hash_lock(ctx->msgid_hash) <= 0)
			ctx->msgid_hash = NULL;
	}

	hdr = ctx->msgid_hash == NULL ? NULL :
		mail_hash_get_header(ctx->msgid_hash);
	if (hdr == NULL) {
		/* we want to build it in memory */
	} else if (hdr->message_count > last_seq) {
		if (hdr->last_uid > last_uid) {
			/* view is a bit out of date, can't optimize */
			mail_hash_unlock(ctx->msgid_hash);
			ctx->msgid_hash = NULL;
		} else {
			/* rebuild */
			if (mail_hash_reset(ctx->msgid_hash, 0) < 0)
				ctx->msgid_hash = NULL;
		}
	} else if (hdr->last_uid != 0) {
		/* non-empty hash. add only the new messages in there. */
		if (mailbox_get_uids(client->mailbox, 1, hdr->last_uid,
				     &ctx->seqset.seq1,
				     &ctx->seqset.seq2) < 0) {
			mail_hash_unlock(ctx->msgid_hash);
			return -1;
		}

		if (ctx->seqset.seq2 != hdr->message_count) {
			/* some messages have been expunged. have to rebuild. */
			if (mail_hash_reset(ctx->msgid_hash, 0) < 0)
				ctx->msgid_hash = NULL;
		} else {
			/* after all these checks, this is the only case we
			   can actually optimize. */
			ctx->tmp_search_arg.type = SEARCH_SEQSET;
			if (ctx->seqset.seq2 == last_seq) {
				/* search nothing */
				ctx->tmp_search_arg.value.seqset = NULL;
			} else {
				/* search next+1..n */
				ctx->seqset.seq1 = ctx->seqset.seq2 + 1;
				ctx->seqset.seq2 = last_seq;
				ctx->tmp_search_arg.value.seqset = &ctx->seqset;
			}
			search_args = &ctx->tmp_search_arg;

			if (mail_hash_resize_if_needed(ctx->msgid_hash,
						       last_seq -
						       hdr->message_count,
						       resize_callback,
						       ctx) < 0)
				ctx->msgid_hash = NULL;
		}
	}

	if (ctx->msgid_hash == NULL) {
		/* fallback to using in-memory hash */
		struct index_mailbox *ibox =
			(struct index_mailbox *)client->mailbox;

		ctx->msgid_hash =
			mail_hash_open(ibox->index, ".thread",
				       MAIL_HASH_OPEN_FLAG_CREATE |
				       MAIL_HASH_OPEN_FLAG_IN_MEMORY,
				       sizeof(struct mail_thread_rec), 0,
				       mail_thread_hash_key,
				       mail_thread_hash_rec,
				       mail_thread_hash_cmp,
				       tbox);
	}

	/* initialize searching */
	ctx->t = mailbox_transaction_begin(client->mailbox, 0);
	ctx->search_ctx = mailbox_search_init(ctx->t, charset,
					      search_args, NULL);

	ctx->box = client->mailbox;
	ctx->output = client->output;

	/* at this point the hash is either locked or we're using in-memory
	   hash where it doesn't matter */
	hdr = mail_hash_get_header(ctx->msgid_hash);
	count = client->messages_count < hdr->record_count ? 0 :
		client->messages_count - hdr->record_count;
	count += APPROX_MSG_EXTRA_COUNT;
	ctx->msgid_pool =
		pool_alloconly_create("msgids", count * APPROX_MSGID_SIZE);
	i_array_init(&ctx->msgid_map,
		     I_MAX(hdr->record_count, client->messages_count));

	ctx->tmp_mail = mail_alloc(ctx->t, 0, NULL);
	return 0;
}

int imap_thread(struct client_command_context *cmd, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type)
{
	static const char *wanted_headers[] = {
		HDR_MESSAGE_ID, HDR_IN_REPLY_TO, HDR_REFERENCES, HDR_SUBJECT,
		NULL
	};
	struct imap_thread_mailbox *tbox =
		IMAP_THREAD_CONTEXT(cmd->client->mailbox);
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct thread_context *ctx;
	struct mail *mail;
	int ret, try;

	i_assert(type == MAIL_THREAD_REFERENCES ||
		 type == MAIL_THREAD_REFERENCES2);

	if (tbox->msgid_hash == NULL)
		imap_thread_hash_init(cmd->client->mailbox, TRUE);

	headers_ctx = mailbox_header_lookup_init(cmd->client->mailbox,
						 wanted_headers);

	ctx = t_new(struct thread_context, 1);
	tbox->ctx = ctx;
	ctx->msgid_hash = tbox->msgid_hash;
	ctx->thread_type = type;

	for (try = 0; try < 2; try++) {
		ret = 0;
		if (imap_thread_context_init(tbox, cmd->client,
					     charset, args) < 0) {
			ret = -1;
			break;
		}

		mail = mail_alloc(ctx->t, MAIL_FETCH_DATE, headers_ctx);
		ctx->id_is_uid = cmd->uid;
		while (ret == 0 &&
		       mailbox_search_next(ctx->search_ctx, mail) > 0) {
			t_push();
			ret = mail_thread_input(ctx, mail);
			t_pop();
		}
		mail_free(&mail);

		if (mail_thread_finish(ctx) < 0)
			ret = -1;

		ret = mailbox_search_deinit(&ctx->search_ctx);
		if (mailbox_transaction_commit(&ctx->t, 0) < 0)
			ret = -1;
		mail_thread_deinit(tbox, ctx);

		if (ctx->failed && ctx->msgid_hash == tbox->msgid_hash) {
			/* try again with in-memory hash */
			memset(ctx, 0, sizeof(*ctx));
		} else {
			break;
		}
	}

	tbox->ctx = NULL;
	mailbox_header_lookup_deinit(&headers_ctx);
	return ret;
}

static int
mail_thread_children_update_parent(struct thread_context *ctx,
				   const struct mail_thread_rec *parent_rec)
{
	const struct mail_thread_rec *child_rec;
	struct mail_thread_rec tmp_rec;
	uint32_t idx;

	for (idx = parent_rec->first_child_idx; idx != 0; ) {
		if (mail_thread_rec_idx(ctx, idx, &child_rec) < 0)
			return -1;

		tmp_rec = *child_rec;
		tmp_rec.parent_idx = parent_rec->parent_idx;
		if (mail_hash_update_idx(ctx->msgid_hash, idx, &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		idx = child_rec->next_idx;
	}
	return 0;
}

static int
mail_thread_rec_unref_idx(struct thread_context *ctx, uint32_t idx,
			  const char *msgid, bool is_parent)
{
	const struct mail_thread_rec *rec;
	struct mail_thread_rec tmp_rec;
	struct msgid_rec key;

	if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
		return -1;

	if (rec->refcount == 0 ||
	    (is_parent && rec->refcount == 1 && rec->rec.uid != 0)) {
		mail_hash_set_corrupted(ctx->msgid_hash, "refcount too low");
		return -1;
	}

	if (rec->refcount == 1) {
		/* last reference to the node, remove it completely.
		   it may however still have children, so update their
		   parents */
		if (mail_thread_children_update_parent(ctx, rec) < 0)
			return -1;

		if (rec->parent_idx != 0) {
			if (unlink_child(ctx, idx, 0) < 0)
				return -1;
		}

		key.msgid = msgid != NULL ? msgid :
			mail_thread_rec_get_msgid(ctx, rec, idx);
		if (key.msgid == NULL)
			return -1;
		key.msgid_crc32 = crc32_str_nonzero(key.msgid);

		if (mail_hash_remove_idx(ctx->msgid_hash, idx, &key) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 0;
	} else {
		tmp_rec = *rec;
		tmp_rec.refcount--;

		if (mail_hash_update_idx(ctx->msgid_hash, idx, &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 1;
	}
}

static int
mail_thread_rec_get_nondummy(struct thread_context *ctx,
			     const struct mail_thread_rec *rec,
			     const struct mail_thread_rec **nondummy_rec_r)
{
	while (rec->rec.uid == 0 && rec->first_child_idx != 0) {
		if (mail_thread_rec_idx(ctx, rec->first_child_idx, &rec) < 0)
			return -1;
	}

	*nondummy_rec_r = rec;
	return 0;
}

static int mail_thread_rec_time_cmp(struct thread_context *ctx,
				    const struct mail_thread_rec *rec1,
				    const struct mail_thread_rec *rec2)
{
	/* assume that rec2 is already non-dummy */
	i_assert(rec2->rec.uid != 0 || rec2->first_child_idx == 0);

	if (rec1->rec.uid == 0) {
		if (mail_thread_rec_get_nondummy(ctx, rec1, &rec1) < 0)
			return 1;
	}

	/* use the sent date as long as both of the dates are valid */
	if (rec1->sent_date != rec2->sent_date &&
	    rec1->sent_date != 0 && rec2->sent_date != 0)
		return rec1->sent_date < rec2->sent_date ? -1 : 1;

	/* otherwise fallback to comparing UIDs.
	   put dummy records to end of list */
	if (rec1->rec.uid == 0)
		return rec2->rec.uid != 0 ? 1 : 0;
	if (rec2->rec.uid == 0)
		return -1;

	return rec1->rec.uid < rec2->rec.uid ? -1 : 1;
}

static int
update_next_idx(struct thread_context *ctx, uint32_t idx, uint32_t next_idx,
		uint32_t parent_idx)
{
	struct mail_thread_rec tmp_rec;
	const struct mail_thread_rec *rec;

	if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
		return -1;

	if (idx == parent_idx) {
		/* first child */
		tmp_rec = *rec;
		tmp_rec.first_child_idx = next_idx;
	} else {
		/* sibling */
		tmp_rec = *rec;
		tmp_rec.next_idx = next_idx;
	}
	return mail_hash_update_idx(ctx->msgid_hash, idx, &tmp_rec);
}

static int
mail_thread_update_child_pos(struct thread_context *ctx, uint32_t child_idx,
			     const struct mail_thread_rec *child_rec,
			     const struct mail_thread_rec *parent_rec,
			     bool remove_existing)
{
	const struct mail_thread_rec *rec, *cmp_rec;
	struct mail_thread_rec tmp_rec;
	uint32_t idx, prev_idx, orig_next_idx;
	bool found = FALSE;

	if (child_rec->parent_idx == 0) {
		/* we're not sorting root nodes */
		return 0;
	}

	if (parent_rec == NULL) {
		/* not given, have to look up */
		if (mail_thread_rec_idx(ctx, child_rec->parent_idx,
					&parent_rec) < 0)
			return -1;
	}

	if (parent_rec->first_child_idx == 0) {
		/* this is the first child */
		i_assert(!remove_existing);
		tmp_rec = *parent_rec;
		tmp_rec.first_child_idx = child_idx;
		if (mail_hash_update_idx(ctx->msgid_hash, child_rec->parent_idx,
					 &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	} else {
		/* find the position where we want it inserted */
		prev_idx = child_rec->parent_idx;
		orig_next_idx = child_rec->next_idx;
		idx = parent_rec->first_child_idx;
		if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
			return -1;

		if (mail_thread_rec_get_nondummy(ctx, child_rec, &cmp_rec) < 0)
			return -1;

		while (mail_thread_rec_time_cmp(ctx, rec, cmp_rec) < 0) {
			if (idx == child_idx) {
				/* unlink the child from here */
				i_assert(remove_existing);
				if (found)
					return -1;
				found = TRUE;

				i_assert(rec->next_idx == orig_next_idx);
				if (update_next_idx(ctx, prev_idx,
						    orig_next_idx,
						    child_rec->parent_idx) < 0)
					return -1;
			} else {
				prev_idx = idx;
			}
			idx = rec->next_idx;
			if (idx == 0)
				break;

			if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
				return -1;
		}

		if (idx == child_idx) {
			/* already in the right position */
			i_assert(remove_existing);
			return found ? -1 : 0;
		}

		/* insert into this position */
		if (update_next_idx(ctx, prev_idx, child_idx,
				    child_rec->parent_idx) < 0)
			return -1;

		/* update the child's next_idx */
		if (child_rec->next_idx != idx) {
			tmp_rec = *child_rec;
			tmp_rec.next_idx = idx;
			if (mail_hash_update_idx(ctx->msgid_hash, child_idx,
						 &tmp_rec) < 0)
				return -1;
		}

		if (remove_existing && !found) {
			/* go through the rest and remove the existing child */
			while (rec->next_idx != child_idx) {
				idx = rec->next_idx;
				if (idx == 0) {
					/* should have been found */
					return -1;
				}
				if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
					return -1;
			}
			if (update_next_idx(ctx, idx, orig_next_idx,
					    child_rec->parent_idx) < 0)
				return -1;
		}
	}

	if (mail_thread_rec_idx(ctx, child_rec->parent_idx, &parent_rec) < 0)
		return -1;
	if (parent_rec->rec.uid != 0 ||
	    parent_rec->first_child_idx != child_idx)
		return 0;

	/* parent is a dummy and we updated its first child.
	   that might move the parent */
	return mail_thread_update_child_pos(ctx, child_rec->parent_idx,
					    parent_rec, NULL, TRUE);
}

static int create_or_update_msg(struct thread_context *ctx, const char *msgid,
				time_t sent_date, uint32_t uid, uint32_t *idx_r)
{
	struct msgid_rec key;
	struct mail_thread_rec rec;
	const struct mail_thread_rec *recp;
	const void *value;
	uint32_t idx;
	int ret;

	memset(&rec, 0, sizeof(rec));
	rec.rec.uid = uid;
	rec.msgid_crc32 = msgid == NULL ? 0 : crc32_str_nonzero(msgid);
	rec.refcount = 1;
	rec.sent_date = sent_date;

	if (msgid == NULL) {
		if (mail_hash_insert(ctx->msgid_hash, NULL, &rec, &idx) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		*idx_r = idx;
		return 0;
	}

	key.msgid = msgid;
	key.msgid_crc32 = rec.msgid_crc32;

	ret = mail_hash_lookup(ctx->msgid_hash, &key, &value, &idx);
	if (ret < 0 || ctx->failed) {
		ctx->failed = TRUE;
		return -1;
	}
	if (ret == 0) {
		/* first time we see this message */
		if (mail_hash_insert(ctx->msgid_hash, &key, &rec, &idx) < 0) {
			ctx->failed = TRUE;
			return -1;
		}

		msgid = p_strdup(ctx->msgid_pool, msgid);
		array_idx_set(&ctx->msgid_map, idx, &msgid);
		*idx_r = idx;
		return 0;
	}

	recp = value;
	if (recp->rec.uid == 0) {
		/* seen before in references */
		const char **p;

		rec = *recp;
		rec.rec.uid = uid;
		rec.sent_date = sent_date;
		rec.refcount++;
		if (mail_hash_update_idx(ctx->msgid_hash, idx, &rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		if (mail_thread_update_child_pos(ctx, idx, &rec,
						 NULL, TRUE) < 0)
			return -1;

		p = array_idx_modifiable(&ctx->msgid_map, idx);
		if (*p == NULL)
			*p = p_strdup(ctx->msgid_pool, msgid);
	} else {
		/* duplicate */
		struct mail_thread_rec orig_rec;
		uint32_t orig_idx = idx;

		orig_rec = *recp;
		rec.msgid_crc32 = 0;
		if (mail_hash_insert(ctx->msgid_hash, NULL, &rec, &idx) < 0) {
			ctx->failed = TRUE;
			return -1;
		}

		/* if the original message gets expunged, the thread tree must
		   be rebuilt. */
		orig_rec.expunge_rebuilds = TRUE;
		if (mail_hash_update_idx(ctx->msgid_hash, orig_idx,
					 &orig_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}
	*idx_r = idx;
	return 0;
}

static int unlink_child(struct thread_context *ctx, uint32_t child_idx,
			uint32_t new_parent_idx)
{
	const struct mail_thread_rec *child_rec, *parent_rec, *sibling_rec;
	struct mail_thread_rec rec;
	uint32_t idx, parent_idx, sibling_idx;

	if (mail_thread_rec_idx(ctx, child_idx, &child_rec) < 0)
		return -1;
	if (child_rec->parent_idx == 0)
		return 0;

	parent_idx = child_rec->parent_idx;
	if (mail_thread_rec_idx(ctx, parent_idx, &parent_rec) < 0)
		return -1;

	/* find the node which links to this child */
	sibling_idx = parent_idx;
	for (idx = parent_rec->first_child_idx; idx != child_idx; ) {
		i_assert(idx != 0);

		sibling_idx = idx;
		if (mail_thread_rec_idx(ctx, sibling_idx, &parent_rec) < 0)
			return -1;
		idx = parent_rec->next_idx;
	}

	if (mail_thread_rec_idx(ctx, sibling_idx, &sibling_rec) < 0)
		return -1;
	if (mail_thread_rec_idx(ctx, child_idx, &child_rec) < 0)
		return -1;

	/* remove from old parent's children list */
	rec = *sibling_rec;
	if (sibling_idx != parent_idx)
		rec.next_idx = child_rec->next_idx;
	else
		rec.first_child_idx = child_rec->next_idx;
	i_assert(sibling_idx != rec.parent_idx);
	if (mail_hash_update_idx(ctx->msgid_hash, sibling_idx, &rec) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	if (parent_idx == sibling_idx && parent_rec->rec.uid == 0) {
		/* parent is a dummy and we removed its first child.
		   this might move the parent */
		if (mail_thread_update_child_pos(ctx, parent_idx, parent_rec,
						 NULL, TRUE) < 0)
			return -1;
	}

	/* update the child's parent. it's added to new parent's children list
	   elsewhere. since this node was originally elsewhere as a dummy,
	   expunging this node will need to move it back there. */
	rec = *child_rec;
	rec.parent_idx = new_parent_idx;
	rec.next_idx = 0;
	rec.expunge_rebuilds = TRUE;
	i_assert(child_idx != rec.parent_idx);
	if (mail_hash_update_idx(ctx->msgid_hash, child_idx, &rec) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

static bool
find_parent(struct thread_context *ctx,
	    const struct mail_thread_rec *parent_rec, uint32_t child_idx)
{
	while (parent_rec->parent_idx != 0) {
		if (parent_rec->parent_idx == child_idx)
			return TRUE;

		if (mail_thread_rec_idx(ctx, parent_rec->parent_idx,
					&parent_rec) < 0)
			return TRUE;
	}
	return FALSE;
}

static int mark_rebuild_with_parents(struct thread_context *ctx, uint32_t idx)
{
	const struct mail_thread_rec *rec;
	struct mail_thread_rec tmp_rec;

	while (idx != 0) {
		if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
			return 1;

		if (!rec->expunge_rebuilds) {
			tmp_rec = *rec;
			tmp_rec.expunge_rebuilds = TRUE;
			if (mail_hash_update_idx(ctx->msgid_hash, idx,
						 &tmp_rec) < 0) {
				ctx->failed = TRUE;
				return -1;
			}
		}
		idx = rec->parent_idx;
	}
	return 0;
}

static int
msgid_ref_or_create(struct thread_context *ctx, const char *msgid,
		    uint32_t *idx_r, const struct mail_thread_rec **rec_r)
{
	struct msgid_rec key;
	struct mail_thread_rec tmp_rec;
	const void *value;
	int ret;

	key.msgid = msgid;
	key.msgid_crc32 = crc32_str_nonzero(msgid);

	ret = mail_hash_lookup(ctx->msgid_hash, &key, &value, idx_r);
	if (ret < 0 || ctx->failed) {
		ctx->failed = TRUE;
		return -1;
	}
	if (ret > 0) {
		if (rec_r != NULL)
			*rec_r = value;

		memcpy(&tmp_rec, value, sizeof(tmp_rec));
		tmp_rec.refcount++;
		if (mail_hash_update_idx(ctx->msgid_hash, *idx_r,
					 &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 0;
	}

	/* not found, create */
	memset(&ctx->tmp_rec, 0, sizeof(ctx->tmp_rec));
	ctx->tmp_rec.msgid_crc32 = key.msgid_crc32;
	ctx->tmp_rec.refcount = 1;
	if (mail_hash_insert(ctx->msgid_hash, &key, &ctx->tmp_rec, idx_r) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	msgid = p_strdup(ctx->msgid_pool, msgid);
	array_idx_set(&ctx->msgid_map, *idx_r, &msgid);
	if (rec_r != NULL)
		*rec_r = &ctx->tmp_rec;
	return 0;
}

static int
link_to_parent_msgid(struct thread_context *ctx, const char *parent_msgid,
		     uint32_t child_idx, bool replace)
{
	const struct mail_thread_rec *child_rec, *parent_rec;
	struct mail_thread_rec tmp_rec;
	uint32_t parent_idx;

	if (mail_thread_rec_idx(ctx, child_idx, &child_rec) < 0)
		return -1;

	/* create the msgid even if we don't use it. it's important because */
	if (msgid_ref_or_create(ctx, parent_msgid,
				&parent_idx, &parent_rec) < 0)
		return -1;

	if (child_rec->parent_idx != 0 && !replace) {
		/* already got a parent, don't want to replace it.
		   if the old parent gets expunged, we'll need a rebuild */
		tmp_rec = *parent_rec;
		tmp_rec.expunge_rebuilds = TRUE;
		if (mail_hash_update_idx(ctx->msgid_hash, parent_idx,
					 &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		return 0;
	}

	/* look up again, since the pointer may have been invalidated if
	   the parent_rec was inserted into hash */
	if (mail_thread_rec_idx(ctx, child_idx, &child_rec) < 0)
		return -1;

	if (child_rec->parent_idx == parent_idx) {
		/* already have this parent, ignore */
		return 0;
	}

	if (parent_idx == child_idx ||
	    find_parent(ctx, parent_rec, child_idx)) {
		if (ctx->failed)
			return -1;

		/* this would create a loop, not allowed. if any of the
		   parents get expunged, the loop gets removed and we'll
		   need a rebuild */
		if (mark_rebuild_with_parents(ctx, parent_idx) < 0)
			return -1;
		return 0;
	}

	/* set new parent */
	if (child_rec->parent_idx != 0) {
		if (unlink_child(ctx, child_idx, parent_idx) < 0)
			return -1;
	} else {
		tmp_rec = *child_rec;
		tmp_rec.parent_idx = parent_idx;
		i_assert(child_idx != tmp_rec.parent_idx);
		if (mail_hash_update_idx(ctx->msgid_hash, child_idx,
					 &tmp_rec) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}

	/* increase parent's refcount */
	tmp_rec = *parent_rec;
	tmp_rec.refcount++;
	if (mail_hash_update_idx(ctx->msgid_hash, parent_idx, &tmp_rec) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	/* add to parent's child list */
	return mail_thread_update_child_pos(ctx, child_idx, child_rec,
					    parent_rec, FALSE);
}

static int link_message_ids(struct thread_context *ctx,
			    const char *parent_msgid, const char *child_msgid)
{
	uint32_t child_idx;

	if (msgid_ref_or_create(ctx, child_msgid, &child_idx, NULL) < 0)
		return -1;
	if (link_to_parent_msgid(ctx, parent_msgid, child_idx, FALSE) < 0)
		return -1;
	return 0;
}

static int link_references(struct thread_context *ctx, uint32_t child_idx,
			   const char *references)
{
	const char *parent_msgid, *child_msgid;

	parent_msgid = message_id_get_next(&references);
	if (parent_msgid == NULL)
		return 0;

	while ((child_msgid = message_id_get_next(&references)) != NULL) {
		if (link_message_ids(ctx, parent_msgid, child_msgid) < 0)
			return -1;
		parent_msgid = child_msgid;
	}

	/* link the last message to us */
	if (link_to_parent_msgid(ctx, parent_msgid, child_idx, TRUE) < 0)
		return -1;
	return 1;
}

static int mail_thread_input(struct thread_context *ctx, struct mail *mail)
{
	const char *refid, *message_id, *in_reply_to, *references;
	uint32_t idx;
	time_t sent_date;
	int ret;

	sent_date = mail_get_date(mail, NULL);
	if (sent_date == (time_t)-1)
		sent_date = 0;

	message_id = mail_get_first_header(mail, HDR_MESSAGE_ID);
	if (create_or_update_msg(ctx, message_id_get_next(&message_id),
				 sent_date, mail->uid, &idx) < 0)
		return -1;

	/* link references */
	references = mail_get_first_header(mail, HDR_REFERENCES);
	ret = link_references(ctx, idx, references);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		in_reply_to = mail_get_first_header(mail, HDR_IN_REPLY_TO);
		refid = in_reply_to == NULL ? NULL :
			message_id_get_next(&in_reply_to);

		if (refid != NULL) {
			if (link_to_parent_msgid(ctx, refid, idx, TRUE) < 0)
				return -1;
		} else {
			/* no references, make sure it's not linked */
			if (unlink_child(ctx, idx, 0) < 0)
				return -1;
		}
	}
	return 0;
}

static int
mail_thread_rec_idx_moved(struct thread_context *ctx, uint32_t idx,
			  bool *moved, const struct mail_thread_rec **rec_r)
{
	const struct mail_thread_moved_rec *mrec;

	if (*moved) {
		mrec = array_idx(&ctx->moved_recs, idx);
		*rec_r = &mrec->rec;
		*moved = mrec->moved_children;
		return 0;
	} else {
		return mail_thread_rec_idx(ctx, idx, rec_r);
	}
}

static int get_first_nondummy_child(struct thread_context *ctx,
				    const struct mail_thread_rec *rec,
				    uint32_t *idx_r, bool children_moved)
{
	uint32_t idx = rec->first_child_idx;
	bool sub_moved;
	int ret;

	while (idx != 0) {
		sub_moved = children_moved;
		if (mail_thread_rec_idx_moved(ctx, idx, &sub_moved, &rec) < 0)
			return -1;
		if (rec->rec.uid != 0) {
			*idx_r = idx;
			return 1;
		}

		if (rec->first_child_idx != 0) {
			ret = get_first_nondummy_child(ctx, rec, idx_r,
						       sub_moved);
			if (ret != 0)
				return ret;
		}
		idx = rec->next_idx;
	}

	return 0;
}

static int have_nondummy_children(struct thread_context *ctx,
				  const struct mail_thread_rec *rec,
				  bool children_moved)
{
	uint32_t idx;

	return get_first_nondummy_child(ctx, rec, &idx, children_moved);
}

static int
get_next_nondummy_idx(struct thread_context *ctx,
		      const struct mail_thread_rec *rec,
		      bool moved, uint32_t *idx_r)
{
	uint32_t idx = rec->next_idx;
	bool children_moved;
	int ret;

	while (idx != 0) {
		children_moved = moved;
		if (mail_thread_rec_idx_moved(ctx, idx, &children_moved,
					      &rec) < 0)
			return -1;
		if (rec->rec.uid != 0)
			break;

		if (rec->first_child_idx != 0) {
			/* does it have non-dummy children? */
			ret = have_nondummy_children(ctx, rec, children_moved);
			if (ret < 0)
				return -1;
			if (ret > 0)
				break;
		}
		idx = rec->next_idx;
	}

	*idx_r = idx;
	return 0;
}

static void add_base_subject(struct thread_context *ctx, const char *subject,
			     struct mail_thread_root_rec *rec)
{
	struct mail_thread_root_rec *hash_rec;
	char *hash_subject;
	void *key, *value;
	bool is_reply_or_forward;

	i_assert(rec->next == NULL);

	if (subject == NULL)
		return;

	subject = imap_get_base_subject_cased(pool_datastack_create(), subject,
					      &is_reply_or_forward);
	if (*subject == '\0')
		return;

	if (!hash_lookup_full(ctx->subject_hash, subject, &key, &value)) {
		hash_subject = p_strdup(ctx->subject_pool, subject);
		hash_insert(ctx->subject_hash, hash_subject, rec);
	} else {
		hash_subject = key;
		hash_rec = value;

		if (!ROOT_REC_IS_DUMMY(hash_rec) &&
		    (ROOT_REC_IS_DUMMY(rec) ||
		     (hash_rec->reply && !is_reply_or_forward))) {
			rec->next = hash_rec;
			hash_rec->nonroot = TRUE;
			hash_update(ctx->subject_hash, hash_subject, rec);
		} else {
			while (hash_rec->next != NULL)
				hash_rec = hash_rec->next;
			hash_rec->next = rec;
			rec->nonroot = TRUE;
		}
	}

	rec->reply = is_reply_or_forward;
}

static int gather_base_subjects(struct thread_context *ctx)
{
	struct mail_thread_root_rec **roots;
	const struct mail_thread_rec *rec;
	const char *subject;
	unsigned int i, count;
	uint32_t idx, uid;
	int ret;

	roots = array_get_modifiable(&ctx->roots, &count);

	ctx->subject_pool =
		pool_alloconly_create("base subjects",
				      nearest_power(count * 20));
	ctx->subject_hash =
		hash_create(default_pool, ctx->subject_pool, count * 2,
			    str_hash, (hash_cmp_callback_t *)strcmp);

	for (i = 0; i < count; i++) {
		if (roots[i]->uid != 0) {
			idx = roots[i]->idx;
			uid = roots[i]->uid;
		} else {
			/* find the first non-dummy child */
			if (mail_thread_rec_idx(ctx, roots[i]->idx, &rec) < 0)
				return -1;
			ret = get_first_nondummy_child(ctx, rec, &idx, FALSE);
			if (ret < 0)
				return -1;
			if (ret == 0) {
				/* a complete dummy thread, skip it */
				continue;
			}

			if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
				return -1;
			uid = rec->rec.uid;
		}

		if (mail_set_uid(ctx->tmp_mail, roots[i]->uid) > 0) {
			t_push();
			subject = mail_get_first_header(ctx->tmp_mail,
							HDR_SUBJECT);
			add_base_subject(ctx, subject, roots[i]);
			t_pop();
		}
	}
	return 0;
}

static int
mail_thread_root_rec_time_cmp(struct mail_thread_root_rec *r1,
			      struct mail_thread_root_rec *r2)
{
	/* use the sent date as long as both of the dates are valid */
	if (r1->sent_date != r2->sent_date &&
	    r1->sent_date != 0 && r2->sent_date != 0)
		return r1->sent_date < r2->sent_date ? -1 : 1;

	/* otherwise fallback to comparing UIDs */
	return r1->uid < r2->uid ? -1 : 1;
}

static int mrec_add_sorted(struct thread_context *ctx,
			   unsigned int parent_mrec_idx,
			   struct mail_thread_moved_rec *child_mrec,
			   uint32_t child_mrec_idx)
{
	struct mail_thread_moved_rec *mrec, *parent_mrec;
	const struct mail_thread_rec *rec, *cmp_rec, *rec_nondummy;
	uint32_t idx, prev_idx = 0;
	bool children_moved;

	if (mail_thread_rec_get_nondummy(ctx, &child_mrec->rec, &cmp_rec) < 0)
		return -1;

	parent_mrec = array_idx_modifiable(&ctx->moved_recs, parent_mrec_idx);
	for (idx = parent_mrec->rec.first_child_idx; idx != 0; ) {
		children_moved = TRUE;
		if (mail_thread_rec_idx_moved(ctx, idx, &children_moved,
					      &rec) < 0)
			return -1;
		if (mail_thread_rec_get_nondummy(ctx, rec, &rec_nondummy) < 0)
			return -1;

		if (mail_thread_rec_time_cmp(ctx, rec_nondummy, cmp_rec) > 0)
			break;

		prev_idx = idx;
		idx = rec->next_idx;
	}

	if (prev_idx == 0) {
		/* insert as first */
		child_mrec->rec.next_idx = parent_mrec->rec.first_child_idx;
		parent_mrec->rec.first_child_idx = child_mrec_idx;
	} else {
		child_mrec->rec.next_idx = idx;
		mrec = array_idx_modifiable(&ctx->moved_recs, prev_idx);
		mrec->rec.next_idx = child_mrec_idx;
	}
	return 0;
}

static int mrec_add_root(struct thread_context *ctx,
			 unsigned int parent_mrec_idx,
			 const struct mail_thread_root_rec *parent_rrec)
{
	const struct mail_thread_rec *rec;
	struct mail_thread_moved_rec *mrec;
	uint32_t mrec_idx;
	bool children_moved = parent_rrec->moved;

	if (mail_thread_rec_idx_moved(ctx, parent_rrec->idx,
				      &children_moved, &rec) < 0)
		return -1;

	mrec_idx = array_count(&ctx->moved_recs);
	mrec = array_append_space(&ctx->moved_recs);
	mrec->rec = *rec;
	mrec->moved_children = children_moved;

	return mrec_add_sorted(ctx, parent_mrec_idx, mrec, mrec_idx);
}

static int mrec_add_children(struct thread_context *ctx,
			     unsigned int parent_mrec_idx,
			     const struct mail_thread_rec *parent_rec)
{
	const struct mail_thread_rec *rec;
	struct mail_thread_moved_rec *mrec;
	uint32_t mrec_idx, idx;

	for (idx = parent_rec->first_child_idx; idx != 0; idx = rec->next_idx) {
		if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
			return -1;

		mrec_idx = array_count(&ctx->moved_recs);
		mrec = array_append_space(&ctx->moved_recs);
		mrec->rec = *rec;

		if (mrec_add_sorted(ctx, parent_mrec_idx, mrec, mrec_idx) < 0)
			return -1;
	}
	return 0;
}

static int mail_thread_root_thread_merge(struct thread_context *ctx,
					 struct mail_thread_root_rec *rrec)
{
	struct mail_thread_root_rec *next;
	const struct mail_thread_rec *rec;
	struct mail_thread_moved_rec *mrec;
	uint32_t mrec_idx;

	if (mail_thread_rec_idx(ctx, rrec->idx, &rec) < 0)
		return -1;

	if (!ROOT_REC_IS_DUMMY(rrec)) {
		/* the record has the correct date already. the following
		   messages that have the reply-flag set will be children
		   of this record. */
		next = rrec->next;
		if (next->reply) {
			/* move the parent */
			mrec_idx = array_count(&ctx->moved_recs);
			mrec = array_append_space(&ctx->moved_recs);

			mrec->rec = *rec;
			mrec->rec.first_child_idx = 0;
			mrec->moved_children = TRUE;
			rrec->moved = TRUE;
			rrec->idx = mrec_idx;

			if (mrec_add_children(ctx, mrec_idx, rec) < 0)
				return -1;

			while (next != NULL && next->reply) {
				mrec_add_root(ctx, mrec_idx, next);
				next = next->next;
			}
		}
		/* if there are more messages, they'll be siblings to this
		   record, and a dummy root will be added. */
		if (next != NULL) {
			/* create dummy */
			mrec_idx = array_count(&ctx->moved_recs);
			mrec = array_append_space(&ctx->moved_recs);
			mrec_add_root(ctx, mrec_idx, rrec);

			mrec->moved_children = TRUE;
			rrec->moved = TRUE;
			rrec->idx = mrec_idx;

			while (next != NULL) {
				mrec_add_root(ctx, mrec_idx, next);
				next = next->next;
			}
		}
	} else {
		/* add the rest of the records as children to this dummy */
		mrec_idx = array_count(&ctx->moved_recs);
		mrec = array_append_space(&ctx->moved_recs);

		mrec->rec = *rec;
		mrec->rec.first_child_idx = 0;
		mrec->moved_children = TRUE;
		rrec->moved = TRUE;
		rrec->idx = mrec_idx;

		for (next = rrec->next; next != NULL; next = next->next) {
			if (!ROOT_REC_IS_DUMMY(next))
				mrec_add_root(ctx, mrec_idx, next);
			else {
				if (mail_thread_rec_idx(ctx, next->idx,
							&rec) < 0)
					return -1;

				if (mrec_add_children(ctx, mrec_idx, rec) < 0)
					return -1;
			}
		}
	}
	return 0;
}

static int merge_subject_threads(struct thread_context *ctx)
{
	struct mail_thread_root_rec **roots;
	unsigned int i, count;

	i_array_init(&ctx->moved_recs, 128);
	(void)array_append_space(&ctx->moved_recs);

	roots = array_get_modifiable(&ctx->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->next != NULL && !roots[i]->nonroot) {
			if (mail_thread_root_thread_merge(ctx, roots[i]) < 0)
				return -1;
		}
	}
	return 0;
}

static int mail_thread_root_rec_sort_cmp(const void *p1, const void *p2)
{
	struct mail_thread_root_rec *const *rp1 = p1, *const *rp2 = p2;
	struct mail_thread_root_rec *r1 = *rp1, *r2 = *rp2;

	/* move the nonroots to the end of the array. we just want to get
	   rid of them. */
	if (r1->nonroot)
		return r2->nonroot ? 0 : 1;
	if (r2->nonroot)
		return -1;

	return mail_thread_root_rec_time_cmp(r1, r2);
}

static void sort_root_nodes(struct thread_context *ctx)
{
	struct mail_thread_root_rec **roots;
	unsigned int count;

	/* the root nodes contain the first non-dummy node's uid/sent_date,
	   so we can compare them directly. the first non-dummy node is also
	   the oldest one as the children lists are always kept sorted */
	roots = array_get_modifiable(&ctx->roots, &count);
	qsort(roots, count, sizeof(*roots), mail_thread_root_rec_sort_cmp);
}

static void update_root_dates(struct thread_context *ctx)
{
	struct mail_thread_root_rec **roots;
	unsigned int i, count;

	roots = array_get_modifiable(&ctx->roots, &count);
	for (i = 0; i < count; i++)
		roots[i]->sent_date = ctx->alt_dates[roots[i]->idx];
}

static int str_add_id(struct thread_context *ctx, string_t *str, uint32_t uid)
{
	if (!ctx->id_is_uid) {
		if (mailbox_get_uids(ctx->box, uid, uid, &uid, &uid) < 0)
			return -1;
		i_assert(uid != 0);
	}
	str_printfa(str, "%u", uid);
	return 0;
}

#define STR_NEED_FLUSH(str, extra) \
	(str_len(str) + (extra) + MAX_INT_STRLEN*2 + 3 >= OUTPUT_BUF_SIZE)

static int send_nodes(struct thread_context *ctx, string_t *str, uint32_t idx,
		      bool moved)
{
	const struct mail_thread_rec *rec;
	uint32_t next_idx;
	bool children_moved;
	int ret;

	/* FIXME: there could be some more sanity checks, for example verify
	   that nodes are returned sorted */
	children_moved = moved;
	if (mail_thread_rec_idx_moved(ctx, idx, &children_moved, &rec) < 0)
		return -1;

	if (get_next_nondummy_idx(ctx, rec, moved, &next_idx) < 0)
		return -1;
	if (next_idx == 0) {
		/* no siblings - special case to avoid extra paranthesis */
		if (rec->rec.uid == 0) {
			/* dummy node, just skip this */
			if (rec->first_child_idx != 0) {
				send_nodes(ctx, str, rec->first_child_idx,
					   children_moved);
			}
			return 0;
		}

		if ((ret = have_nondummy_children(ctx, rec,
						  children_moved)) < 0)
			return -1;

		if (str_add_id(ctx, str, rec->rec.uid) < 0)
			return -1;
		if (ret != 0) {
			str_append_c(str, ' ');
			send_nodes(ctx, str, rec->first_child_idx,
				   children_moved);
		}
		return 0;
	}

	for (;;) {
		if (STR_NEED_FLUSH(str, 0)) {
			/* string getting full, flush it */
			if (o_stream_send(ctx->output,
					  str_data(str), str_len(str)) < 0)
				return -1;
			str_truncate(str, 0);
		}

		if ((ret = have_nondummy_children(ctx, rec, children_moved)) < 0)
			return -1;
		if (ret == 0) {
			/* only child */
			if (rec->rec.uid != 0) {
				str_append_c(str, '(');
				if (str_add_id(ctx, str, rec->rec.uid) < 0)
					return -1;
				str_append_c(str, ')');
			}
		} else if (rec->rec.uid == 0) {
			/* dummy with children */
			str_append_c(str, '(');
			send_nodes(ctx, str, rec->first_child_idx,
				   children_moved);
			str_append_c(str, ')');
		} else {
			/* node with children */
			str_append_c(str, '(');
			if (str_add_id(ctx, str, rec->rec.uid) < 0)
				return -1;
			str_append_c(str, ' ');
			send_nodes(ctx, str, rec->first_child_idx,
				   children_moved);
			str_append_c(str, ')');
		}

		if (get_next_nondummy_idx(ctx, rec, moved, &idx) < 0)
			return -1;
		if (idx == 0)
			break;

		children_moved = moved;
		if (mail_thread_rec_idx_moved(ctx, idx,
					      &children_moved, &rec) < 0)
			return -1;
	}

	return 1;
}

static int send_root(struct thread_context *ctx, string_t *str,
		     struct mail_thread_root_rec *root)
{
	const struct mail_thread_rec *rec;
	const struct mail_thread_moved_rec *mrec;
	uoff_t orig_offset;
	bool moved = FALSE;

	if (STR_NEED_FLUSH(str, 1)) {
		/* string getting full, flush it */
		if (o_stream_send(ctx->output,
				  str_data(str), str_len(str)) < 0)
			return -1;
		str_truncate(str, 0);
	}

	if (root->moved) {
		mrec = array_idx(&ctx->moved_recs, root->idx);
		rec = &mrec->rec;
		moved = mrec->moved_children;
	} else {
		if (mail_thread_rec_idx(ctx, root->idx, &rec) < 0)
			return -1;
	}

	str_append_c(str, '(');
	orig_offset = ctx->output->offset + str_len(str);
	if (rec->rec.uid != 0) {
		if (str_add_id(ctx, str, rec->rec.uid) < 0)
			return -1;
	}

	if (rec->first_child_idx != 0) {
		if (rec->rec.uid != 0)
			str_append_c(str, ' ');

		if (send_nodes(ctx, str, rec->first_child_idx, moved) < 0)
			return -1;
	}

	if (ctx->output->offset + str_len(str) != orig_offset)
		str_append_c(str, ')');
	else {
		/* just a bunch of dummy nodes */
		str_truncate(str, str_len(str)-1);
	}
	return 0;
}

static int send_roots(struct thread_context *ctx)
{
	struct mail_thread_root_rec *const *roots;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(OUTPUT_BUF_SIZE);
	str_append(str, "* THREAD ");

	/* sort root nodes again, they have been modified since the last time */
	sort_root_nodes(ctx);

	roots = array_get(&ctx->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->nonroot) {
			/* nonroots are last in the list */
			break;
		}

		if (send_root(ctx, str, roots[i]) < 0)
			return -1;
	}

	str_append(str, "\r\n");
	(void)o_stream_send(ctx->output, str_data(str), str_len(str));
	return 0;
}

static int update_altdates(struct thread_context *ctx, uint32_t idx,
			   const struct mail_thread_rec *rec)
{
	const struct mail_hash_header *hdr;
	uint32_t timestamp = rec->sent_date;

	hdr = mail_hash_get_header(ctx->msgid_hash);
	for (;;) {
		if (ctx->alt_dates[idx] < timestamp) {
			/* @UNSAFE */
			ctx->alt_dates[idx] = timestamp;
		}

		idx = rec->parent_idx;
		if (idx == 0)
			break;

		if (idx > hdr->record_count) {
			mail_hash_set_corrupted(ctx->msgid_hash,
						"parent_idx too large");
			return -1;
		}

		if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
			return -1;
	}
	return 0;
}

static int mail_thread_finish(struct thread_context *ctx)
{
	const struct mail_hash_header *hdr;
	const struct mail_thread_rec *rec;
	struct mail_thread_root_rec *root_rec;
	uint32_t idx;

	if (ctx->failed)
		return -1;

	hdr = mail_hash_get_header(ctx->msgid_hash);
	if (hdr->record_count == 0)
		return 0;

	/* (2) save root nodes */
	i_array_init(&ctx->roots, I_MIN(128, hdr->record_count));
	if (ctx->thread_type == MAIL_THREAD_REFERENCES2)
		ctx->alt_dates = i_new(uint32_t, hdr->record_count + 1);
	for (idx = 1; idx <= hdr->record_count; idx++) {
		if (mail_thread_rec_idx(ctx, idx, &rec) < 0)
			return -1;

		if (MAIL_HASH_RECORD_IS_DELETED(&rec->rec))
			continue;

		if (rec->parent_idx == 0) {
			/* use the first non-dummy message's uid/sent_date
			   so that the roots can be directly sorted */
			if (mail_thread_rec_get_nondummy(ctx, rec, &rec) < 0)
				return -1;

			root_rec = p_new(ctx->msgid_pool,
					 struct mail_thread_root_rec, 1);
			root_rec->idx = idx;
			root_rec->uid = rec->rec.uid;
			root_rec->sent_date = rec->sent_date;
			array_append(&ctx->roots, &root_rec, 1);
		}

		if (ctx->thread_type == MAIL_THREAD_REFERENCES2)
			update_altdates(ctx, idx, rec);
	}

	if (ctx->thread_type == MAIL_THREAD_REFERENCES2) {
		update_root_dates(ctx);
		i_free_and_null(ctx->alt_dates);
	} else {
		/* (4) */
		sort_root_nodes(ctx);

		/* (5) Gather together messages under the root that have
		   the same base subject text. */
		if (gather_base_subjects(ctx) < 0)
			return -1;

		/* (5.C) Merge threads with the same thread subject. */
		if (merge_subject_threads(ctx) < 0)
			return -1;
	}

	/* (6) Sort again and send replies */
	t_push();
	send_roots(ctx);
	t_pop();

	return 0;
}

static int
mail_thread_rec_from_seq(struct thread_context *ctx, uint32_t seq,
			 struct msgid_rec *key_r, uint32_t *idx_r,
			 const struct mail_thread_rec **rec_r)
{
	const void *value;
	const char *message_id;

	if (mail_set_seq(ctx->tmp_mail, seq) < 0)
		return -1;

	message_id = mail_get_first_header(ctx->tmp_mail, HDR_MESSAGE_ID);
	if (message_id == NULL)
		return 0;

	key_r->msgid = message_id_get_next(&message_id);
	if (key_r->msgid == NULL)
		return 0;
	key_r->msgid_crc32 = crc32_str_nonzero(key_r->msgid);

	if (mail_hash_lookup(ctx->msgid_hash, key_r, &value, idx_r) <= 0)
		return -1;

	*rec_r = value;
	if ((*rec_r)->rec.uid != ctx->tmp_mail->uid) {
		/* duplicate Message-ID probably */
		return -1;
	}
	return 1;
}

static int mail_thread_unref_references(struct thread_context *ctx)
{
	const char *references, *msgid;
	struct msgid_rec key;
	const void *value;
	uint32_t idx;
	int ret;

	references = mail_get_first_header(ctx->tmp_mail, HDR_REFERENCES);
	if (references == NULL)
		return 0;

	msgid = message_id_get_next(&references);
	if (msgid == NULL)
		return 0;

	t_push();
	/* tmp_mail may be changed below, so we have to save the
	   references string */
	references = t_strdup(references);
	do {
		key.msgid = msgid;
		key.msgid_crc32 = crc32_str_nonzero(msgid);

		ctx->cmp_match_count = 0;
		ctx->cmp_last_idx = 0;

		ret = mail_hash_lookup(ctx->msgid_hash, &key, &value, &idx);
		if (ret < 0 || (ret == 0 && ctx->cmp_match_count != 1)) {
			ctx->failed = TRUE;
			break;
		}
		if (ret == 0) {
			/* there's only one key with this crc32 value, so it
			   must be what we're looking for */
			idx = ctx->cmp_last_idx;
			ctx->failed = FALSE;
		}
		if (mail_thread_rec_unref_idx(ctx, idx, msgid, FALSE) < 0)
			break;

		msgid = message_id_get_next(&references);
	} while (msgid != NULL);
	t_pop();

	return msgid == NULL ? 1 : -1;
}

static int mail_thread_rec_turn_to_dummy(struct thread_context *ctx,
					 const struct mail_thread_rec *rec)
{
	struct mail_thread_rec tmp_rec;
	uint32_t idx;

	idx = mail_hash_value_idx(ctx->msgid_hash, rec);
	tmp_rec = *rec;
	tmp_rec.refcount--;
	tmp_rec.sent_date = 0;
	tmp_rec.rec.uid = 0;

	if (mail_hash_update_idx(ctx->msgid_hash, idx, &tmp_rec) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	if (rec->parent_idx != 0) {
		/* since our sent_date got removed, we may need to be moved */
		if (mail_thread_update_child_pos(ctx, idx, rec, NULL, TRUE) < 0)
			return -1;
	}

	return 1;
}

static int
imap_thread_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			    uint32_t seq, const void *data __attr_unused__,
			    void **sync_context __attr_unused__,
			    void *context)
{
	struct imap_thread_mailbox *tbox = context;
	struct thread_context *ctx = tbox->ctx;
	struct msgid_rec key;
	const struct mail_thread_rec *rec;
	uint32_t idx;
	int ret;

	if (ctx == NULL) {
		/* init */
		struct mail_index_transaction *t;
		struct mailbox_transaction_context *mt;

		tbox->ctx = ctx = i_new(struct thread_context, 1);

		if (mail_hash_lock(tbox->msgid_hash) <= 0)
			return 0;

		t = mail_index_transaction_begin(sync_ctx->view, FALSE, FALSE);
		mt = MAIL_STORAGE_CONTEXT(t);

		ctx->msgid_hash = tbox->msgid_hash;
		ctx->msgid_pool =
			pool_alloconly_create("msgids", 20 * APPROX_MSGID_SIZE);
		i_array_init(&ctx->msgid_map, 20);
		ctx->tmp_mail = mail_alloc(mt, 0, NULL);
	} else if (data == NULL) {
		/* deinit */
		if (ctx->msgid_hash != NULL) {
			mail_hash_unlock(tbox->msgid_hash);
			mail_free(&ctx->tmp_mail);
			array_free(&ctx->msgid_map);
			pool_unref(ctx->msgid_pool);
		}
		i_free_and_null(tbox->ctx);
		return 0;
	} else {
		if (ctx->msgid_hash == NULL) {
			/* locking had failed */
			return 0;
		}
		if (ctx->failed)
			return 0;
	}

	if (mail_thread_rec_from_seq(ctx, seq, &key, &idx, &rec) <= 0)
		return 0;

	ret = mail_thread_unref_references(ctx);
	if (ret < 0)
		return 0;
	if (ret == 0 && rec->parent_idx != 0) {
		/* We have a parent but no References header, so it means
		   there's In-Reply-To. Don't bother verifying this, just
		   unreference the parent. */
		if (mail_thread_rec_unref_idx(ctx, rec->parent_idx,
					      NULL, TRUE) < 0)
			return 0;
	}

	/* now unreference the expunged message itself */
	if (rec->refcount == 1) {
		if (mail_thread_rec_unref_idx(ctx, idx, NULL, FALSE) < 0)
			return 0;
	} else {
		if (mail_thread_rec_turn_to_dummy(ctx, rec) <= 0)
			return 0;
	}

	return 0;
}

static int imap_thread_mailbox_close(struct mailbox *box)
{
	struct imap_thread_mailbox *tbox = IMAP_THREAD_CONTEXT(box);
	int ret;

	if (tbox->msgid_hash != NULL)
		mail_hash_free(&tbox->msgid_hash);

	ret = tbox->module_ctx.super.close(box);
	i_free(tbox);
	return ret;
}

static void imap_thread_hash_init(struct mailbox *box, bool create)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct imap_thread_mailbox *tbox = IMAP_THREAD_CONTEXT(box);
	uint32_t ext_id;

	i_assert(tbox->msgid_hash == NULL);

	tbox->msgid_hash =
		mail_hash_open(ibox->index, ".thread", create ?
			       MAIL_HASH_OPEN_FLAG_CREATE : 0,
			       sizeof(struct mail_thread_rec), 0,
			       mail_thread_hash_key,
			       mail_thread_hash_rec,
			       mail_thread_hash_cmp,
			       tbox);
	if (tbox->msgid_hash == NULL)
		return;

	ext_id = mail_index_ext_register(ibox->index, "thread", 0, 0, 0);
	mail_index_register_expunge_handler(ibox->index, ext_id, TRUE,
					    imap_thread_expunge_handler, tbox);
}

static struct mailbox_sync_context *
imap_thread_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct imap_thread_mailbox *tbox = IMAP_THREAD_CONTEXT(box);
	struct mailbox_sync_context *ctx;

	ctx = tbox->module_ctx.super.sync_init(box, flags);
	if (box->opened) {
		imap_thread_hash_init(box, FALSE);
		/* we don't want to get back here */
		box->v.sync_init = tbox->module_ctx.super.sync_init;
	}
	return ctx;
}

static void imap_thread_mailbox_opened(struct mailbox *box)
{
	struct imap_thread_mailbox *tbox;

	if (next_hook_mailbox_opened != NULL)
		next_hook_mailbox_opened(box);

	tbox = i_new(struct imap_thread_mailbox, 1);
	tbox->module_ctx.super = box->v;
	box->v.close = imap_thread_mailbox_close;

	MODULE_CONTEXT_SET(box, imap_thread_storage_module, tbox);

	if (box->opened)
		imap_thread_hash_init(box, FALSE);
	else {
		/* delayed opening used. we want to try to open the hash
		   anyway, because if syncing expunges anything and we didn't
		   notice it, we would have to rebuild the hash */
		box->v.sync_init = imap_thread_sync_init;
	}
}

void imap_thread_init(void)
{
	next_hook_mailbox_opened = hook_mailbox_opened;
	hook_mailbox_opened = imap_thread_mailbox_opened;
}

void imap_thread_deinit(void)
{
	i_assert(hook_mailbox_opened == imap_thread_mailbox_opened);
	hook_mailbox_opened = next_hook_mailbox_opened;
}
