/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "istream.h"
#include "seq-range-array.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "dsync-transaction-log-scan.h"
#include "dsync-mail.h"
#include "dsync-mailbox-import.h"

struct importer_mail {
	const char *guid;
	uint32_t uid;
};

struct importer_new_mail {
	/* linked list of mails for this GUID */
	struct importer_new_mail *next;
	/* if non-NULL, this mail exists in both local and remote. this link
	   points to the other side. */
	struct importer_new_mail *link;

	const char *guid;
	struct dsync_mail_change *change;

	uint32_t uid;
	unsigned int uid_in_local:1;
	unsigned int uid_is_usable:1;
	unsigned int skip:1;
	unsigned int copy_failed:1;
};

struct dsync_mailbox_importer {
	pool_t pool;
	struct mailbox *box;
	uint32_t last_common_uid;
	uint64_t last_common_modseq;
	uint32_t remote_uid_next;
	uint32_t remote_first_recent_uid;
	uint64_t remote_highest_modseq;

	struct mailbox_transaction_context *trans, *ext_trans;
	struct mail_search_context *search_ctx;
	struct mail *mail, *ext_mail;

	struct mail *cur_mail;
	const char *cur_guid;

	/* UID => struct dsync_mail_change */
	const struct hash_table *local_changes;

	ARRAY_TYPE(seq_range) maybe_expunge_uids;
	ARRAY_DEFINE(maybe_saves, struct dsync_mail_change *);

	/* GUID => struct importer_new_mail */
	struct hash_table *import_guids;
	/* UID => struct importer_new_mail */
	struct hash_table *import_uids;

	ARRAY_DEFINE(newmails, struct importer_new_mail *);
	ARRAY_TYPE(uint32_t) wanted_uids;

	ARRAY_DEFINE(mail_requests, struct dsync_mail_request);
	unsigned int mail_request_idx;

	uint32_t prev_uid, next_local_seq, local_uid_next;
	uint64_t local_initial_highestmodseq;

	unsigned int failed:1;
	unsigned int last_common_uid_found:1;
	unsigned int cur_uid_has_change:1;
	unsigned int cur_mail_saved:1;
	unsigned int local_expunged_guids_set:1;
	unsigned int new_uids_assigned:1;
	unsigned int want_mail_requests:1;
	unsigned int mails_have_guids:1;
	unsigned int master_brain:1;
};

static void
dsync_mailbox_import_search_init(struct dsync_mailbox_importer *importer)
{
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;

	search_args = mail_search_build_init();
	sarg = mail_search_build_add(search_args, SEARCH_UIDSET);
	p_array_init(&sarg->value.seqset, search_args->pool, 128);
	seq_range_array_add_range(&sarg->value.seqset,
				  importer->last_common_uid+1, (uint32_t)-1);

	importer->search_ctx =
		mailbox_search_init(importer->trans, search_args, NULL,
				    0, NULL);
	mail_search_args_unref(&search_args);

	if (mailbox_search_next(importer->search_ctx, &importer->cur_mail))
		importer->next_local_seq = importer->cur_mail->seq;
	/* this flag causes cur_guid to be looked up later */
	importer->cur_mail_saved = TRUE;
}

struct dsync_mailbox_importer *
dsync_mailbox_import_init(struct mailbox *box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  uint64_t last_common_modseq,
			  uint32_t remote_uid_next,
			  uint32_t remote_first_recent_uid,
			  uint64_t remote_highest_modseq,
			  enum dsync_mailbox_import_flags flags)
{
	const enum mailbox_transaction_flags ext_trans_flags =
		MAILBOX_TRANSACTION_FLAG_SYNC |
		MAILBOX_TRANSACTION_FLAG_EXTERNAL |
		MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;
	struct dsync_mailbox_importer *importer;
	struct mailbox_status status;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync mailbox importer",
				     10240);
	importer = p_new(pool, struct dsync_mailbox_importer, 1);
	importer->pool = pool;
	importer->box = box;
	importer->last_common_uid = last_common_uid;
	importer->last_common_modseq = last_common_modseq;
	importer->last_common_uid_found =
		last_common_uid != 0 || last_common_modseq != 0;
	importer->remote_uid_next = remote_uid_next;
	importer->remote_first_recent_uid = remote_first_recent_uid;
	importer->remote_highest_modseq = remote_highest_modseq;

	importer->import_guids =
		hash_table_create(default_pool, pool, 0,
				  str_hash, (hash_cmp_callback_t *)strcmp);
	importer->import_uids =
		hash_table_create(default_pool, pool, 0, NULL, NULL);
	i_array_init(&importer->maybe_expunge_uids, 16);
	i_array_init(&importer->maybe_saves, 128);
	i_array_init(&importer->newmails, 128);
	i_array_init(&importer->wanted_uids, 128);

	importer->trans = mailbox_transaction_begin(importer->box,
		MAILBOX_TRANSACTION_FLAG_SYNC);
	importer->ext_trans = mailbox_transaction_begin(box, ext_trans_flags);
	importer->mail = mail_alloc(importer->trans, 0, NULL);
	importer->ext_mail = mail_alloc(importer->ext_trans, 0, NULL);

	if ((flags & DSYNC_MAILBOX_IMPORT_FLAG_WANT_MAIL_REQUESTS) != 0) {
		i_array_init(&importer->mail_requests, 128);
		importer->want_mail_requests = TRUE;
	}
	importer->mails_have_guids =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_MAILS_HAVE_GUIDS) != 0;
	importer->master_brain =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_MASTER_BRAIN) != 0;

	mailbox_get_open_status(importer->box,
				STATUS_UIDNEXT | STATUS_HIGHESTMODSEQ,
				&status);
	importer->local_uid_next = status.uidnext;
	importer->local_initial_highestmodseq = status.highest_modseq;
	dsync_mailbox_import_search_init(importer);

	importer->local_changes = dsync_transaction_log_scan_get_hash(log_scan);
	return importer;
}

static void dsync_mail_error(struct dsync_mailbox_importer *importer,
			     struct mail *mail, const char *field)
{
	const char *errstr;
	enum mail_error error;

	errstr = mailbox_get_last_error(importer->box, &error);
	if (error == MAIL_ERROR_EXPUNGED)
		return;

	i_error("Can't lookup %s for UID=%u: %s", field, mail->uid, errstr);
	importer->failed = TRUE;
}

static bool
importer_next_mail(struct dsync_mailbox_importer *importer, uint32_t wanted_uid)
{
	if (importer->cur_mail == NULL) {
		/* end of search */
		return FALSE;
	}
	while (importer->cur_mail->seq < importer->next_local_seq ||
	       importer->cur_mail->uid < wanted_uid) {
		if (!importer->cur_uid_has_change &&
		    !importer->last_common_uid_found) {
			/* this message exists locally, but remote didn't send
			   expunge-change for it. if the message's
			   uid <= last-common-uid, it should be deleted */
			seq_range_array_add(&importer->maybe_expunge_uids, 
					    importer->cur_mail->uid);
		}

		importer->cur_mail_saved = FALSE;
		if (!mailbox_search_next(importer->search_ctx,
					 &importer->cur_mail)) {
			importer->cur_mail = NULL;
			importer->cur_guid = NULL;
			return FALSE;
		}
		importer->cur_uid_has_change = FALSE;
	}
	importer->cur_uid_has_change = importer->cur_mail != NULL &&
		importer->cur_mail->uid == wanted_uid;
	if (mail_get_special(importer->cur_mail, MAIL_FETCH_GUID,
			     &importer->cur_guid) < 0) {
		dsync_mail_error(importer, importer->cur_mail, "GUID");
		return importer_next_mail(importer, wanted_uid);
	}
	/* make sure next_local_seq gets updated in case we came here
	   because of min_uid */
	importer->next_local_seq = importer->cur_mail->seq;
	return TRUE;
}

static int
importer_mail_cmp(const struct importer_mail *m1,
		  const struct importer_mail *m2)
{
	int ret;

	if (m1->guid == NULL)
		return 1;
	if (m2->guid == NULL)
		return -1;

	ret = strcmp(m1->guid, m2->guid);
	if (ret != 0)
		return ret;

	if (m1->uid < m2->uid)
		return -1;
	if (m1->uid > m2->uid)
		return 1;
	return 0;
}

static void importer_mail_request(struct dsync_mailbox_importer *importer,
				  struct importer_new_mail *newmail)
{
	struct dsync_mail_request *request;

	if (importer->want_mail_requests && !newmail->uid_in_local) {
		request = array_append_space(&importer->mail_requests);
		request->guid = newmail->guid;
		request->uid = newmail->uid;
	}
}

static void newmail_link(struct dsync_mailbox_importer *importer,
			 struct importer_new_mail *newmail)
{
	struct importer_new_mail *first_mail, **last, *mail, *link = NULL;

	if (*newmail->guid != '\0') {
		first_mail = hash_table_lookup(importer->import_guids,
					       newmail->guid);
		if (first_mail == NULL) {
			/* first mail for this GUID */
			hash_table_insert(importer->import_guids,
					  (void *)newmail->guid, newmail);
			importer_mail_request(importer, newmail);
			return;
		}
	} else {
		if (!newmail->uid_in_local) {
			/* FIXME: ? */
			return;
		}
		first_mail = hash_table_lookup(importer->import_uids,
					POINTER_CAST(newmail->uid));
		if (first_mail == NULL) {
			/* first mail for this UID */
			hash_table_insert(importer->import_uids,
					  POINTER_CAST(newmail->uid), newmail);
			importer_mail_request(importer, newmail);
			return;
		}
	}
	/* 1) add the newmail to the end of the linked list
	   2) find our link */
	last = &first_mail->next;
	for (mail = first_mail; mail != NULL; mail = mail->next) {
		if (mail->uid == newmail->uid)
			mail->uid_is_usable = TRUE;
		if (link == NULL && mail->link == NULL &&
		    mail->uid_in_local != newmail->uid_in_local)
			link = mail;
		last = &mail->next;
	}
	*last = newmail;
	if (link != NULL && newmail->link == NULL) {
		link->link = newmail;
		newmail->link = link;
	}
}

static bool dsync_mailbox_try_save_cur(struct dsync_mailbox_importer *importer,
				       struct dsync_mail_change *save_change)
{
	struct importer_mail m1, m2;
	struct importer_new_mail *newmail;
	int diff;
	bool remote_saved;

	memset(&m1, 0, sizeof(m1));
	if (importer->cur_mail != NULL) {
		m1.guid = importer->cur_guid;
		m1.uid = importer->cur_mail->uid;
	}
	memset(&m2, 0, sizeof(m2));
	if (save_change != NULL) {
		m2.guid = save_change->guid;
		m2.uid = save_change->uid;
	}

	newmail = p_new(importer->pool, struct importer_new_mail, 1);

	diff = importer_mail_cmp(&m1, &m2);
	if (diff < 0) {
		/* add a record for local mail */
		i_assert(importer->cur_mail != NULL);
		newmail->guid = p_strdup(importer->pool, importer->cur_guid);
		newmail->uid = importer->cur_mail->uid;
		newmail->uid_in_local = TRUE;
		newmail->uid_is_usable =
			newmail->uid >= importer->remote_uid_next;
		remote_saved = FALSE;
	} else if (diff > 0) {
		i_assert(save_change != NULL);
		newmail->guid = save_change->guid;
		newmail->uid = save_change->uid;
		newmail->uid_in_local = FALSE;
		newmail->uid_is_usable =
			newmail->uid >= importer->local_uid_next;
		remote_saved = TRUE;
	} else {
		/* identical */
		i_assert(importer->cur_mail != NULL);
		i_assert(save_change != NULL);
		newmail->guid = save_change->guid;
		newmail->uid = importer->cur_mail->uid;
		newmail->uid_in_local = TRUE;
		newmail->uid_is_usable = TRUE;
		newmail->link = newmail;
		remote_saved = TRUE;
	}

	if (newmail->uid_in_local) {
		importer->cur_mail_saved = TRUE;
		importer->next_local_seq++;
	} else {
		/* NOTE: assumes save_change is allocated from importer pool */
		newmail->change = save_change;
	}

	array_append(&importer->newmails, &newmail, 1);
	newmail_link(importer, newmail);
	return remote_saved;
}

static bool ATTR_NULL(2)
dsync_mailbox_try_save(struct dsync_mailbox_importer *importer,
		       struct dsync_mail_change *save_change)
{
	if (importer->cur_mail_saved) {
		if (!importer_next_mail(importer, 0) && save_change == NULL)
			return FALSE;
	}
	return dsync_mailbox_try_save_cur(importer, save_change);
}

static void dsync_mailbox_save(struct dsync_mailbox_importer *importer,
			       struct dsync_mail_change *save_change)
{
	while (!dsync_mailbox_try_save(importer, save_change)) ;
}

static bool
dsync_import_set_mail(struct dsync_mailbox_importer *importer,
		      const struct dsync_mail_change *change)
{
	const char *guid;

	if (!mail_set_uid(importer->mail, change->uid))
		return FALSE;
	if (change->guid == NULL) {
		/* GUID is unknown */
		return TRUE;
	}
	if (*change->guid == '\0') {
		/* backend doesn't support GUIDs. if hdr_hash is set, we could
		   verify it, but since this message really is supposed to
		   match, it's probably too much trouble. */
		return TRUE;
	}

	/* verify that GUID matches, just in case */
	if (mail_get_special(importer->mail, MAIL_FETCH_GUID, &guid) < 0) {
		dsync_mail_error(importer, importer->mail, "GUID");
		return FALSE;
	}
	if (strcmp(guid, change->guid) != 0) {
		i_error("Mailbox %s: Unexpected GUID mismatch for "
			"UID=%u: %s != %s", mailbox_get_vname(importer->box),
			change->uid, guid, change->guid);
		importer->last_common_uid = 1;
		importer->failed = TRUE;
		return FALSE;
	}
	return TRUE;
}

static void
merge_flags(uint32_t local_final, uint32_t local_add, uint32_t local_remove,
	    uint32_t remote_final, uint32_t remote_add, uint32_t remote_remove,
	    bool prefer_remote,
	    uint32_t *change_add_r, uint32_t *change_remove_r)
{
	uint32_t combined_add, combined_remove, conflict_flags;
	uint32_t local_wanted, remote_wanted;

	/* resolve conflicts */
	conflict_flags = local_add & remote_remove;
	if (conflict_flags != 0) {
		if (prefer_remote)
			local_add &= ~conflict_flags;
		else
			remote_remove &= ~conflict_flags;
	}
	conflict_flags = local_remove & remote_add;
	if (conflict_flags != 0) {
		if (prefer_remote)
			local_remove &= ~conflict_flags;
		else
			remote_add &= ~conflict_flags;
	}
	combined_add = local_add|remote_add;
	combined_remove = local_remove|remote_remove;
	i_assert((combined_add & combined_remove) == 0);

	/* see if there are conflicting final flags */
	local_wanted = (local_final|combined_add) & ~combined_remove;
	remote_wanted = (remote_final|combined_add) & ~combined_remove;

	conflict_flags = local_wanted ^ remote_wanted;
	if (conflict_flags != 0) {
		if (prefer_remote)
			local_wanted = remote_wanted;
		/*else
			remote_wanted = local_wanted;*/
	}

	*change_add_r = local_wanted & ~local_final;
	*change_remove_r = local_final & ~local_wanted;
}

static bool
keyword_find(ARRAY_TYPE(const_string) *keywords, const char *name,
	     unsigned int *idx_r)
{
	const char *const *names;
	unsigned int i, count;

	names = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(names[i], name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static void keywords_append(ARRAY_TYPE(const_string) *dest,
			    const ARRAY_TYPE(const_string) *keywords,
			    uint32_t bits, unsigned int start_idx)
{
	const char *const *namep;
	unsigned int i;

	for (i = 0; i < 32; i++) {
		if ((bits & (1U << i)) == 0)
			continue;

		namep = array_idx(keywords, start_idx+i);
		array_append(dest, namep, 1);
	}
}

static void
merge_keywords(struct mail *mail, const ARRAY_TYPE(const_string) *local_changes,
	       const ARRAY_TYPE(const_string) *remote_changes,
	       bool prefer_remote)
{
	/* local_changes and remote_changes are assumed to have no
	   duplicates names */
	uint32_t *local_add, *local_remove, *local_final;
	uint32_t *remote_add, *remote_remove, *remote_final;
	uint32_t *change_add, *change_remove;
	ARRAY_TYPE(const_string) all_keywords, add_keywords, remove_keywords;
	const char *const *changes, *name, *const *local_keywords;
	struct mail_keywords *kw;
	unsigned int i, count, name_idx, array_size;

	local_keywords = mail_get_keywords(mail);

	/* we'll assign a common index for each keyword name and place
	   the changes to separate bit arrays. */
	if (array_is_created(remote_changes))
		changes = array_get(remote_changes, &count);
	else {
		changes = NULL;
		count = 0;
	}

	array_size = str_array_length(local_keywords) + count;
	if (array_is_created(local_changes))
		array_size += array_count(local_changes);
	if (array_size == 0) {
		/* this message has no keywords */
		return;
	}
	t_array_init(&all_keywords, array_size);
	t_array_init(&add_keywords, array_size);
	t_array_init(&remove_keywords, array_size);

	/* @UNSAFE: create large enough arrays to fit all keyword indexes. */
	array_size = (array_size+31)/32;
	local_add = t_new(uint32_t, array_size);
	local_remove = t_new(uint32_t, array_size);
	local_final = t_new(uint32_t, array_size);
	remote_add = t_new(uint32_t, array_size);
	remote_remove = t_new(uint32_t, array_size);
	remote_final = t_new(uint32_t, array_size);
	change_add = t_new(uint32_t, array_size);
	change_remove = t_new(uint32_t, array_size);

	/* get remote changes */
	for (i = 0; i < count; i++) {
		name = changes[i]+1;
		name_idx = array_count(&all_keywords);
		array_append(&all_keywords, &name, 1);

		switch (changes[i][0]) {
		case KEYWORD_CHANGE_ADD:
			remote_add[name_idx/32] |= 1U << (name_idx%32);
			/* fall through */
		case KEYWORD_CHANGE_FINAL:
			remote_final[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_REMOVE:
			remote_remove[name_idx/32] |= 1U << (name_idx%32);
			break;
		}
	}

	/* get local changes. use existing indexes for names when they exist. */
	if (array_is_created(local_changes))
		changes = array_get(local_changes, &count);
	else {
		changes = NULL;
		count = 0;
	}
	for (i = 0; i < count; i++) {
		name = changes[i]+1;
		if (!keyword_find(&all_keywords, name, &name_idx)) {
			name_idx = array_count(&all_keywords);
			array_append(&all_keywords, &name, 1);
		}

		switch (changes[i][0]) {
		case KEYWORD_CHANGE_ADD:
			local_add[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_REMOVE:
			local_remove[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_FINAL:
			i_unreached();
		}
	}
	for (i = 0; local_keywords[i] != NULL; i++) {
		name = local_keywords[i];
		if (!keyword_find(&all_keywords, name, &name_idx)) {
			name_idx = array_count(&all_keywords);
			array_append(&all_keywords, &name, 1);
		}
		local_final[name_idx/32] |= 1U << (name_idx%32);
	}
	i_assert(array_count(&all_keywords) <= array_size*32);
	array_size = (array_count(&all_keywords)+31) / 32;

	/* merge keywords */
	for (i = 0; i < array_size; i++) {
		merge_flags(local_final[i], local_add[i], local_remove[i],
			    remote_final[i], remote_add[i], remote_remove[i],
			    prefer_remote, &change_add[i], &change_remove[i]);
		if (change_add[i] != 0) {
			keywords_append(&add_keywords, &all_keywords,
					change_add[i], i*32);
		}
		if (change_remove[i] != 0) {
			keywords_append(&remove_keywords, &all_keywords,
					change_add[i], i*32);
		}
	}

	/* apply changes */
	if (array_count(&add_keywords) > 0) {
		(void)array_append_space(&add_keywords);
		kw = mailbox_keywords_create_valid(mail->box,
			array_idx(&add_keywords, 0));
		mail_update_keywords(mail, MODIFY_ADD, kw);
		mailbox_keywords_unref(&kw);
	}
	if (array_count(&remove_keywords) > 0) {
		(void)array_append_space(&remove_keywords);
		kw = mailbox_keywords_create_valid(mail->box,
			array_idx(&remove_keywords, 0));
		mail_update_keywords(mail, MODIFY_REMOVE, kw);
		mailbox_keywords_unref(&kw);
	}
}

static void
dsync_mailbox_import_flag_change(struct dsync_mailbox_importer *importer,
				 const struct dsync_mail_change *change)
{
	const struct dsync_mail_change *local_change;
	enum mail_flags local_add, local_remove;
	uint32_t change_add, change_remove;
	ARRAY_TYPE(const_string) local_keyword_changes = ARRAY_INIT;
	struct mail *mail;
	bool prefer_remote;

	i_assert((change->add_flags & change->remove_flags) == 0);

	if (importer->cur_mail != NULL &&
	    importer->cur_mail->uid == change->uid)
		mail = importer->cur_mail;
	else {
		if (!dsync_import_set_mail(importer, change))
			return;
		mail = importer->mail;
	}

	local_change = hash_table_lookup(importer->local_changes,
					 POINTER_CAST(change->uid));
	if (local_change == NULL) {
		local_add = local_remove = 0;
	} else {
		local_add = local_change->add_flags;
		local_remove = local_change->remove_flags;
		local_keyword_changes = local_change->keyword_changes;
	}

	if (mail_get_modseq(mail) < change->modseq)
		prefer_remote = TRUE;
	else if (mail_get_modseq(mail) > change->modseq)
		prefer_remote = FALSE;
	else {
		/* identical modseq, we'll just have to pick one.
		   Note that both brains need to pick the same one, otherwise
		   they become unsynced. */
		prefer_remote = !importer->master_brain;
	}

	/* merge flags */
	merge_flags(mail_get_flags(mail), local_add, local_remove,
		    change->final_flags, change->add_flags, change->remove_flags,
		    prefer_remote, &change_add, &change_remove);

	if (change_add != 0)
		mail_update_flags(mail, MODIFY_ADD, change_add);
	if (change_remove != 0)
		mail_update_flags(mail, MODIFY_REMOVE, change_remove);

	/* merge keywords */
	merge_keywords(mail, &local_keyword_changes, &change->keyword_changes,
		       prefer_remote);
	mail_update_modseq(mail, change->modseq);
}

static void
dsync_mailbox_import_save(struct dsync_mailbox_importer *importer,
			  const struct dsync_mail_change *change)
{
	struct dsync_mail_change *save;

	i_assert(change->guid != NULL);

	if (change->uid == importer->last_common_uid) {
		/* we've already verified that the GUID matches.
		   apply flag changes if there are any. */
		i_assert(!importer->last_common_uid_found);
		dsync_mailbox_import_flag_change(importer, change);
		return;
	}

	save = p_new(importer->pool, struct dsync_mail_change, 1);
	dsync_mail_change_dup(importer->pool, change, save);

	if (importer->last_common_uid_found) {
		/* this is a new mail. its UID may or may not conflict with
		   an existing local mail, we'll figure it out later. */
		i_assert(change->uid > importer->last_common_uid);
		dsync_mailbox_save(importer, save);
	} else {
		/* the local mail is expunged. we'll decide later if we want
		   to save this mail locally or expunge it form remote. */
		i_assert(change->uid > importer->last_common_uid);
		i_assert(change->uid < importer->cur_mail->uid);
		array_append(&importer->maybe_saves, &save, 1);
	}
}

static void
dsync_mailbox_import_expunge(struct dsync_mailbox_importer *importer,
			     const struct dsync_mail_change *change)
{

	if (importer->last_common_uid_found) {
		/* expunge the message, unless its GUID unexpectedly doesn't
		   match */
		i_assert(change->uid <= importer->last_common_uid);
		if (dsync_import_set_mail(importer, change))
			mail_expunge(importer->mail);
	} else if (change->uid < importer->cur_mail->uid) {
		/* already expunged locally, we can ignore this.
		   uid=last_common_uid if we managed to verify from
		   transaction log that the GUIDs match */
		i_assert(change->uid >= importer->last_common_uid);
	} else if (change->uid == importer->last_common_uid) {
		/* already verified that the GUID matches */
		i_assert(importer->cur_mail->uid == change->uid);
		mail_expunge(importer->cur_mail);
	} else {
		/* we don't know yet if we should expunge this
		   message or not. queue it until we do. */
		i_assert(change->uid > importer->last_common_uid);
		seq_range_array_add(&importer->maybe_expunge_uids, change->uid);
	}
}

static void
dsync_mailbox_rewind_search(struct dsync_mailbox_importer *importer)
{
	/* If there are local mails after last_common_uid which we skipped
	   while trying to match the next message, we need to now go back */
	if (importer->cur_mail != NULL &&
	    importer->cur_mail->uid <= importer->last_common_uid+1)
		return;

	importer->cur_mail = NULL;
	importer->cur_guid = NULL;
	importer->next_local_seq = 0;

	(void)mailbox_search_deinit(&importer->search_ctx);
	dsync_mailbox_import_search_init(importer);
}

static void
dsync_mailbox_common_uid_found(struct dsync_mailbox_importer *importer)
{
	struct dsync_mail_change *const *saves;
	struct seq_range_iter iter;
	unsigned int n, i, count;
	uint32_t uid;

	importer->last_common_uid_found = TRUE;
	dsync_mailbox_rewind_search(importer);

	/* expunge the messages whose expunge-decision we delayed previously */
	seq_range_array_iter_init(&iter, &importer->maybe_expunge_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		if (uid > importer->last_common_uid) {
			/* we expunge messages only up to last_common_uid,
			   ignore the rest */
			break;
		}

		if (mail_set_uid(importer->mail, uid))
			mail_expunge(importer->mail);
	}

	/* handle pending saves */
	saves = array_get(&importer->maybe_saves, &count);
	for (i = 0; i < count; i++) {
		if (saves[i]->uid > importer->last_common_uid)
			dsync_mailbox_save(importer, saves[i]);
	}
}

static int
dsync_mailbox_import_match_msg(struct dsync_mailbox_importer *importer,
			       const struct dsync_mail_change *change)
{
	const char *hdr_hash;

	if (*change->guid != '\0' && *importer->cur_guid != '\0') {
		/* we have GUIDs, verify them */
		return strcmp(change->guid, importer->cur_guid) == 0 ? 1 : 0;
	}

	/* verify hdr_hash if it exists */
	if (change->hdr_hash == NULL) {
		i_assert(*importer->cur_guid == '\0');
		i_error("Mailbox %s: GUIDs not supported, "
			"sync with header hashes instead",
			mailbox_get_vname(importer->box));
		importer->failed = TRUE;
		return -1;
	}

	if (dsync_mail_get_hdr_hash(importer->cur_mail, &hdr_hash) < 0) {
		dsync_mail_error(importer, importer->cur_mail, "hdr-stream");
		return -1;
	}
	return strcmp(change->hdr_hash, hdr_hash) == 0 ? 1 : 0;
}

static void
dsync_mailbox_find_common_uid(struct dsync_mailbox_importer *importer,
			      const struct dsync_mail_change *change)
{
	const struct dsync_mail_change *local_change;
	guid_128_t guid_128, change_guid_128;
	int ret;

	/* try to find the matching local mail */
	if (!importer_next_mail(importer, change->uid)) {
		/* no more local mails. use the last message with a matching
		   GUID as the last common UID. */
		dsync_mailbox_common_uid_found(importer);
		return;
	}

	if (change->guid == NULL) {
		/* we can't know if this UID matches */
		return;
	}
	if (importer->cur_mail->uid == change->uid) {
		/* we have a matching local UID. check GUID to see if it's
		   really the same mail or not */
		if ((ret = dsync_mailbox_import_match_msg(importer, change)) < 0) {
			/* unknown */
			return;
		}
		if (ret == 0) {
			/* mismatch - found the first non-common UID */
			dsync_mailbox_common_uid_found(importer);
		} else {
			importer->last_common_uid = change->uid;
		}
		return;
	}

	if (*change->guid == '\0') {
		/* remote doesn't support GUIDs, can't verify expunge */
		return;
	}

	/* local message is expunged. see if we can find its GUID from
	   transaction log and check if the GUIDs match. The GUID in
	   log is a 128bit GUID, so we may need to convert the remote's
	   GUID string to 128bit GUID first. */
	local_change = hash_table_lookup(importer->local_changes,
					 POINTER_CAST(change->uid));
	if (local_change == NULL || local_change->guid == NULL)
		return;
	if (guid_128_from_string(local_change->guid, guid_128) < 0)
		i_unreached();

	mail_generate_guid_128_hash(change->guid, change_guid_128);
	if (memcmp(change_guid_128, guid_128, GUID_128_SIZE) != 0) {
		/* mismatch - found the first non-common UID */
		dsync_mailbox_common_uid_found(importer);
	} else {
		importer->last_common_uid = change->uid;
	}
	return;
}

void dsync_mailbox_import_change(struct dsync_mailbox_importer *importer,
				 const struct dsync_mail_change *change)
{
	i_assert(!importer->new_uids_assigned);
	i_assert(importer->prev_uid < change->uid);

	importer->prev_uid = change->uid;

	if (!importer->last_common_uid_found)
		dsync_mailbox_find_common_uid(importer, change);

	if (importer->last_common_uid_found) {
		/* a) uid <= last_common_uid for flag changes and expunges.
		   this happens only when last_common_uid was originally given
		   as parameter to importer.

		   when we're finding the last_common_uid ourself,
		   uid>last_common_uid always in here, because
		   last_common_uid_found=TRUE only after we find the first
		   mismatch.

		   b) uid > last_common_uid for i) new messages, ii) expunges
		   that were sent "just in case" */
		if (change->uid <= importer->last_common_uid) {
			i_assert(change->type != DSYNC_MAIL_CHANGE_TYPE_SAVE);
		} else if (change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
			/* ignore */
			return;
		} else {
			i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_SAVE);
		}
	} else {
		/* a) uid < last_common_uid can never happen */
		i_assert(change->uid >= importer->last_common_uid);
		/* b) uid = last_common_uid if we've verified that the
		   messages' GUIDs match so far.

		   c) uid > last_common_uid: i) TYPE_EXPUNGE change has
		   GUID=NULL, so we couldn't verify yet if it matches our
		   local message, ii) local message is expunged and we couldn't
		   find its GUID */
		if (change->uid > importer->last_common_uid) {
			i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE ||
				 change->uid < importer->cur_mail->uid);
		}
	}

	switch (change->type) {
	case DSYNC_MAIL_CHANGE_TYPE_SAVE:
		dsync_mailbox_import_save(importer, change);
		break;
	case DSYNC_MAIL_CHANGE_TYPE_EXPUNGE:
		dsync_mailbox_import_expunge(importer, change);
		break;
	case DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE:
		i_assert(importer->last_common_uid_found);
		dsync_mailbox_import_flag_change(importer, change);
		break;
	}
}

static void
dsync_msg_update_uid(struct dsync_mailbox_importer *importer,
		     uint32_t old_uid, uint32_t new_uid)
{
	struct mail_save_context *save_ctx;

	if (!mail_set_uid(importer->mail, old_uid))
		return;

	save_ctx = mailbox_save_alloc(importer->ext_trans);
	mailbox_save_copy_flags(save_ctx, importer->mail);
	mailbox_save_set_uid(save_ctx, new_uid);
	if (mailbox_copy(&save_ctx, importer->mail) == 0) {
		array_append(&importer->wanted_uids, &new_uid, 1);
		mail_expunge(importer->mail);
	}
}

static void
dsync_mailbox_import_assign_new_uids(struct dsync_mailbox_importer *importer)
{
	struct importer_new_mail *newmail, *const *newmailp;
	uint32_t common_uid_next, new_uid;

	common_uid_next = I_MAX(importer->local_uid_next,
				importer->remote_uid_next);
	array_foreach_modifiable(&importer->newmails, newmailp) {
		newmail = *newmailp;
		if (newmail->skip) {
			/* already assigned */
			if (newmail->uid_in_local) {
				if (mail_set_uid(importer->mail, newmail->uid))
					mail_expunge(importer->mail);
			}
			continue;
		}

		/* figure out what UID to use for the mail */
		if (newmail->uid_is_usable) {
			/* keep the UID */
			new_uid = newmail->uid;
		} else if (newmail->link != NULL &&
			 newmail->link->uid_is_usable)
			new_uid = newmail->link->uid;
		else
			new_uid = common_uid_next++;

		if (newmail->uid_in_local && newmail->uid != new_uid) {
			/* local UID changed, reassign it by copying */
			dsync_msg_update_uid(importer, newmail->uid, new_uid);
		}
		newmail->uid = new_uid;

		if (newmail->link != NULL) {
			/* skip the linked mail */
			newmail->link->skip = TRUE;
		}
	}
	importer->last_common_uid = common_uid_next;
	importer->new_uids_assigned = TRUE;
}

void dsync_mailbox_import_changes_finish(struct dsync_mailbox_importer *importer)
{
	i_assert(!importer->new_uids_assigned);

	if (!importer->last_common_uid_found) {
		/* handle pending expunges and flag updates */
		dsync_mailbox_common_uid_found(importer);
	}
	/* skip common local mails */
	(void)importer_next_mail(importer, importer->last_common_uid+1);
	/* if there are any local mails left, add them to newmails list */
	while (importer->cur_mail != NULL)
		(void)dsync_mailbox_try_save(importer, NULL);

	dsync_mailbox_import_assign_new_uids(importer);
}

const struct dsync_mail_request *
dsync_mailbox_import_next_request(struct dsync_mailbox_importer *importer)
{
	const struct dsync_mail_request *requests;
	unsigned int count;

	requests = array_get(&importer->mail_requests, &count);
	if (importer->mail_request_idx == count)
		return NULL;
	return &requests[importer->mail_request_idx++];
}

static const char *const *
dsync_mailbox_get_final_keywords(const struct dsync_mail_change *change)
{
	ARRAY_TYPE(const_string) keywords;
	const char *const *changes;
	unsigned int i, count;

	if (!array_is_created(&change->keyword_changes))
		return NULL;

	changes = array_get(&change->keyword_changes, &count);
	t_array_init(&keywords, count);
	for (i = 0; i < count; i++) {
		if (changes[i][0] == KEYWORD_CHANGE_ADD ||
		    changes[i][0] == KEYWORD_CHANGE_FINAL) {
			const char *name = changes[i]+1;

			array_append(&keywords, &name, 1);
		}
	}
	if (array_count(&keywords) == 0)
		return NULL;

	(void)array_append_space(&keywords);
	return array_idx(&keywords, 0);
}

static void
dsync_mailbox_save_set_metadata(struct dsync_mailbox_importer *importer,
				struct mail_save_context *save_ctx,
				const struct dsync_mail_change *change)
{
	const char *const *keyword_names;
	struct mail_keywords *keywords;

	keyword_names = dsync_mailbox_get_final_keywords(change);
	keywords = keyword_names == NULL ? NULL :
		mailbox_keywords_create_valid(importer->box,
					      keyword_names);
	mailbox_save_set_flags(save_ctx, change->final_flags, keywords);
	if (keywords != NULL)
		mailbox_keywords_unref(&keywords);

	mailbox_save_set_save_date(save_ctx, change->save_timestamp);
	if (change->modseq > 1) {
		(void)mailbox_enable(importer->box, MAILBOX_FEATURE_CONDSTORE);
		mailbox_save_set_min_modseq(save_ctx, change->modseq);
	}
}

static int
dsync_msg_try_copy(struct dsync_mailbox_importer *importer,
		   struct mail_save_context **save_ctx_p,
		   struct importer_new_mail *all_newmails)
{
	struct importer_new_mail *inst;

	for (inst = all_newmails; inst != NULL; inst = inst->next) {
		if (inst->uid_in_local && !inst->copy_failed &&
		    mail_set_uid(importer->mail, inst->uid)) {
			if (mailbox_copy(save_ctx_p, importer->mail) < 0) {
				inst->copy_failed = TRUE;
				return -1;
			}
			return 1;
		}
	}
	return 0;
}

static struct mail_save_context *
dsync_mailbox_save_init(struct dsync_mailbox_importer *importer,
			const struct dsync_mail *mail,
			struct importer_new_mail *newmail)
{
	struct mail_save_context *save_ctx;

	save_ctx = mailbox_save_alloc(importer->ext_trans);
	mailbox_save_set_uid(save_ctx, newmail->uid);
	if (*mail->guid != '\0')
		mailbox_save_set_guid(save_ctx, mail->guid);
	dsync_mailbox_save_set_metadata(importer, save_ctx, newmail->change);
	if (*mail->pop3_uidl != '\0')
		mailbox_save_set_pop3_uidl(save_ctx, mail->pop3_uidl);
	if (mail->pop3_order > 0)
		mailbox_save_set_pop3_order(save_ctx, mail->pop3_order);
	mailbox_save_set_received_date(save_ctx, mail->received_date, 0);
	return save_ctx;
}

static void dsync_mailbox_save_body(struct dsync_mailbox_importer *importer,
				    const struct dsync_mail *mail,
				    struct importer_new_mail *newmail,
				    struct importer_new_mail *all_newmails)
{
	struct mail_save_context *save_ctx;
	ssize_t ret;
	bool save_failed = FALSE;

	/* try to save the mail by copying an existing mail */
	save_ctx = dsync_mailbox_save_init(importer, mail, newmail);
	if ((ret = dsync_msg_try_copy(importer, &save_ctx, all_newmails)) < 0) {
		if (save_ctx == NULL)
			save_ctx = dsync_mailbox_save_init(importer, mail, newmail);
	}
	if (ret > 0) {
		array_append(&importer->wanted_uids, &newmail->uid, 1);
		return;
	}
	/* fallback to saving from remote stream */

	if (mail->input == NULL) {
		/* it was just expunged in remote, skip it */
		mailbox_save_cancel(&save_ctx);
		return;
	}

	i_stream_seek(mail->input, 0);
	if (mailbox_save_begin(&save_ctx, mail->input) < 0) {
		i_error("Can't save message to mailbox %s: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_error(importer->box, NULL));
		importer->failed = TRUE;
		return;
	}
	while ((ret = i_stream_read(mail->input)) > 0 || ret == -2) {
		if (mailbox_save_continue(save_ctx) < 0) {
			save_failed = TRUE;
			ret = -1;
			break;
		}
	}
	i_assert(ret == -1);

	if (mail->input->stream_errno != 0) {
		errno = mail->input->stream_errno;
		i_error("read(msg input) failed: %m");
		mailbox_save_cancel(&save_ctx);
		importer->failed = TRUE;
	} else if (save_failed) {
		mailbox_save_cancel(&save_ctx);
		importer->failed = TRUE;
	} else {
		i_assert(mail->input->eof);
		if (mailbox_save_finish(&save_ctx) < 0) {
			i_error("Can't save message to mailbox %s: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_error(importer->box, NULL));
			importer->failed = TRUE;
		} else {
			array_append(&importer->wanted_uids, &newmail->uid, 1);
		}
	}
}

void dsync_mailbox_import_mail(struct dsync_mailbox_importer *importer,
			       const struct dsync_mail *mail)
{
	struct importer_new_mail *newmail, *allmails;

	i_assert(mail->input->seekable);
	i_assert(importer->new_uids_assigned);

	newmail = *mail->guid != '\0' ?
		hash_table_lookup(importer->import_guids, mail->guid) :
		hash_table_lookup(importer->import_uids, POINTER_CAST(mail->uid));
	if (newmail == NULL) {
		if (importer->want_mail_requests) {
			i_error("%s: Remote sent unwanted message body for "
				"GUID=%s UID=%u",
				mailbox_get_vname(importer->box),
				mail->guid, mail->uid);
		}
		return;
	}
	if (*mail->guid != '\0')
		hash_table_remove(importer->import_guids, mail->guid);
	else {
		hash_table_remove(importer->import_uids,
				  POINTER_CAST(mail->uid));
	}

	/* save all instances of the message */
	allmails = newmail;
	for (; newmail != NULL; newmail = newmail->next) {
		if (newmail->skip) {
			/* no need to do anything for this mail */
			continue;
		}
		if (newmail->uid_in_local) {
			/* we already handled this by copying the mail */
			continue;
		}

		T_BEGIN {
			dsync_mailbox_save_body(importer, mail, newmail,
						allmails);
		} T_END;
	}
}

static int
reassign_uids_in_seq_range(struct mailbox *box, uint32_t seq1, uint32_t seq2)
{
	const enum mailbox_transaction_flags trans_flags =
		MAILBOX_TRANSACTION_FLAG_EXTERNAL |
		MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	uint32_t seq;
	int ret = 0;

	trans = mailbox_transaction_begin(box, trans_flags);
	mail = mail_alloc(trans, 0, NULL);

	for (seq = seq1; seq <= seq2; seq++) {
		mail_set_seq(mail, seq);

		save_ctx = mailbox_save_alloc(trans);
		mailbox_save_copy_flags(save_ctx, mail);
		if (mailbox_copy(&save_ctx, mail) < 0)
			ret = -1;
		else
			mail_expunge(mail);
	}
	mail_free(&mail);

	if (mailbox_transaction_commit(&trans) < 0) {
		i_error("UID reassign commit failed to mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		ret = -1;
	}
	return ret;
}

static bool
reassign_unwanted_uids(struct dsync_mailbox_importer *importer,
		       const struct mail_transaction_commit_changes *changes,
		       bool *changes_during_sync_r)
{
	struct seq_range_iter iter;
	const uint32_t *wanted_uids;
	uint32_t saved_uid, highest_unwanted_uid = 0;
	uint32_t seq1, seq2, lowest_saved_uid = (uint32_t)-1;
	unsigned int i, n, wanted_count;
	int ret = 0;

	/* find the highest wanted UID that doesn't match what we got */
	wanted_uids = array_get(&importer->wanted_uids, &wanted_count);
	seq_range_array_iter_init(&iter, &changes->saved_uids); i = n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &saved_uid)) {
		i_assert(i < wanted_count);
		if (lowest_saved_uid > saved_uid)
			lowest_saved_uid = saved_uid;
		if (saved_uid != wanted_uids[i]) {
			if (highest_unwanted_uid < wanted_uids[i])
				highest_unwanted_uid = wanted_uids[i];
		}
		i++;
	}

	if (highest_unwanted_uid == 0 && i > 0 &&
	    importer->local_uid_next <= lowest_saved_uid-1) {
		/* we didn't see any unwanted UIDs, but we'll still need to
		   verify that messages didn't just get saved locally to a gap
		   that we left in local_uid_next..(lowest_saved_uid-1) */
		highest_unwanted_uid = lowest_saved_uid-1;
	}

	if (highest_unwanted_uid == 0)
		seq1 = seq2 = 0;
	else {
		mailbox_get_seq_range(importer->box, importer->local_uid_next,
				      highest_unwanted_uid, &seq1, &seq2);
	}
	if (seq1 > 0) {
		ret = reassign_uids_in_seq_range(importer->box, seq1, seq2);
		*changes_during_sync_r = TRUE;
	}
	return ret;
}

static int dsync_mailbox_import_commit(struct dsync_mailbox_importer *importer,
				       bool *changes_during_sync_r)
{
	struct mail_transaction_commit_changes changes;
	struct mailbox_update update;
	int ret = 0;

	/* commit saves */
	if (mailbox_transaction_commit_get_changes(&importer->ext_trans,
						   &changes) < 0) {
		i_error("Save commit failed to mailbox %s: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_error(importer->box, NULL));
		mailbox_transaction_rollback(&importer->trans);
		return -1;
	}

	/* commit flag changes and expunges */
	if (mailbox_transaction_commit(&importer->trans) < 0) {
		i_error("Commit failed to mailbox %s: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_error(importer->box, NULL));
		pool_unref(&changes.pool);
		return -1;
	}

	/* update mailbox metadata. */
	memset(&update, 0, sizeof(update));
	update.min_next_uid = importer->remote_uid_next;
	update.min_first_recent_uid =
		I_MIN(importer->last_common_uid+1,
		      importer->remote_first_recent_uid);
	update.min_highest_modseq = importer->remote_highest_modseq;

	if (mailbox_update(importer->box, &update) < 0) {
		i_error("Mailbox update failed to mailbox %s: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_error(importer->box, NULL));
		ret = -1;
	}

	/* sync mailbox to finish flag changes and expunges. */
	if (mailbox_sync(importer->box, 0) < 0) {
		i_error("Mailbox sync failed to mailbox %s: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_error(importer->box, NULL));
		ret = -1;
	}

	if (reassign_unwanted_uids(importer, &changes,
				   changes_during_sync_r) < 0)
		ret = -1;
	pool_unref(&changes.pool);
	return ret;
}

static unsigned int
dsync_mailbox_import_count_missing_imports(struct hash_table *imports)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	unsigned int msgs_left = 0;

	iter = hash_table_iterate_init(imports);
	while (hash_table_iterate(iter, &key, &value)) {
		struct importer_new_mail *mail = value;

		for (; mail != NULL; mail = mail->next) {
			if (!mail->uid_in_local) {
				msgs_left++;
				break;
			}
		}
	}
	hash_table_iterate_deinit(&iter);
	return msgs_left;
}

int dsync_mailbox_import_deinit(struct dsync_mailbox_importer **_importer,
				uint32_t *last_common_uid_r,
				uint64_t *last_common_modseq_r,
				bool *changes_during_sync_r)
{
	struct dsync_mailbox_importer *importer = *_importer;
	unsigned int msgs_left;
	int ret;

	*_importer = NULL;
	*changes_during_sync_r = FALSE;

	if (!importer->new_uids_assigned)
		dsync_mailbox_import_assign_new_uids(importer);

	msgs_left =
		dsync_mailbox_import_count_missing_imports(importer->import_guids) +
		dsync_mailbox_import_count_missing_imports(importer->import_uids);
	if (!importer->failed && msgs_left > 0) {
		i_error("%s: Remote didn't send %u expected message bodies",
			mailbox_get_vname(importer->box), msgs_left);
	}

	if (importer->search_ctx != NULL) {
		if (mailbox_search_deinit(&importer->search_ctx) < 0)
			importer->failed = TRUE;
	}
	mail_free(&importer->mail);
	mail_free(&importer->ext_mail);

	if (dsync_mailbox_import_commit(importer, changes_during_sync_r) < 0)
		importer->failed = TRUE;

	hash_table_destroy(&importer->import_guids);
	hash_table_destroy(&importer->import_uids);
	array_free(&importer->maybe_expunge_uids);
	array_free(&importer->maybe_saves);
	array_free(&importer->wanted_uids);
	array_free(&importer->newmails);
	if (array_is_created(&importer->mail_requests))
		array_free(&importer->mail_requests);

	*last_common_uid_r = importer->last_common_uid;
	if (!*changes_during_sync_r)
		*last_common_modseq_r = importer->last_common_modseq;
	else {
		/* local changes occurred during dsync. we exported changes up
		   to local_initial_highestmodseq, so all of the changes have
		   happened after it. we want the next run to see those changes,
		   so return it as the last common modseq */
		*last_common_modseq_r = importer->local_initial_highestmodseq;
	}

	ret = importer->failed ? -1 : 0;
	pool_unref(&importer->pool);
	return ret;
}
