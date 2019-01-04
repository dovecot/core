/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "istream.h"
#include "mail-index-modseq.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "dsync-transaction-log-scan.h"
#include "dsync-mail.h"
#include "dsync-mailbox.h"
#include "dsync-mailbox-export.h"

struct dsync_mail_guid_instances {
	ARRAY_TYPE(seq_range) seqs;
	bool requested;
	bool searched;
};

struct dsync_mailbox_exporter {
	pool_t pool;
	struct mailbox *box;
	struct dsync_transaction_log_scan *log_scan;
	uint32_t last_common_uid;

	struct mailbox_header_lookup_ctx *wanted_headers;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	unsigned int search_pos, search_count;
	unsigned int hdr_hash_version;

	const char *const *hashed_headers;

	/* GUID => instances */
	HASH_TABLE(char *, struct dsync_mail_guid_instances *) export_guids;
	ARRAY_TYPE(seq_range) requested_uids;
	ARRAY_TYPE(seq_range) search_uids;

	ARRAY_TYPE(seq_range) expunged_seqs;
	ARRAY_TYPE(const_string) expunged_guids;
	unsigned int expunged_guid_idx;

	/* uint32_t UID => struct dsync_mail_change */
	HASH_TABLE(void *, struct dsync_mail_change *) changes;
	/* changes sorted by UID */
	ARRAY(struct dsync_mail_change *) sorted_changes;
	unsigned int change_idx;
	uint32_t highest_changed_uid;

	struct mailbox_attribute_iter *attr_iter;
	struct hash_iterate_context *attr_change_iter;
	enum mail_attribute_type attr_type;
	struct dsync_mailbox_attribute attr;

	struct dsync_mail_change change;
	struct dsync_mail dsync_mail;

	const char *error;
	enum mail_error mail_error;

	bool body_search_initialized:1;
	bool auto_export_mails:1;
	bool mails_have_guids:1;
	bool minimal_dmail_fill:1;
	bool return_all_mails:1;
	bool export_received_timestamps:1;
	bool export_virtual_sizes:1;
	bool no_hdr_hashes:1;
};

static int dsync_mail_error(struct dsync_mailbox_exporter *exporter,
			    struct mail *mail, const char *field)
{
	const char *errstr;
	enum mail_error error;

	errstr = mailbox_get_last_internal_error(exporter->box, &error);
	if (error == MAIL_ERROR_EXPUNGED)
		return 0;

	exporter->mail_error = error;
	exporter->error = p_strdup_printf(exporter->pool,
		"Can't lookup %s for UID=%u: %s",
		field, mail->uid, errstr);
	return -1;
}

static bool
final_keyword_check(struct dsync_mail_change *change, const char *name,
		    char *type_r)
{
	const char *const *changes;
	unsigned int i, count;

	*type_r = KEYWORD_CHANGE_FINAL;

	changes = array_get(&change->keyword_changes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(changes[i]+1, name) != 0)
			continue;

		switch (changes[i][0]) {
		case KEYWORD_CHANGE_ADD:
			/* replace with ADD_AND_FINAL */
			array_delete(&change->keyword_changes, i, 1);
			*type_r = KEYWORD_CHANGE_ADD_AND_FINAL;
			return FALSE;
		case KEYWORD_CHANGE_REMOVE:
			/* a final keyword is marked as removed.
			   this shouldn't normally happen. */
			array_delete(&change->keyword_changes, i, 1);
			return FALSE;
		case KEYWORD_CHANGE_ADD_AND_FINAL:
		case KEYWORD_CHANGE_FINAL:
			/* no change */
			return TRUE;
		}
	}
	return FALSE;
}

static void
search_update_flag_changes(struct dsync_mailbox_exporter *exporter,
			   struct mail *mail, struct dsync_mail_change *change)
{
	const char *const *keywords;
	unsigned int i;
	char type;

	i_assert((change->add_flags & change->remove_flags) == 0);

	change->modseq = mail_get_modseq(mail);
	change->pvt_modseq = mail_get_pvt_modseq(mail);
	change->final_flags = mail_get_flags(mail);

	keywords = mail_get_keywords(mail);
	if (!array_is_created(&change->keyword_changes) &&
	    keywords[0] != NULL) {
		p_array_init(&change->keyword_changes, exporter->pool,
			     str_array_length(keywords));
	}
	for (i = 0; keywords[i] != NULL; i++) {
		/* add the final keyword if it's not already there
		   as +keyword */
		if (!final_keyword_check(change, keywords[i], &type)) {
			const char *keyword_change =
				p_strdup_printf(exporter->pool, "%c%s",
						type, keywords[i]);
			array_append(&change->keyword_changes,
				     &keyword_change, 1);
		}
	}
}

static int
exporter_get_guids(struct dsync_mailbox_exporter *exporter,
		   struct mail *mail, const char **guid_r,
		   const char **hdr_hash_r)
{
	*guid_r = "";
	*hdr_hash_r = NULL;

	/* always try to get GUID, even if we're also getting header hash */
	if (mail_get_special(mail, MAIL_FETCH_GUID, guid_r) < 0)
		return dsync_mail_error(exporter, mail, "GUID");

	if (!exporter->mails_have_guids) {
		/* get header hash also */
		if (exporter->no_hdr_hashes) {
			*hdr_hash_r = "";
			return 1;
		}
		if (dsync_mail_get_hdr_hash(mail, exporter->hdr_hash_version,
					    exporter->hashed_headers, hdr_hash_r) < 0)
			return dsync_mail_error(exporter, mail, "hdr-stream");
		return 1;
	} else if (**guid_r == '\0') {
		exporter->mail_error = MAIL_ERROR_TEMP;
		exporter->error = "Backend doesn't support GUIDs, "
			"sync with header hashes instead";
		return -1;
	} else {
		/* GUIDs are required, we don't need header hash */
		return 1;
	} 
}

static int
search_update_flag_change_guid(struct dsync_mailbox_exporter *exporter,
			       struct mail *mail)
{
	struct dsync_mail_change *change, *log_change;
	const char *guid, *hdr_hash;
	int ret;

	change = hash_table_lookup(exporter->changes, POINTER_CAST(mail->uid));
	if (change != NULL) {
		i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE);
	} else {
		i_assert(exporter->return_all_mails);

		change = p_new(exporter->pool, struct dsync_mail_change, 1);
		change->uid = mail->uid;
		change->type = DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE;
		hash_table_insert(exporter->changes,
				  POINTER_CAST(mail->uid), change);
	}

	if ((ret = exporter_get_guids(exporter, mail, &guid, &hdr_hash)) < 0)
		return -1;
	if (ret == 0) {
		/* the message was expunged during export */
		i_zero(change);
		change->type = DSYNC_MAIL_CHANGE_TYPE_EXPUNGE;
		change->uid = mail->uid;

		/* find its GUID from log if possible */
		log_change = dsync_transaction_log_scan_find_new_expunge(
			exporter->log_scan, mail->uid);
		if (log_change != NULL)
			change->guid = log_change->guid;
	} else {
		change->guid = *guid == '\0' ? "" :
			p_strdup(exporter->pool, guid);
		change->hdr_hash = p_strdup(exporter->pool, hdr_hash);
		search_update_flag_changes(exporter, mail, change);
	}
	return 0;
}

static struct dsync_mail_change *
export_save_change_get(struct dsync_mailbox_exporter *exporter, uint32_t uid)
{
	struct dsync_mail_change *change;

	change = hash_table_lookup(exporter->changes, POINTER_CAST(uid));
	if (change == NULL) {
		change = p_new(exporter->pool, struct dsync_mail_change, 1);
		change->uid = uid;
		hash_table_insert(exporter->changes, POINTER_CAST(uid), change);
	} else {
		/* move flag changes into a save. this happens only when
		   last_common_uid isn't known */
		i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE);
		i_assert(exporter->last_common_uid == 0);
	}

	change->type = DSYNC_MAIL_CHANGE_TYPE_SAVE;
	return change;
}

static void
export_add_mail_instance(struct dsync_mailbox_exporter *exporter,
			 struct dsync_mail_change *change, uint32_t seq)
{
	struct dsync_mail_guid_instances *instances;

	if (exporter->auto_export_mails && !exporter->mails_have_guids) {
		/* GUIDs not supported, mail is requested by UIDs */
		seq_range_array_add(&exporter->requested_uids, change->uid);
		return;
	}
	if (*change->guid == '\0') {
		/* mail UIDs are manually requested */
		i_assert(!exporter->mails_have_guids);
		return;
	}

	instances = hash_table_lookup(exporter->export_guids, change->guid);
	if (instances == NULL) {
		instances = p_new(exporter->pool,
				  struct dsync_mail_guid_instances, 1);
		p_array_init(&instances->seqs, exporter->pool, 2);
		hash_table_insert(exporter->export_guids,
				  p_strdup(exporter->pool, change->guid),
				  instances);
		if (exporter->auto_export_mails)
			instances->requested = TRUE;
	}
	seq_range_array_add(&instances->seqs, seq);
}

static int
search_add_save(struct dsync_mailbox_exporter *exporter, struct mail *mail)
{
	struct dsync_mail_change *change;
	const char *guid, *hdr_hash;
	enum mail_fetch_field wanted_fields = MAIL_FETCH_GUID;
	time_t received_timestamp = 0;
	uoff_t virtual_size = (uoff_t)-1;
	int ret;

	/* update wanted fields in case we didn't already set them for the
	   search */
	if (exporter->export_received_timestamps)
		wanted_fields |= MAIL_FETCH_RECEIVED_DATE;
	if (exporter->export_virtual_sizes)
		wanted_fields |= MAIL_FETCH_VIRTUAL_SIZE;
	mail_add_temp_wanted_fields(mail, wanted_fields,
				    exporter->wanted_headers);

	/* If message is already expunged here, just skip it */
	if ((ret = exporter_get_guids(exporter, mail, &guid, &hdr_hash)) <= 0)
		return ret;

	if (exporter->export_received_timestamps) {
		if (mail_get_received_date(mail, &received_timestamp) < 0)
			return dsync_mail_error(exporter, mail, "received-time");
		if (received_timestamp == 0) {
			/* don't allow timestamps to be zero. we want to have
			   asserts verify that the timestamp is set properly. */
			received_timestamp = 1;
		}
	}
	if (exporter->export_virtual_sizes) {
		if (mail_get_virtual_size(mail, &virtual_size) < 0)
			return dsync_mail_error(exporter, mail, "virtual-size");
		i_assert(virtual_size != (uoff_t)-1);
	}

	change = export_save_change_get(exporter, mail->uid);
	change->guid = *guid == '\0' ? "" :
		p_strdup(exporter->pool, guid);
	change->hdr_hash = p_strdup(exporter->pool, hdr_hash);
	change->received_timestamp = received_timestamp;
	change->virtual_size = virtual_size;
	search_update_flag_changes(exporter, mail, change);

	export_add_mail_instance(exporter, change, mail->seq);
	return 1;
}

static void
dsync_mailbox_export_add_flagchange_uids(struct dsync_mailbox_exporter *exporter,
					 ARRAY_TYPE(seq_range) *uids)
{
	struct hash_iterate_context *iter;
	void *key;
	struct dsync_mail_change *change;

	iter = hash_table_iterate_init(exporter->changes);
	while (hash_table_iterate(iter, exporter->changes, &key, &change)) {
		if (change->type == DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE)
			seq_range_array_add(uids, change->uid);
	}
	hash_table_iterate_deinit(&iter);
}

static void
dsync_mailbox_export_drop_expunged_flag_changes(struct dsync_mailbox_exporter *exporter)
{
	struct hash_iterate_context *iter;
	void *key;
	struct dsync_mail_change *change;

	/* any flag changes for UIDs above last_common_uid weren't found by
	   mailbox search, which means they were already expunged. for some
	   reason the log scanner found flag changes for the message, but not
	   the expunge. just remove these. */
	iter = hash_table_iterate_init(exporter->changes);
	while (hash_table_iterate(iter, exporter->changes, &key, &change)) {
		if (change->type == DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE &&
		    change->uid > exporter->last_common_uid)
			hash_table_remove(exporter->changes, key);
	}
	hash_table_iterate_deinit(&iter);
}

static void
dsync_mailbox_export_search(struct dsync_mailbox_exporter *exporter)
{
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;
	struct mail *mail;
	enum mail_fetch_field wanted_fields = 0;
	struct mailbox_header_lookup_ctx *wanted_headers = NULL;
	int ret = 0;

	search_args = mail_search_build_init();
	sarg = mail_search_build_add(search_args, SEARCH_UIDSET);
	p_array_init(&sarg->value.seqset, search_args->pool, 1);

	if (exporter->return_all_mails || exporter->last_common_uid == 0) {
		/* we want to know about all mails */
		seq_range_array_add_range(&sarg->value.seqset, 1, (uint32_t)-1);
	} else {
		/* lookup GUIDs for messages with flag changes */
		dsync_mailbox_export_add_flagchange_uids(exporter,
							 &sarg->value.seqset);
		/* lookup new messages */
		seq_range_array_add_range(&sarg->value.seqset,
					  exporter->last_common_uid + 1,
					  (uint32_t)-1);
	}

	if (exporter->last_common_uid == 0) {
		/* we're syncing all mails, so we can request the wanted
		   fields for all the mails */
		wanted_fields = MAIL_FETCH_GUID;
		wanted_headers = exporter->wanted_headers;
	}

	exporter->trans = mailbox_transaction_begin(exporter->box,
						MAILBOX_TRANSACTION_FLAG_SYNC,
						__func__);
	search_ctx = mailbox_search_init(exporter->trans, search_args, NULL,
					 wanted_fields, wanted_headers);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		T_BEGIN {
			if (mail->uid <= exporter->last_common_uid)
				ret = search_update_flag_change_guid(exporter, mail);
			else
				ret = search_add_save(exporter, mail);
		} T_END;
		if (ret < 0)
			break;
	}
	i_assert(ret >= 0 || exporter->error != NULL);

	dsync_mailbox_export_drop_expunged_flag_changes(exporter);

	if (mailbox_search_deinit(&search_ctx) < 0 &&
	    exporter->error == NULL) {
		exporter->error = p_strdup_printf(exporter->pool,
			"Mail search failed: %s",
			mailbox_get_last_internal_error(exporter->box,
							&exporter->mail_error));
	}
}

static int dsync_mail_change_p_uid_cmp(struct dsync_mail_change *const *c1,
				       struct dsync_mail_change *const *c2)
{
	if ((*c1)->uid < (*c2)->uid)
		return -1;
	if ((*c1)->uid > (*c2)->uid)
		return 1;
	return 0;
}

static void
dsync_mailbox_export_sort_changes(struct dsync_mailbox_exporter *exporter)
{
	struct hash_iterate_context *iter;
	void *key;
	struct dsync_mail_change *change;

	p_array_init(&exporter->sorted_changes, exporter->pool,
		     hash_table_count(exporter->changes));

	iter = hash_table_iterate_init(exporter->changes);
	while (hash_table_iterate(iter, exporter->changes, &key, &change))
		array_append(&exporter->sorted_changes, &change, 1);
	hash_table_iterate_deinit(&iter);
	array_sort(&exporter->sorted_changes, dsync_mail_change_p_uid_cmp);
}

static void
dsync_mailbox_export_attr_init(struct dsync_mailbox_exporter *exporter,
			       enum mail_attribute_type type)
{
	exporter->attr_iter =
		mailbox_attribute_iter_init(exporter->box, type, "");
	exporter->attr_type = type;
}

static void
dsync_mailbox_export_log_scan(struct dsync_mailbox_exporter *exporter,
			      struct dsync_transaction_log_scan *log_scan)
{
	HASH_TABLE_TYPE(dsync_uid_mail_change) log_changes;
	struct hash_iterate_context *iter;
	void *key;
	struct dsync_mail_change *change, *dup_change;

	log_changes = dsync_transaction_log_scan_get_hash(log_scan);
	if (dsync_transaction_log_scan_has_all_changes(log_scan)) {
		/* we tried to access too old/invalid modseqs. to make sure
		   no changes get lost, we need to send all of the messages */
		exporter->return_all_mails = TRUE;
	}

	/* clone the hash table, since we're changing it. */
	hash_table_create_direct(&exporter->changes, exporter->pool,
				 hash_table_count(log_changes));
	iter = hash_table_iterate_init(log_changes);
	while (hash_table_iterate(iter, log_changes, &key, &change)) {
		dup_change = p_new(exporter->pool, struct dsync_mail_change, 1);
		*dup_change = *change;
		hash_table_insert(exporter->changes, key, dup_change);
		if (exporter->highest_changed_uid < change->uid)
			exporter->highest_changed_uid = change->uid;
	}
	hash_table_iterate_deinit(&iter);
}

struct dsync_mailbox_exporter *
dsync_mailbox_export_init(struct mailbox *box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  enum dsync_mailbox_exporter_flags flags,
			  unsigned int hdr_hash_version,
			  const char *const *hashed_headers)
{
	struct dsync_mailbox_exporter *exporter;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync mailbox export",
				     4096);
	exporter = p_new(pool, struct dsync_mailbox_exporter, 1);
	exporter->pool = pool;
	exporter->box = box;
	exporter->log_scan = log_scan;
	exporter->last_common_uid = last_common_uid;
	exporter->auto_export_mails =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_AUTO_EXPORT_MAILS) != 0;
	exporter->mails_have_guids =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_MAILS_HAVE_GUIDS) != 0;
	exporter->minimal_dmail_fill =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_MINIMAL_DMAIL_FILL) != 0;
	exporter->export_received_timestamps =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_TIMESTAMPS) != 0;
	exporter->export_virtual_sizes =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_VSIZES) != 0;
	exporter->hdr_hash_version = hdr_hash_version;
	exporter->no_hdr_hashes =
		(flags & DSYNC_MAILBOX_EXPORTER_FLAG_NO_HDR_HASHES) != 0;
	exporter->hashed_headers = hashed_headers;

	p_array_init(&exporter->requested_uids, pool, 16);
	p_array_init(&exporter->search_uids, pool, 16);
	hash_table_create(&exporter->export_guids, pool, 0, str_hash, strcmp);
	p_array_init(&exporter->expunged_seqs, pool, 16);
	p_array_init(&exporter->expunged_guids, pool, 16);

	if (!exporter->mails_have_guids && !exporter->no_hdr_hashes)
		exporter->wanted_headers =
			dsync_mail_get_hash_headers(box, exporter->hashed_headers);

	/* first scan transaction log and save any expunges and flag changes */
	dsync_mailbox_export_log_scan(exporter, log_scan);
	/* get saves and also find GUIDs for flag changes */
	dsync_mailbox_export_search(exporter);
	/* get the changes sorted by UID */
	dsync_mailbox_export_sort_changes(exporter);

	dsync_mailbox_export_attr_init(exporter, MAIL_ATTRIBUTE_TYPE_PRIVATE);
	return exporter;
}

static int
dsync_mailbox_export_iter_next_nonexistent_attr(struct dsync_mailbox_exporter *exporter)
{
	struct dsync_mailbox_attribute *attr;
	struct mail_attribute_value value;

	while (hash_table_iterate(exporter->attr_change_iter,
				  dsync_transaction_log_scan_get_attr_hash(exporter->log_scan),
				  &attr, &attr)) {
		if (attr->exported || !attr->deleted)
			continue;

		/* lookup the value mainly to get its last_change value. */
		if (mailbox_attribute_get_stream(exporter->box, attr->type,
						 attr->key, &value) < 0) {
			exporter->error = p_strdup_printf(exporter->pool,
				"Mailbox attribute %s lookup failed: %s", attr->key,
				mailbox_get_last_internal_error(exporter->box,
								&exporter->mail_error));
			break;
		}
		if ((value.flags & MAIL_ATTRIBUTE_VALUE_FLAG_READONLY) != 0) {
			i_stream_unref(&value.value_stream);
			continue;
		}

		attr->last_change = value.last_change;
		if (value.value != NULL || value.value_stream != NULL) {
			attr->value = p_strdup(exporter->pool, value.value);
			attr->value_stream = value.value_stream;
			attr->deleted = FALSE;
		}
		attr->exported = TRUE;
		exporter->attr = *attr;
		return 1;
	}
	hash_table_iterate_deinit(&exporter->attr_change_iter);
	return 0;
}

static int
dsync_mailbox_export_iter_next_attr(struct dsync_mailbox_exporter *exporter)
{
	HASH_TABLE_TYPE(dsync_attr_change) attr_changes;
	struct dsync_mailbox_attribute lookup_attr, *attr;
	struct dsync_mailbox_attribute *attr_change;
	const char *key;
	struct mail_attribute_value value;
	bool export_all_attrs;

	export_all_attrs = exporter->return_all_mails ||
		exporter->last_common_uid == 0;
	attr_changes = dsync_transaction_log_scan_get_attr_hash(exporter->log_scan);
	lookup_attr.type = exporter->attr_type;

	/* note that the order of processing may be important for some
	   attributes. for example sieve can't set a script active until it's
	   first been created */
	while ((key = mailbox_attribute_iter_next(exporter->attr_iter)) != NULL) {
		lookup_attr.key = key;
		attr_change = hash_table_lookup(attr_changes, &lookup_attr);
		if (attr_change == NULL && !export_all_attrs)
			continue;

		if (mailbox_attribute_get_stream(exporter->box,
						 exporter->attr_type, key,
						 &value) < 0) {
			exporter->error = p_strdup_printf(exporter->pool,
				"Mailbox attribute %s lookup failed: %s", key,
				mailbox_get_last_internal_error(exporter->box,
								&exporter->mail_error));
			return -1;
		}
		if ((value.flags & MAIL_ATTRIBUTE_VALUE_FLAG_READONLY) != 0) {
			/* readonly attributes can't be changed,
			   no point in exporting them */
			if (value.value_stream != NULL)
				i_stream_unref(&value.value_stream);
			continue;
		}
		if (value.value == NULL && value.value_stream == NULL &&
		    (attr_change == NULL || !attr_change->deleted)) {
			/* the attribute was just deleted?
			   skip for this sync. */
			continue;
		}
		if (attr_change != NULL && attr_change->exported) {
			/* duplicate attribute returned.
			   shouldn't normally happen, but don't crash. */
			i_warning("Ignoring duplicate attributes '%s'", key);
			continue;
		}

		attr = &exporter->attr;
		i_zero(attr);
		attr->type = exporter->attr_type;
		attr->value = p_strdup(exporter->pool, value.value);
		attr->value_stream = value.value_stream;
		attr->last_change = value.last_change;
		if (attr_change != NULL) {
			attr_change->exported = TRUE;
			attr->key = attr_change->key;
			attr->deleted = attr_change->deleted &&
				!DSYNC_ATTR_HAS_VALUE(attr);
			attr->modseq = attr_change->modseq;
		} else {
			attr->key = p_strdup(exporter->pool, key);
		}
		return 1;
	}
	if (mailbox_attribute_iter_deinit(&exporter->attr_iter) < 0) {
		exporter->error = p_strdup_printf(exporter->pool,
			"Mailbox attribute iteration failed: %s",
			mailbox_get_last_internal_error(exporter->box,
							&exporter->mail_error));
		return -1;
	}
	if (exporter->attr_type == MAIL_ATTRIBUTE_TYPE_PRIVATE) {
		/* export shared attributes */
		dsync_mailbox_export_attr_init(exporter,
					       MAIL_ATTRIBUTE_TYPE_SHARED);
		return dsync_mailbox_export_iter_next_attr(exporter);
	}
	exporter->attr_change_iter = hash_table_iterate_init(attr_changes);
	return dsync_mailbox_export_iter_next_nonexistent_attr(exporter);
}

int dsync_mailbox_export_next_attr(struct dsync_mailbox_exporter *exporter,
				   const struct dsync_mailbox_attribute **attr_r)
{
	int ret;

	if (exporter->error != NULL)
		return -1;

	i_stream_unref(&exporter->attr.value_stream);

	if (exporter->attr_iter != NULL) {
		ret = dsync_mailbox_export_iter_next_attr(exporter);
	} else {
		ret = dsync_mailbox_export_iter_next_nonexistent_attr(exporter);
	}
	if (ret > 0)
		*attr_r = &exporter->attr;
	return ret;
}

int dsync_mailbox_export_next(struct dsync_mailbox_exporter *exporter,
			      const struct dsync_mail_change **change_r)
{
	struct dsync_mail_change *const *changes;
	unsigned int count;

	if (exporter->error != NULL)
		return -1;

	changes = array_get(&exporter->sorted_changes, &count);
	if (exporter->change_idx == count)
		return 0;
	*change_r = changes[exporter->change_idx++];
	return 1;
}

static int
dsync_mailbox_export_body_search_init(struct dsync_mailbox_exporter *exporter)
{
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;
	struct hash_iterate_context *iter;
	const struct seq_range *uids;
	char *guid;
	const char *const_guid;
	enum mail_fetch_field wanted_fields;
	struct dsync_mail_guid_instances *instances;
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t seq, seq1, seq2;

	i_assert(exporter->search_ctx == NULL);

	search_args = mail_search_build_init();
	sarg = mail_search_build_add(search_args, SEARCH_SEQSET);
	p_array_init(&sarg->value.seqset, search_args->pool, 128);

	/* get a list of messages we want to fetch. if there are more than one
	   instance for a GUID, use the first one. */
	iter = hash_table_iterate_init(exporter->export_guids);
	while (hash_table_iterate(iter, exporter->export_guids,
				  &guid, &instances)) {
		if (!instances->requested ||
		    array_count(&instances->seqs) == 0)
			continue;

		uids = array_first(&instances->seqs);
		seq = uids[0].seq1;
		if (!instances->searched) {
			instances->searched = TRUE;
			seq_range_array_add(&sarg->value.seqset, seq);
		} else if (seq_range_exists(&exporter->expunged_seqs, seq)) {
			/* we're on a second round, refetching expunged
			   messages */
			seq_range_array_remove(&instances->seqs, seq);
			seq_range_array_remove(&exporter->expunged_seqs, seq);
			if (array_count(&instances->seqs) == 0) {
				/* no instances left */
				const_guid = guid;
				array_append(&exporter->expunged_guids,
					     &const_guid, 1);
				continue;
			}
			uids = array_first(&instances->seqs);
			seq = uids[0].seq1;
			seq_range_array_add(&sarg->value.seqset, seq);
		}
	}
	hash_table_iterate_deinit(&iter);

	/* add requested UIDs */
	range = array_get(&exporter->requested_uids, &count);
	for (i = 0; i < count; i++) {
		mailbox_get_seq_range(exporter->box,
				      range[i].seq1, range[i].seq2,
				      &seq1, &seq2);
		seq_range_array_add_range(&sarg->value.seqset,
					  seq1, seq2);
	}
	array_clear(&exporter->search_uids);
	array_append_array(&exporter->search_uids, &exporter->requested_uids);
	array_clear(&exporter->requested_uids);

	wanted_fields = MAIL_FETCH_GUID | MAIL_FETCH_SAVE_DATE;
	if (!exporter->minimal_dmail_fill) {
		wanted_fields |= MAIL_FETCH_RECEIVED_DATE |
			MAIL_FETCH_UIDL_BACKEND | MAIL_FETCH_POP3_ORDER |
			MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY;
	}
	exporter->search_count += seq_range_count(&sarg->value.seqset);
	exporter->search_ctx =
		mailbox_search_init(exporter->trans, search_args, NULL,
				    wanted_fields, NULL);
	mail_search_args_unref(&search_args);
	return array_count(&sarg->value.seqset) > 0 ? 1 : 0;
}

static void
dsync_mailbox_export_body_search_deinit(struct dsync_mailbox_exporter *exporter)
{
	if (exporter->search_ctx == NULL)
		return;

	if (mailbox_search_deinit(&exporter->search_ctx) < 0 &&
	    exporter->error == NULL) {
		exporter->error = p_strdup_printf(exporter->pool,
			"Mail search failed: %s",
			mailbox_get_last_internal_error(exporter->box,
							&exporter->mail_error));
	}
}

static int dsync_mailbox_export_mail(struct dsync_mailbox_exporter *exporter,
				     struct mail *mail)
{
	struct dsync_mail_guid_instances *instances;
	const char *error_field;

	if (dsync_mail_fill(mail, exporter->minimal_dmail_fill,
			    &exporter->dsync_mail, &error_field) < 0)
		return dsync_mail_error(exporter, mail, error_field);

	instances = *exporter->dsync_mail.guid == '\0' ? NULL :
		hash_table_lookup(exporter->export_guids,
				  exporter->dsync_mail.guid);
	if (instances != NULL) {
		/* GUID found */
	} else if (exporter->dsync_mail.uid != 0) {
		/* mail requested by UID */
	} else {
		exporter->mail_error = MAIL_ERROR_TEMP;
		exporter->error = p_strdup_printf(exporter->pool,
			"GUID unexpectedly changed for UID=%u GUID=%s",
			mail->uid, exporter->dsync_mail.guid);
		return -1;
	}

	if (!seq_range_exists(&exporter->search_uids, mail->uid))
		exporter->dsync_mail.uid = 0;
	else
		exporter->dsync_mail.guid = "";

	/* this message was successfully returned, don't try retrying it */
	if (instances != NULL)
		array_clear(&instances->seqs);
	return 1;
}

void dsync_mailbox_export_want_mail(struct dsync_mailbox_exporter *exporter,
				    const struct dsync_mail_request *request)
{
	struct dsync_mail_guid_instances *instances;

	i_assert(!exporter->auto_export_mails);

	if (request->guid == NULL) {
		i_assert(request->uid > 0);
		seq_range_array_add(&exporter->requested_uids, request->uid);
		return;
	}

	instances = hash_table_lookup(exporter->export_guids, request->guid);
	if (instances == NULL) {
		exporter->mail_error = MAIL_ERROR_TEMP;
		exporter->error = p_strdup_printf(exporter->pool,
			"Remote requested unexpected GUID %s", request->guid);
		return;
	}
	instances->requested = TRUE;
}

int dsync_mailbox_export_next_mail(struct dsync_mailbox_exporter *exporter,
				   const struct dsync_mail **mail_r)
{
	struct mail *mail;
	const char *const *guids;
	unsigned int count;
	int ret;

	if (exporter->error != NULL)
		return -1;
	if (!exporter->body_search_initialized) {
		exporter->body_search_initialized = TRUE;
		if (dsync_mailbox_export_body_search_init(exporter) < 0) {
			i_assert(exporter->error != NULL);
			return -1;
		}
	}

	while (mailbox_search_next(exporter->search_ctx, &mail)) {
		exporter->search_pos++;
		if ((ret = dsync_mailbox_export_mail(exporter, mail)) > 0) {
			*mail_r = &exporter->dsync_mail;
			return 1;
		}
		if (ret < 0) {
			i_assert(exporter->error != NULL);
			return -1;
		}
		/* the message was expunged. if the GUID has another instance,
		   try sending it later. */
		seq_range_array_add(&exporter->expunged_seqs, mail->seq);
	}
	/* if some instances of messages were expunged, retry fetching them
	   with other instances */
	dsync_mailbox_export_body_search_deinit(exporter);
	if ((ret = dsync_mailbox_export_body_search_init(exporter)) < 0) {
		i_assert(exporter->error != NULL);
		return -1;
	}
	if (ret > 0) {
		/* not finished yet */
		return dsync_mailbox_export_next_mail(exporter, mail_r);
	}

	/* finished with messages. if there are any expunged messages,
	   return them */
	guids = array_get(&exporter->expunged_guids, &count);
	if (exporter->expunged_guid_idx < count) {
		i_zero(&exporter->dsync_mail);
		exporter->dsync_mail.guid =
			guids[exporter->expunged_guid_idx++];
		*mail_r = &exporter->dsync_mail;
		return 1;
	}
	return 0;
}

int dsync_mailbox_export_deinit(struct dsync_mailbox_exporter **_exporter,
				const char **errstr_r, enum mail_error *error_r)
{
	struct dsync_mailbox_exporter *exporter = *_exporter;

	*_exporter = NULL;

	if (exporter->attr_iter != NULL)
		(void)mailbox_attribute_iter_deinit(&exporter->attr_iter);
	dsync_mailbox_export_body_search_deinit(exporter);
	(void)mailbox_transaction_commit(&exporter->trans);
	mailbox_header_lookup_unref(&exporter->wanted_headers);

	i_stream_unref(&exporter->attr.value_stream);
	hash_table_destroy(&exporter->export_guids);
	hash_table_destroy(&exporter->changes);

	i_assert((exporter->error != NULL) == (exporter->mail_error != 0));

	*error_r = exporter->mail_error;
	*errstr_r = t_strdup(exporter->error);
	pool_unref(&exporter->pool);
	return *errstr_r != NULL ? -1 : 0;
}

const char *dsync_mailbox_export_get_proctitle(struct dsync_mailbox_exporter *exporter)
{
	if (exporter->search_ctx == NULL)
		return "";
	return t_strdup_printf("%u/%u", exporter->search_pos,
			       exporter->search_count);
}
