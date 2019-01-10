/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "hex-binary.h"
#include "istream.h"
#include "seq-range-array.h"
#include "imap-util.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "dsync-transaction-log-scan.h"
#include "dsync-mail.h"
#include "dsync-mailbox.h"
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

	/* the final UID for the message */
	uint32_t final_uid;
	/* the original local UID, or 0 if exists only remotely */
	uint32_t local_uid;
	/* the original remote UID, or 0 if exists only remotely */
	uint32_t remote_uid;
	/* UID for the mail in the virtual \All mailbox */
	uint32_t virtual_all_uid;

	bool uid_in_local:1;
	bool uid_is_usable:1;
	bool skip:1;
	bool expunged:1;
	bool copy_failed:1;
	bool saved:1;
};

/* for quickly testing that two-way sync doesn't actually do any unexpected
   modifications. */
#define IMPORTER_DEBUG_CHANGE(importer) /*i_assert(!importer->master_brain)*/

HASH_TABLE_DEFINE_TYPE(guid_new_mail, const char *, struct importer_new_mail *);
HASH_TABLE_DEFINE_TYPE(uid_new_mail, void *, struct importer_new_mail *);

struct dsync_mailbox_importer {
	pool_t pool;
	struct mailbox *box;
	uint32_t last_common_uid;
	uint64_t last_common_modseq, last_common_pvt_modseq;
	uint32_t remote_uid_next;
	uint32_t remote_first_recent_uid;
	uint64_t remote_highest_modseq, remote_highest_pvt_modseq;
	time_t sync_since_timestamp;
	time_t sync_until_timestamp;
	uoff_t sync_max_size;
	enum mailbox_transaction_flags transaction_flags;
	unsigned int hdr_hash_version;
	unsigned int commit_msgs_interval;

	const char *const *hashed_headers;

	enum mail_flags sync_flag;
	const char *sync_keyword;
	bool sync_flag_dontwant;

	struct mailbox_transaction_context *trans, *ext_trans;
	struct mail_search_context *search_ctx;
	struct mail *mail, *ext_mail;

	struct mailbox *virtual_all_box;
	struct mailbox_transaction_context *virtual_trans;
	struct mail *virtual_mail;

	struct mail *cur_mail;
	const char *cur_guid;
	const char *cur_hdr_hash;

	/* UID => struct dsync_mail_change */
	HASH_TABLE_TYPE(dsync_uid_mail_change) local_changes;
	HASH_TABLE_TYPE(dsync_attr_change) local_attr_changes;

	ARRAY_TYPE(seq_range) maybe_expunge_uids;
	ARRAY(struct dsync_mail_change *) maybe_saves;

	/* GUID => struct importer_new_mail */
	HASH_TABLE_TYPE(guid_new_mail) import_guids;
	/* UID => struct importer_new_mail */
	HASH_TABLE_TYPE(uid_new_mail) import_uids;

	ARRAY(struct importer_new_mail *) newmails;
	ARRAY_TYPE(uint32_t) wanted_uids;
	ARRAY_TYPE(uint32_t) saved_uids;
	uint32_t highest_wanted_uid;

	ARRAY(struct dsync_mail_request) mail_requests;
	unsigned int mail_request_idx;

	uint32_t prev_uid, next_local_seq, local_uid_next;
	uint64_t local_initial_highestmodseq, local_initial_highestpvtmodseq;
	unsigned int import_pos, import_count;
	unsigned int first_unsaved_idx, saves_since_commit;

	enum mail_error mail_error;

	bool failed:1;
	bool require_full_resync:1;
	bool debug:1;
	bool stateful_import:1;
	bool last_common_uid_found:1;
	bool cur_uid_has_change:1;
	bool cur_mail_skip:1;
	bool local_expunged_guids_set:1;
	bool new_uids_assigned:1;
	bool want_mail_requests:1;
	bool master_brain:1;
	bool revert_local_changes:1;
	bool mails_have_guids:1;
	bool mails_use_guid128:1;
	bool delete_mailbox:1;
	bool empty_hdr_workaround:1;
};

static const char *dsync_mail_change_type_names[] = {
	"save", "expunge", "flag-change"
};

static bool dsync_mailbox_save_newmails(struct dsync_mailbox_importer *importer,
					const struct dsync_mail *mail,
					struct importer_new_mail *all_newmails,
					bool remote_mail);
static int dsync_mailbox_import_commit(struct dsync_mailbox_importer *importer,
				       bool final);

static void ATTR_FORMAT(2, 3)
imp_debug(struct dsync_mailbox_importer *importer, const char *fmt, ...)
{
	va_list args;

	if (importer->debug) T_BEGIN {
		va_start(args, fmt);
		i_debug("brain %c: Import %s: %s",
			importer->master_brain ? 'M' : 'S',
			mailbox_get_vname(importer->box),
			t_strdup_vprintf(fmt, args));
		va_end(args);
	} T_END;
}

static void
dsync_import_unexpected_state(struct dsync_mailbox_importer *importer,
			      const char *error)
{
	if (!importer->stateful_import) {
		i_error("Mailbox %s: %s", mailbox_get_vname(importer->box),
			error);
	} else {
		i_warning("Mailbox %s doesn't match previous state: %s "
			  "(dsync must be run again without the state)",
			  mailbox_get_vname(importer->box), error);
	}
	importer->require_full_resync = TRUE;
}

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
	importer->cur_mail_skip = TRUE;
}

static void
dsync_mailbox_import_transaction_begin(struct dsync_mailbox_importer *importer)
{
	const enum mailbox_transaction_flags ext_trans_flags =
		importer->transaction_flags |
		MAILBOX_TRANSACTION_FLAG_EXTERNAL |
		MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;

	importer->trans = mailbox_transaction_begin(importer->box,
						    importer->transaction_flags,
						    "dsync import");
	importer->ext_trans = mailbox_transaction_begin(importer->box,
							ext_trans_flags,
							"dsync ext import");
	importer->mail = mail_alloc(importer->trans, 0, NULL);
	importer->ext_mail = mail_alloc(importer->ext_trans, 0, NULL);
}

struct dsync_mailbox_importer *
dsync_mailbox_import_init(struct mailbox *box,
			  struct mailbox *virtual_all_box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  uint64_t last_common_modseq,
			  uint64_t last_common_pvt_modseq,
			  uint32_t remote_uid_next,
			  uint32_t remote_first_recent_uid,
			  uint64_t remote_highest_modseq,
			  uint64_t remote_highest_pvt_modseq,
			  time_t sync_since_timestamp,
			  time_t sync_until_timestamp,
			  uoff_t sync_max_size,
			  const char *sync_flag,
			  unsigned int commit_msgs_interval,
			  enum dsync_mailbox_import_flags flags,
			  unsigned int hdr_hash_version,
			  const char *const *hashed_headers)
{
	struct dsync_mailbox_importer *importer;
	struct mailbox_status status;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync mailbox importer",
				     10240);
	importer = p_new(pool, struct dsync_mailbox_importer, 1);
	importer->pool = pool;
	importer->box = box;
	importer->virtual_all_box = virtual_all_box;
	importer->last_common_uid = last_common_uid;
	importer->last_common_modseq = last_common_modseq;
	importer->last_common_pvt_modseq = last_common_pvt_modseq;
	importer->last_common_uid_found =
		last_common_uid != 0 || last_common_modseq != 0;
	importer->remote_uid_next = remote_uid_next;
	importer->remote_first_recent_uid = remote_first_recent_uid;
	importer->remote_highest_modseq = remote_highest_modseq;
	importer->remote_highest_pvt_modseq = remote_highest_pvt_modseq;
	importer->sync_since_timestamp = sync_since_timestamp;
	importer->sync_until_timestamp = sync_until_timestamp;
	importer->sync_max_size = sync_max_size;
	importer->stateful_import = importer->last_common_uid_found;
	importer->hashed_headers = hashed_headers;

	if (sync_flag != NULL) {
		if (sync_flag[0] == '-') {
			importer->sync_flag_dontwant = TRUE;
			sync_flag++;
		}
		if (sync_flag[0] == '\\')
			importer->sync_flag = imap_parse_system_flag(sync_flag);
		else
			importer->sync_keyword = p_strdup(pool, sync_flag);
	}
	importer->commit_msgs_interval = commit_msgs_interval;
	importer->transaction_flags = MAILBOX_TRANSACTION_FLAG_SYNC;
	if ((flags & DSYNC_MAILBOX_IMPORT_FLAG_NO_NOTIFY) != 0)
		importer->transaction_flags |= MAILBOX_TRANSACTION_FLAG_NO_NOTIFY;

	hash_table_create(&importer->import_guids, pool, 0, str_hash, strcmp);
	hash_table_create_direct(&importer->import_uids, pool, 0);
	i_array_init(&importer->maybe_expunge_uids, 16);
	i_array_init(&importer->maybe_saves, 128);
	i_array_init(&importer->newmails, 128);
	i_array_init(&importer->wanted_uids, 128);
	i_array_init(&importer->saved_uids, 128);

	dsync_mailbox_import_transaction_begin(importer);

	if ((flags & DSYNC_MAILBOX_IMPORT_FLAG_WANT_MAIL_REQUESTS) != 0) {
		i_array_init(&importer->mail_requests, 128);
		importer->want_mail_requests = TRUE;
	}
	importer->master_brain =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_MASTER_BRAIN) != 0;
	importer->revert_local_changes =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_REVERT_LOCAL_CHANGES) != 0;
	importer->debug = (flags & DSYNC_MAILBOX_IMPORT_FLAG_DEBUG) != 0;
	importer->mails_have_guids =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_MAILS_HAVE_GUIDS) != 0;
	importer->mails_use_guid128 =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_MAILS_USE_GUID128) != 0;
	importer->hdr_hash_version = hdr_hash_version;
	importer->empty_hdr_workaround =
		(flags & DSYNC_MAILBOX_IMPORT_FLAG_EMPTY_HDR_WORKAROUND) != 0;

	mailbox_get_open_status(importer->box, STATUS_UIDNEXT |
				STATUS_HIGHESTMODSEQ | STATUS_HIGHESTPVTMODSEQ,
				&status);
	importer->local_uid_next = status.uidnext;
	importer->local_initial_highestmodseq = status.highest_modseq;
	importer->local_initial_highestpvtmodseq = status.highest_pvt_modseq;
	dsync_mailbox_import_search_init(importer);

	if (!importer->stateful_import)
		;
	else if (importer->local_uid_next <= last_common_uid) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"local UIDNEXT %u <= last common UID %u",
			importer->local_uid_next, last_common_uid));
	} else if (importer->local_initial_highestmodseq < last_common_modseq) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"local HIGHESTMODSEQ %"PRIu64" < last common HIGHESTMODSEQ %"PRIu64,
			importer->local_initial_highestmodseq,
			last_common_modseq));
	} else if (importer->local_initial_highestpvtmodseq < last_common_pvt_modseq) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"local HIGHESTMODSEQ %"PRIu64" < last common HIGHESTMODSEQ %"PRIu64,
			importer->local_initial_highestpvtmodseq,
			last_common_pvt_modseq));
	}

	importer->local_changes = dsync_transaction_log_scan_get_hash(log_scan);
	importer->local_attr_changes = dsync_transaction_log_scan_get_attr_hash(log_scan);
	return importer;
}

static int
dsync_mailbox_import_lookup_attr(struct dsync_mailbox_importer *importer,
				 enum mail_attribute_type type, const char *key,
				 struct dsync_mailbox_attribute **attr_r)
{
	struct dsync_mailbox_attribute lookup_attr, *attr;
	const struct dsync_mailbox_attribute *attr_change;
	struct mail_attribute_value value;

	*attr_r = NULL;

	if (mailbox_attribute_get_stream(importer->box, type, key, &value) < 0) {
		i_error("Mailbox %s: Failed to get attribute %s: %s",
			mailbox_get_vname(importer->box), key,
			mailbox_get_last_internal_error(importer->box,
							&importer->mail_error));
		importer->failed = TRUE;
		return -1;
	}

	lookup_attr.type = type;
	lookup_attr.key = key;

	attr_change = hash_table_lookup(importer->local_attr_changes,
					&lookup_attr);
	if (attr_change == NULL &&
	    value.value == NULL && value.value_stream == NULL) {
		/* we have no knowledge of this attribute */
		return 0;
	}
	attr = t_new(struct dsync_mailbox_attribute, 1);
	attr->type = type;
	attr->key = key;
	attr->value = value.value;
	attr->value_stream = value.value_stream;
	attr->last_change = value.last_change;
	if (attr_change != NULL) {
		attr->deleted = attr_change->deleted &&
			!DSYNC_ATTR_HAS_VALUE(attr);
		attr->modseq = attr_change->modseq;
	}
	*attr_r = attr;
	return 0;
}

static int
dsync_istreams_cmp(struct istream *input1, struct istream *input2, int *cmp_r)
{
	const unsigned char *data1, *data2;
	size_t size1, size2, size;

	*cmp_r = -1; /* quiet gcc */

	for (;;) {
		(void)i_stream_read_more(input1, &data1, &size1);
		(void)i_stream_read_more(input2, &data2, &size2);

		if (size1 == 0 || size2 == 0)
			break;
		size = I_MIN(size1, size2);
		*cmp_r = memcmp(data1, data2, size);
		if (*cmp_r != 0)
			return 0;
		i_stream_skip(input1, size);
		i_stream_skip(input2, size);
	}
	if (input1->stream_errno != 0) {
		i_error("read(%s) failed: %s", i_stream_get_name(input1),
			i_stream_get_error(input1));
		return -1;
	}
	if (input2->stream_errno != 0) {
		i_error("read(%s) failed: %s", i_stream_get_name(input2),
			i_stream_get_error(input2));
		return -1;
	}
	if (size1 == 0 && size2 == 0)
		*cmp_r = 0;
	else
		*cmp_r = size1 == 0 ? -1 : 1;
	return 0;
}

static int
dsync_attributes_cmp_values(const struct dsync_mailbox_attribute *attr1,
			    const struct dsync_mailbox_attribute *attr2,
			    int *cmp_r)
{
	struct istream *input1, *input2;
	int ret;

	i_assert(attr1->value_stream != NULL || attr1->value != NULL);
	i_assert(attr2->value_stream != NULL || attr2->value != NULL);

	if (attr1->value != NULL && attr2->value != NULL) {
		*cmp_r = strcmp(attr1->value, attr2->value);
		return 0;
	}
	/* at least one of them is a stream. make both of them streams. */
	input1 = attr1->value_stream != NULL ? attr1->value_stream :
		i_stream_create_from_data(attr1->value, strlen(attr1->value));
	input2 = attr2->value_stream != NULL ? attr2->value_stream :
		i_stream_create_from_data(attr2->value, strlen(attr2->value));
	i_stream_seek(input1, 0);
	i_stream_seek(input2, 0);
	ret = dsync_istreams_cmp(input1, input2, cmp_r);
	if (attr1->value_stream == NULL)
		i_stream_unref(&input1);
	if (attr2->value_stream == NULL)
		i_stream_unref(&input2);
	return ret;
}

static int
dsync_attributes_cmp(const struct dsync_mailbox_attribute *attr,
		     const struct dsync_mailbox_attribute *local_attr,
		     int *cmp_r)
{
	if (DSYNC_ATTR_HAS_VALUE(attr) &&
	    !DSYNC_ATTR_HAS_VALUE(local_attr)) {
		/* remote has a value and local doesn't -> use it */
		*cmp_r = 1;
		return 0;
	} else if (!DSYNC_ATTR_HAS_VALUE(attr) &&
		   DSYNC_ATTR_HAS_VALUE(local_attr)) {
		/* remote doesn't have a value, bt local does -> skip */
		*cmp_r = -1;
		return 0;
	}

	return dsync_attributes_cmp_values(attr, local_attr, cmp_r);
}

static int
dsync_mailbox_import_attribute_real(struct dsync_mailbox_importer *importer,
				    const struct dsync_mailbox_attribute *attr,
				    const struct dsync_mailbox_attribute *local_attr,
				    const char **result_r)
{
	struct mail_attribute_value value;
	int cmp;
	bool ignore = FALSE;

	i_assert(DSYNC_ATTR_HAS_VALUE(attr) || attr->deleted);

	if (attr->deleted &&
	    (local_attr == NULL || !DSYNC_ATTR_HAS_VALUE(local_attr))) {
		/* attribute doesn't exist on either side -> ignore */
		*result_r = "Nonexistent in both sides";
		return 0;
	}
	if (local_attr == NULL) {
		/* we haven't seen this locally -> use whatever remote has */
		*result_r = "Nonexistent locally";
	} else if (local_attr->modseq <= importer->last_common_modseq &&
		   attr->modseq > importer->last_common_modseq &&
		   importer->last_common_modseq > 0) {
		/* we're doing incremental syncing, and we can see that the
		   attribute was changed remotely, but not locally -> use it */
		*result_r = "Changed remotely";
	} else if (local_attr->modseq > importer->last_common_modseq &&
		   attr->modseq <= importer->last_common_modseq &&
		   importer->last_common_modseq > 0) {
		/* we're doing incremental syncing, and we can see that the
		   attribute was changed locally, but not remotely -> ignore */
		*result_r = "Changed locally";
		ignore = TRUE;
	} else if (attr->last_change > local_attr->last_change) {
		/* remote has a newer timestamp -> use it */
		*result_r = "Remote has newer timestamp";
	} else if (attr->last_change < local_attr->last_change) {
		/* remote has an older timestamp -> ignore */
		*result_r = "Local has newer timestamp";
		ignore = TRUE;
	} else {
		/* the timestamps are the same. now we're down to guessing
		   the right answer, unless the values are actually equal,
		   so check that first. next try to use modseqs, but if even
		   they are the same, fallback to just picking one based on the
		   value. */
		if (dsync_attributes_cmp(attr, local_attr, &cmp) < 0) {
			importer->mail_error = MAIL_ERROR_TEMP;
			importer->failed = TRUE;
			return -1;
		}
		if (cmp == 0) {
			/* identical scripts */
			*result_r = "Unchanged value";
			return 0;
		}

		if (attr->modseq > local_attr->modseq) {
			/* remote has a higher modseq -> use it */
			*result_r = "Remote has newer modseq";
		} else if (attr->modseq < local_attr->modseq) {
			/* remote has an older modseq -> ignore */
			*result_r = "Local has newer modseq";
			ignore = TRUE;
		} else if (cmp < 0) {
			ignore = TRUE;
			*result_r = "Value changed, but unknown which is newer - picking local";
		} else {
			*result_r = "Value changed, but unknown which is newer - picking remote";
		}
	}
	if (ignore)
		return 0;

	i_zero(&value);
	value.value = attr->value;
	value.value_stream = attr->value_stream;
	value.last_change = attr->last_change;
	if (mailbox_attribute_set(importer->trans, attr->type,
				  attr->key, &value) < 0) {
		i_error("Mailbox %s: Failed to set attribute %s: %s",
			mailbox_get_vname(importer->box), attr->key,
			mailbox_get_last_internal_error(importer->box, NULL));
		/* the attributes aren't vital, don't fail everything just
		   because of them. */
	}
	return 0;
}

int dsync_mailbox_import_attribute(struct dsync_mailbox_importer *importer,
				   const struct dsync_mailbox_attribute *attr)
{
	struct dsync_mailbox_attribute *local_attr;
	const char *result = "";
	int ret;

	if (dsync_mailbox_import_lookup_attr(importer, attr->type,
					     attr->key, &local_attr) < 0)
		ret = -1;
	else {
		ret = dsync_mailbox_import_attribute_real(importer, attr,
							  local_attr, &result);
		if (local_attr != NULL && local_attr->value_stream != NULL)
			i_stream_unref(&local_attr->value_stream);
	}
	imp_debug(importer, "Import attribute %s: %s", attr->key,
		  ret < 0 ? "failed" : result);
	return ret;
}

static void dsync_mail_error(struct dsync_mailbox_importer *importer,
			     struct mail *mail, const char *field)
{
	const char *errstr;
	enum mail_error error;

	errstr = mailbox_get_last_internal_error(importer->box, &error);
	if (error == MAIL_ERROR_EXPUNGED)
		return;

	i_error("Mailbox %s: Can't lookup %s for UID=%u: %s",
		mailbox_get_vname(mail->box), field, mail->uid, errstr);
	importer->mail_error = error;
	importer->failed = TRUE;
}

static bool
dsync_mail_change_guid_equals(struct dsync_mailbox_importer *importer,
			      const struct dsync_mail_change *change,
			      const char *guid, const char **cmp_guid_r)
{
	guid_128_t guid_128, change_guid_128;

	if (change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
		if (guid_128_from_string(change->guid, change_guid_128) < 0)
			i_unreached();
	} else if (importer->mails_use_guid128) {
		mail_generate_guid_128_hash(change->guid, change_guid_128);
	} else {
		if (cmp_guid_r != NULL)
			*cmp_guid_r = change->guid;
		return strcmp(change->guid, guid) == 0;
	}

	mail_generate_guid_128_hash(guid, guid_128);
	if (memcmp(change_guid_128, guid_128, GUID_128_SIZE) != 0) {
		if (cmp_guid_r != NULL) {
			*cmp_guid_r = t_strdup_printf("%s(guid128, orig=%s)",
				binary_to_hex(change_guid_128, sizeof(change_guid_128)),
				change->guid);
		}
		return FALSE;
	}
	return TRUE;
}

static int
importer_try_next_mail(struct dsync_mailbox_importer *importer,
		       uint32_t wanted_uid)
{
	struct mail_private *pmail;
	const char *hdr_hash;

	if (importer->cur_mail == NULL) {
		/* end of search */
		return -1;
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

		importer->cur_mail_skip = FALSE;
		if (!mailbox_search_next(importer->search_ctx,
					 &importer->cur_mail)) {
			importer->cur_mail = NULL;
			importer->cur_guid = NULL;
			importer->cur_hdr_hash = NULL;
			return -1;
		}
		importer->cur_uid_has_change = FALSE;
	}
	importer->cur_uid_has_change = importer->cur_mail->uid == wanted_uid;
	if (importer->mails_have_guids) {
		if (mail_get_special(importer->cur_mail, MAIL_FETCH_GUID,
				     &importer->cur_guid) < 0) {
			dsync_mail_error(importer, importer->cur_mail, "GUID");
			return 0;
		}
	} else {
		if (dsync_mail_get_hdr_hash(importer->cur_mail,
					    importer->hdr_hash_version,
					    importer->hashed_headers,
					    &hdr_hash) < 0) {
			dsync_mail_error(importer, importer->cur_mail,
					 "header hash");
			return 0;
		} 
		pmail = (struct mail_private *)importer->cur_mail;
		importer->cur_hdr_hash = p_strdup(pmail->pool, hdr_hash);
		importer->cur_guid = "";
	}
	/* make sure next_local_seq gets updated in case we came here
	   because of min_uid */
	importer->next_local_seq = importer->cur_mail->seq;
	return 1;
}

static bool
importer_next_mail(struct dsync_mailbox_importer *importer, uint32_t wanted_uid)
{
	int ret;

	for (;;) {
		T_BEGIN {
			ret = importer_try_next_mail(importer, wanted_uid);
		} T_END;
		if (ret != 0 || importer->failed)
			break;
		importer->next_local_seq = importer->cur_mail->seq + 1;
	}
	return ret > 0;
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

static void newmail_link(struct dsync_mailbox_importer *importer,
			 struct importer_new_mail *newmail, uint32_t remote_uid)
{
	struct importer_new_mail *first_mail, **last, *mail, *link = NULL;

	if (*newmail->guid != '\0') {
		first_mail = hash_table_lookup(importer->import_guids,
					       newmail->guid);
		if (first_mail == NULL) {
			/* first mail for this GUID */
			hash_table_insert(importer->import_guids,
					  newmail->guid, newmail);
			return;
		}
	} else {
		if (remote_uid == 0) {
			/* mail exists only locally. we don't want to request
			   it, and we'll assume it has no duplicate
			   instances. */
			return;
		}
		first_mail = hash_table_lookup(importer->import_uids,
					       POINTER_CAST(remote_uid));
		if (first_mail == NULL) {
			/* first mail for this UID */
			hash_table_insert(importer->import_uids,
					  POINTER_CAST(remote_uid), newmail);
			return;
		}
	}
	/* 1) add the newmail to the end of the linked list
	   2) find our link

	   FIXME: this loop is slow if the same GUID has a ton of instances.
	   Could it be improved in some way? */
	last = &first_mail->next;
	for (mail = first_mail; mail != NULL; mail = mail->next) {
		if (mail->final_uid == newmail->final_uid)
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

static void
dsync_mailbox_revert_existing_uid(struct dsync_mailbox_importer *importer,
				  uint32_t uid, const char *reason)
{
	i_assert(importer->revert_local_changes);

	/* UID either already exists or UIDNEXT is too high. we can't set the
	   wanted UID, so we'll need to delete the whole mailbox and resync */
	i_warning("Deleting mailbox '%s': UID=%u already exists locally for a different mail: %s",
		  mailbox_get_vname(importer->box), uid, reason);
	importer->delete_mailbox = TRUE;
	importer->mail_error = MAIL_ERROR_TEMP;
	importer->failed = TRUE;
}

static bool dsync_mailbox_try_save_cur(struct dsync_mailbox_importer *importer,
				       struct dsync_mail_change *save_change)
{
	struct importer_mail m1, m2;
	struct importer_new_mail *newmail;
	int diff;
	bool remote_saved;

	i_zero(&m1);
	if (importer->cur_mail != NULL) {
		m1.guid = importer->mails_have_guids ?
			importer->cur_guid : importer->cur_hdr_hash;
		m1.uid = importer->cur_mail->uid;
	}
	i_zero(&m2);
	if (save_change != NULL) {
		m2.guid = importer->mails_have_guids ?
			save_change->guid : save_change->hdr_hash;
		m2.uid = save_change->uid;
		i_assert(save_change->type != DSYNC_MAIL_CHANGE_TYPE_EXPUNGE);
	}

	if (importer->empty_hdr_workaround && !importer->mails_have_guids &&
	    importer->cur_mail != NULL && save_change != NULL &&
	    (dsync_mail_hdr_hash_is_empty(m1.guid) ||
	     dsync_mail_hdr_hash_is_empty(m2.guid))) {
		/* one of the headers is empty. assume it's broken and that
		   the header matches what we have currently. */
		diff = 0;
	} else {
		diff = importer_mail_cmp(&m1, &m2);
	}
	if (diff < 0) {
		/* add a record for local mail */
		i_assert(importer->cur_mail != NULL);
		if (importer->revert_local_changes) {
			if (save_change == NULL &&
			    importer->cur_mail->uid >= importer->remote_uid_next) {
				dsync_mailbox_revert_existing_uid(importer, importer->cur_mail->uid,
					t_strdup_printf("higher than remote's UIDs (remote UIDNEXT=%u)", importer->remote_uid_next));
				return TRUE;
			}
			mail_expunge(importer->cur_mail);
			importer->cur_mail_skip = TRUE;
			importer->next_local_seq++;
			return FALSE;
		}
		newmail = p_new(importer->pool, struct importer_new_mail, 1);
		newmail->guid = p_strdup(importer->pool, importer->cur_guid);
		newmail->final_uid = importer->cur_mail->uid;
		newmail->local_uid = importer->cur_mail->uid;
		newmail->uid_in_local = TRUE;
		newmail->uid_is_usable =
			newmail->final_uid >= importer->remote_uid_next;
		remote_saved = FALSE;
	} else if (diff > 0) {
		i_assert(save_change != NULL);
		newmail = p_new(importer->pool, struct importer_new_mail, 1);
		newmail->guid = save_change->guid;
		newmail->final_uid = save_change->uid;
		newmail->remote_uid = save_change->uid;
		newmail->uid_in_local = FALSE;
		newmail->uid_is_usable =
			newmail->final_uid >= importer->local_uid_next;
		if (!newmail->uid_is_usable && importer->revert_local_changes) {
			dsync_mailbox_revert_existing_uid(importer, newmail->final_uid,
				t_strdup_printf("UID >= local UIDNEXT=%u", importer->local_uid_next));
			return TRUE;
		}
		remote_saved = TRUE;
	} else {
		/* identical */
		i_assert(importer->cur_mail != NULL);
		i_assert(save_change != NULL);
		newmail = p_new(importer->pool, struct importer_new_mail, 1);
		newmail->guid = save_change->guid;
		newmail->final_uid = importer->cur_mail->uid;
		newmail->local_uid = importer->cur_mail->uid;
		newmail->remote_uid = save_change->uid;
		newmail->uid_in_local = TRUE;
		newmail->uid_is_usable = TRUE;
		newmail->link = newmail;
		remote_saved = TRUE;
	}

	if (newmail->uid_in_local) {
		importer->cur_mail_skip = TRUE;
		importer->next_local_seq++;
	}
	/* NOTE: assumes save_change is allocated from importer pool */
	newmail->change = save_change;

	array_push_back(&importer->newmails, &newmail);
	newmail_link(importer, newmail,
		     save_change == NULL ? 0 : save_change->uid);
	return remote_saved;
}

static bool ATTR_NULL(2)
dsync_mailbox_try_save(struct dsync_mailbox_importer *importer,
		       struct dsync_mail_change *save_change)
{
	if (importer->cur_mail_skip) {
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
	const char *guid, *cmp_guid;

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
	if (!dsync_mail_change_guid_equals(importer, change, guid, &cmp_guid)) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"Unexpected GUID mismatch for UID=%u: %s != %s",
			change->uid, guid, cmp_guid));
		return FALSE;
	}
	return TRUE;
}

static bool dsync_check_cur_guid(struct dsync_mailbox_importer *importer,
				 const struct dsync_mail_change *change)
{
	const char *cmp_guid;

	if (change->guid == NULL || change->guid[0] == '\0' ||
	    importer->cur_guid[0] == '\0')
		return TRUE;
	if (!dsync_mail_change_guid_equals(importer, change,
					   importer->cur_guid, &cmp_guid)) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"Unexpected GUID mismatch (2) for UID=%u: %s != %s",
			change->uid, importer->cur_guid, cmp_guid));
		return FALSE;
	}
	return TRUE;
}

static void
merge_flags(uint32_t local_final, uint32_t local_add, uint32_t local_remove,
	    uint32_t remote_final, uint32_t remote_add, uint32_t remote_remove,
	    uint32_t pvt_mask, bool prefer_remote, bool prefer_pvt_remote,
	    uint32_t *change_add_r, uint32_t *change_remove_r,
	    bool *remote_changed, bool *remote_pvt_changed)
{
	uint32_t combined_add, combined_remove, conflict_flags;
	uint32_t local_wanted, remote_wanted, conflict_pvt_flags;

	/* resolve conflicts */
	conflict_flags = local_add & remote_remove;
	if (conflict_flags != 0) {
		conflict_pvt_flags = conflict_flags & pvt_mask;
		conflict_flags &= ~pvt_mask;
		if (prefer_remote)
			local_add &= ~conflict_flags;
		else
			remote_remove &= ~conflict_flags;
		if (prefer_pvt_remote)
			local_add &= ~conflict_pvt_flags;
		else
			remote_remove &= ~conflict_pvt_flags;
	}
	conflict_flags = local_remove & remote_add;
	if (conflict_flags != 0) {
		conflict_pvt_flags = conflict_flags & pvt_mask;
		conflict_flags &= ~pvt_mask;
		if (prefer_remote)
			local_remove &= ~conflict_flags;
		else
			remote_add &= ~conflict_flags;
		if (prefer_pvt_remote)
			local_remove &= ~conflict_pvt_flags;
		else
			remote_add &= ~conflict_pvt_flags;
	}
	
	combined_add = local_add|remote_add;
	combined_remove = local_remove|remote_remove;
	i_assert((combined_add & combined_remove) == 0);

	/* don't change flags that are currently identical in both sides */
	conflict_flags = local_final ^ remote_final;
	combined_add &= conflict_flags;
	combined_remove &= conflict_flags;

	/* see if there are conflicting final flags */
	local_wanted = (local_final|combined_add) & ~combined_remove;
	remote_wanted = (remote_final|combined_add) & ~combined_remove;

	conflict_flags = local_wanted ^ remote_wanted;
	if (conflict_flags != 0) {
		if (prefer_remote && prefer_pvt_remote)
			local_wanted = remote_wanted;
		else if (prefer_remote && !prefer_pvt_remote) {
			local_wanted = (local_wanted & pvt_mask) |
				(remote_wanted & ~pvt_mask);
		} else if (!prefer_remote && prefer_pvt_remote) {
			local_wanted = (local_wanted & ~pvt_mask) |
				(remote_wanted & pvt_mask);
		}
	}

	*change_add_r = local_wanted & ~local_final;
	*change_remove_r = local_final & ~local_wanted;
	if ((local_wanted & ~pvt_mask) != (remote_final & ~pvt_mask))
		*remote_changed = TRUE;
	if ((local_wanted & pvt_mask) != (remote_final & pvt_mask))
		*remote_pvt_changed = TRUE;
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
	       bool prefer_remote,
	       bool *remote_changed, bool *remote_pvt_changed)
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
			break;
		case KEYWORD_CHANGE_REMOVE:
			remote_remove[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_FINAL:
			remote_final[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_ADD_AND_FINAL:
			remote_add[name_idx/32] |= 1U << (name_idx%32);
			remote_final[name_idx/32] |= 1U << (name_idx%32);
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
		case KEYWORD_CHANGE_ADD_AND_FINAL:
			local_add[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_REMOVE:
			local_remove[name_idx/32] |= 1U << (name_idx%32);
			break;
		case KEYWORD_CHANGE_FINAL:
			break;
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
			    0, prefer_remote, prefer_remote,
			    &change_add[i], &change_remove[i],
			    remote_changed, remote_pvt_changed);
		if (change_add[i] != 0) {
			keywords_append(&add_keywords, &all_keywords,
					change_add[i], i*32);
		}
		if (change_remove[i] != 0) {
			keywords_append(&remove_keywords, &all_keywords,
					change_remove[i], i*32);
		}
	}

	/* apply changes */
	if (array_count(&add_keywords) > 0) {
		array_append_zero(&add_keywords);
		kw = mailbox_keywords_create_valid(mail->box,
			array_first(&add_keywords));
		mail_update_keywords(mail, MODIFY_ADD, kw);
		mailbox_keywords_unref(&kw);
	}
	if (array_count(&remove_keywords) > 0) {
		array_append_zero(&remove_keywords);
		kw = mailbox_keywords_create_valid(mail->box,
			array_first(&remove_keywords));
		mail_update_keywords(mail, MODIFY_REMOVE, kw);
		mailbox_keywords_unref(&kw);
	}
}

static void
dsync_mailbox_import_replace_flags(struct mail *mail,
				   const struct dsync_mail_change *change)
{
	ARRAY_TYPE(const_string) keywords;
	struct mail_keywords *kw;
	const char *const *changes, *name;
	unsigned int i, count;

	if (array_is_created(&change->keyword_changes))
		changes = array_get(&change->keyword_changes, &count);
	else {
		changes = NULL;
		count = 0;
	}
	t_array_init(&keywords, count+1);
	for (i = 0; i < count; i++) {
		switch (changes[i][0]) {
		case KEYWORD_CHANGE_ADD:
		case KEYWORD_CHANGE_FINAL:
		case KEYWORD_CHANGE_ADD_AND_FINAL:
			name = changes[i]+1;
			array_append(&keywords, &name, 1);
			break;
		case KEYWORD_CHANGE_REMOVE:
			break;
		}
	}
	array_append_zero(&keywords);

	kw = mailbox_keywords_create_valid(mail->box, array_first(&keywords));
	mail_update_keywords(mail, MODIFY_REPLACE, kw);
	mailbox_keywords_unref(&kw);

	mail_update_flags(mail, MODIFY_REPLACE,
			  change->add_flags | change->final_flags);
	if (mail_get_modseq(mail) < change->modseq)
		mail_update_modseq(mail, change->modseq);
	if (mail_get_pvt_modseq(mail) < change->pvt_modseq)
		mail_update_pvt_modseq(mail, change->pvt_modseq);
}

static void
dsync_mailbox_import_flag_change(struct dsync_mailbox_importer *importer,
				 const struct dsync_mail_change *change)
{
	const struct dsync_mail_change *local_change;
	enum mail_flags local_add, local_remove;
	uint32_t change_add, change_remove;
	uint64_t new_modseq;
	ARRAY_TYPE(const_string) local_keyword_changes = ARRAY_INIT;
	struct mail *mail;
	bool prefer_remote, prefer_pvt_remote;
	bool remote_changed = FALSE, remote_pvt_changed = FALSE;

	i_assert((change->add_flags & change->remove_flags) == 0);

	if (importer->cur_mail != NULL &&
	    importer->cur_mail->uid == change->uid) {
		if (!dsync_check_cur_guid(importer, change))
			return;
		mail = importer->cur_mail;
	} else {
		if (!dsync_import_set_mail(importer, change))
			return;
		mail = importer->mail;
	}

	if (importer->revert_local_changes) {
		/* dsync backup: just make the local look like remote. */
		dsync_mailbox_import_replace_flags(mail, change);
		return;
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
	if (mail_get_pvt_modseq(mail) < change->pvt_modseq)
		prefer_pvt_remote = TRUE;
	else if (mail_get_pvt_modseq(mail) > change->pvt_modseq)
		prefer_pvt_remote = FALSE;
	else
		prefer_pvt_remote = !importer->master_brain;

	/* merge flags */
	merge_flags(mail_get_flags(mail), local_add, local_remove,
		    change->final_flags, change->add_flags, change->remove_flags,
		    mailbox_get_private_flags_mask(mail->box),
		    prefer_remote, prefer_pvt_remote,
		    &change_add, &change_remove,
		    &remote_changed, &remote_pvt_changed);

	if (change_add != 0)
		mail_update_flags(mail, MODIFY_ADD, change_add);
	if (change_remove != 0)
		mail_update_flags(mail, MODIFY_REMOVE, change_remove);

	/* merge keywords */
	merge_keywords(mail, &local_keyword_changes, &change->keyword_changes,
		       prefer_remote, &remote_changed, &remote_pvt_changed);

	/* update modseqs. try to anticipate when we have to increase modseq
	   to get it closer to what remote has (although we can't guess it
	   exactly correctly) */
	new_modseq = change->modseq;
	if (remote_changed && new_modseq <= importer->remote_highest_modseq)
		new_modseq = importer->remote_highest_modseq+1;
	if (mail_get_modseq(mail) < new_modseq)
		mail_update_modseq(mail, new_modseq);

	new_modseq = change->pvt_modseq;
	if (remote_pvt_changed && new_modseq <= importer->remote_highest_pvt_modseq)
		new_modseq = importer->remote_highest_pvt_modseq+1;
	if (mail_get_pvt_modseq(mail) < new_modseq)
		mail_update_pvt_modseq(mail, new_modseq);
}

static bool
dsync_mail_change_have_keyword(const struct dsync_mail_change *change,
			       const char *keyword)
{
	const char *const *strp;

	if (!array_is_created(&change->keyword_changes))
		return FALSE;

	array_foreach(&change->keyword_changes, strp) {
		switch ((*strp)[0]) {
		case KEYWORD_CHANGE_FINAL:
		case KEYWORD_CHANGE_ADD_AND_FINAL:
			if (strcasecmp((*strp)+1, keyword) == 0)
				return TRUE;
			break;
		default:
			break;
		}
	}
	return FALSE;
}

static bool
dsync_mailbox_import_want_change(struct dsync_mailbox_importer *importer,
				 const struct dsync_mail_change *change,
				 const char **result_r)
{
	if (importer->sync_since_timestamp > 0) {
		i_assert(change->received_timestamp > 0);
		if (change->received_timestamp < importer->sync_since_timestamp) {
			/* mail has too old timestamp - skip it */
			*result_r = "Ignoring missing local mail with too old timestamp";
			return FALSE;
		}
	}
	if (importer->sync_until_timestamp > 0) {
		i_assert(change->received_timestamp > 0);
		if (change->received_timestamp > importer->sync_until_timestamp) {
			/* mail has too new timestamp - skip it */
			*result_r = "Ignoring missing local mail with too new timestamp";
			return FALSE;
		}
	}
	if (importer->sync_max_size > 0) {
		i_assert(change->virtual_size != (uoff_t)-1);
		if (change->virtual_size < importer->sync_max_size) {
			/* mail is too large - skip it */
			*result_r = "Ignoring missing local mail with too large size";
			return FALSE;
		}
	}
	if (importer->sync_flag != 0) {
		bool have_flag = (change->final_flags & importer->sync_flag) != 0;

		if (have_flag && importer->sync_flag_dontwant) {
			*result_r = "Ignoring missing local mail that doesn't have wanted flags";
			return FALSE;
		}
		if (!have_flag && !importer->sync_flag_dontwant) {
			*result_r = "Ignoring missing local mail that has unwanted flags";
			return FALSE;
		}
	}
	if (importer->sync_keyword != NULL) {
		bool have_kw = dsync_mail_change_have_keyword(change, importer->sync_keyword);

		if (have_kw && importer->sync_flag_dontwant) {
			*result_r = "Ignoring missing local mail that doesn't have wanted keywords";
			return FALSE;
		}
		if (!have_kw && !importer->sync_flag_dontwant) {
			*result_r = "Ignoring missing local mail that has unwanted keywords";
			return FALSE;
		}
	}
	return TRUE;
}

static void
dsync_mailbox_import_save(struct dsync_mailbox_importer *importer,
			  const struct dsync_mail_change *change)
{
	struct dsync_mail_change *save;
	const char *result;

	i_assert(change->guid != NULL);

	if (change->uid == importer->last_common_uid) {
		/* we've already verified that the GUID matches.
		   apply flag changes if there are any. */
		i_assert(!importer->last_common_uid_found);
		dsync_mailbox_import_flag_change(importer, change);
		return;
	}
	if (!dsync_mailbox_import_want_change(importer, change, &result))
		return;

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
		i_assert(importer->cur_mail == NULL ||
			 change->uid < importer->cur_mail->uid);
		array_push_back(&importer->maybe_saves, &save);
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
	} else if (importer->cur_mail == NULL ||
		   change->uid < importer->cur_mail->uid) {
		/* already expunged locally, we can ignore this.
		   uid=last_common_uid if we managed to verify from
		   transaction log that the GUIDs match */
		i_assert(change->uid >= importer->last_common_uid);
	} else if (change->uid == importer->last_common_uid) {
		/* already verified that the GUID matches */
		i_assert(importer->cur_mail->uid == change->uid);
		if (dsync_check_cur_guid(importer, change))
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
	importer->cur_hdr_hash = NULL;
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

	if (importer->debug) T_BEGIN {
		string_t *expunges = t_str_new(64);

		imap_write_seq_range(expunges, &importer->maybe_expunge_uids);
		imp_debug(importer, "Last common UID=%u. Delayed expunges=%s",
			  importer->last_common_uid, str_c(expunges));
	} T_END;

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
		if (saves[i]->uid > importer->last_common_uid) {
			imp_debug(importer, "Delayed save UID=%u: Save",
				  saves[i]->uid);
			dsync_mailbox_save(importer, saves[i]);
		} else {
			imp_debug(importer, "Delayed save UID=%u: Ignore",
				  saves[i]->uid);
		}
	}
}

static int
dsync_mailbox_import_match_msg(struct dsync_mailbox_importer *importer,
			       const struct dsync_mail_change *change,
			       const char **result_r)
{
	const char *hdr_hash, *cmp_guid;

	if (*change->guid != '\0' && *importer->cur_guid != '\0') {
		/* we have GUIDs, verify them */
		if (dsync_mail_change_guid_equals(importer, change,
						  importer->cur_guid, &cmp_guid)) {
			*result_r = "GUIDs match";
			return 1;
		} else {
			*result_r = t_strdup_printf("GUIDs don't match (%s vs %s)",
						    importer->cur_guid, cmp_guid);
			return 0;
		}
	}

	/* verify hdr_hash if it exists */
	if (change->hdr_hash == NULL) {
		i_assert(*importer->cur_guid == '\0');
		if (change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
			/* the message was already expunged, so we don't know
			   its header. return "unknown". */
			*result_r = "Unknown match for expunge";
			return -1;
		}
		i_error("Mailbox %s: GUIDs not supported, "
			"sync with header hashes instead",
			mailbox_get_vname(importer->box));
		importer->mail_error = MAIL_ERROR_TEMP;
		importer->failed = TRUE;
		*result_r = "Error, invalid parameters";
		return -1;
	}

	if (dsync_mail_get_hdr_hash(importer->cur_mail,
				    importer->hdr_hash_version,
				    importer->hashed_headers, &hdr_hash) < 0) {
		dsync_mail_error(importer, importer->cur_mail, "hdr-stream");
		*result_r = "Error fetching header stream";
		return -1;
	}
	if (importer->empty_hdr_workaround &&
	    (dsync_mail_hdr_hash_is_empty(change->hdr_hash) ||
	     dsync_mail_hdr_hash_is_empty(hdr_hash))) {
		*result_r = "Empty headers found with workaround enabled - assuming a match";
		return 1;
	} else if (strcmp(change->hdr_hash, hdr_hash) == 0) {
		*result_r = "Headers hashes match";
		return 1;
	} else {
		*result_r = t_strdup_printf("Headers hashes don't match (%s vs %s)",
					    change->hdr_hash, hdr_hash);
		return 0;
	}
}

static bool
dsync_mailbox_find_common_expunged_uid(struct dsync_mailbox_importer *importer,
				       const struct dsync_mail_change *change,
				       const char **result_r)
{
	const struct dsync_mail_change *local_change;

	if (*change->guid == '\0') {
		/* remote doesn't support GUIDs, can't verify expunge */
		*result_r = "GUIDs not supported, can't verify expunge";
		return FALSE;
	}

	/* local message is expunged. see if we can find its GUID from
	   transaction log and check if the GUIDs match. The GUID in
	   log is a 128bit GUID, so we may need to convert the remote's
	   GUID string to 128bit GUID first. */
	local_change = hash_table_lookup(importer->local_changes,
					 POINTER_CAST(change->uid));
	if (local_change == NULL || local_change->guid == NULL) {
		*result_r = "Expunged local mail's GUID not found";
		return FALSE;
	}

	i_assert(local_change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE);
	if (dsync_mail_change_guid_equals(importer, local_change,
					  change->guid, NULL)) {
		importer->last_common_uid = change->uid;
		*result_r = "Expunged local mail's GUID matches remote";
	} else if (change->type != DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
		dsync_mailbox_common_uid_found(importer);
		*result_r = "Expunged local mail's GUID doesn't match remote GUID";
	} else {
		/* GUID mismatch for two expunged mails. dsync can't update
		   GUIDs for already expunged messages, so we can't immediately
		   determine that the rest of the messages are a mismatch. so
		   for now we'll just skip over this pair. */
		*result_r = "Expunged mails' GUIDs don't match - delaying decision";
		/* NOTE: the return value here doesn't matter, because the only
		   caller that checks for it never reaches this code path */
	}
	return TRUE;
}

static void
dsync_mailbox_revert_missing(struct dsync_mailbox_importer *importer,
			     const struct dsync_mail_change *change)
{
	i_assert(importer->revert_local_changes);

	/* mail exists on remote, but not locally. we'll need to
	   insert this mail back, which means deleting the whole
	   mailbox and resyncing. */
	i_warning("Deleting mailbox '%s': UID=%u GUID=%s is missing locally",
		  mailbox_get_vname(importer->box),
		  change->uid, change->guid);
	importer->delete_mailbox = TRUE;
	importer->mail_error = MAIL_ERROR_TEMP;
	importer->failed = TRUE;
}

static void
dsync_mailbox_find_common_uid(struct dsync_mailbox_importer *importer,
			      const struct dsync_mail_change *change,
			      const char **result_r)
{
	int ret;

	i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE ||
		 ((change->received_timestamp > 0 ||
		   (importer->sync_since_timestamp == 0 &&
		    importer->sync_until_timestamp == 0)) &&
		  (change->virtual_size != (uoff_t)-1 || importer->sync_max_size == 0)));

	/* try to find the matching local mail */
	if (!importer_next_mail(importer, change->uid)) {
		/* no more local mails. we can still try to match
		   expunged mails though. */
		if (change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
			/* mail doesn't exist remotely either, don't bother
			   looking it up locally. */
			*result_r = "Expunged mail not found locally";
			return;
		}
		i_assert(change->guid != NULL);
		if (!dsync_mailbox_import_want_change(importer, change, result_r))
			;
		else if (importer->local_uid_next <= change->uid) {
			dsync_mailbox_common_uid_found(importer);
			*result_r = "Mail's UID is above local UIDNEXT";
		} else if (importer->revert_local_changes) {
			dsync_mailbox_revert_missing(importer, change);
			*result_r = "Reverting local change by deleting mailbox";
		} else if (!dsync_mailbox_find_common_expunged_uid(importer, change, result_r)) {
			/* it's unknown if this mail existed locally and was
			   expunged. since we don't want to lose any mails,
			   assume that we need to preserve the mail. use the
			   last message with a matching GUID as the last common
			   UID. */
			dsync_mailbox_common_uid_found(importer);
		}
		*result_r = t_strdup_printf("%s - No more local mails found", *result_r);
		return;
	}

	if (change->guid == NULL) {
		/* we can't know if this UID matches */
		i_assert(change->type == DSYNC_MAIL_CHANGE_TYPE_EXPUNGE);
		*result_r = "Expunged mail has no GUID, can't verify it";
		return;
	}
	if (importer->cur_mail->uid == change->uid) {
		/* we have a matching local UID. check GUID to see if it's
		   really the same mail or not */
		if ((ret = dsync_mailbox_import_match_msg(importer, change, result_r)) < 0) {
			/* unknown */
			return;
		}
		if (ret > 0) {
			importer->last_common_uid = change->uid;
		} else if (!importer->revert_local_changes) {
			/* mismatch - found the first non-common UID */
			dsync_mailbox_common_uid_found(importer);
		} else {
			/* mismatch and we want to revert local changes -
			   need to delete the mailbox. */
			dsync_mailbox_revert_existing_uid(importer, change->uid, *result_r);
		}
		return;
	}
	/* mail exists remotely, but doesn't exist locally. */
	if (!dsync_mailbox_import_want_change(importer, change, result_r))
		return;
	if (importer->revert_local_changes &&
	    change->type != DSYNC_MAIL_CHANGE_TYPE_EXPUNGE) {
		dsync_mailbox_revert_missing(importer, change);
		*result_r = "Reverting local change by deleting mailbox";
	} else {
		(void)dsync_mailbox_find_common_expunged_uid(importer, change, result_r);
	}
	*result_r = t_strdup_printf("%s (next local mail UID=%u)",
		*result_r, importer->cur_mail == NULL ? 0 : importer->cur_mail->uid);
}

int dsync_mailbox_import_change(struct dsync_mailbox_importer *importer,
				const struct dsync_mail_change *change)
{
	const char *result;

	i_assert(!importer->new_uids_assigned);
	i_assert(importer->prev_uid < change->uid);

	importer->prev_uid = change->uid;

	if (importer->failed)
		return -1;
	if (importer->require_full_resync)
		return 0;

	if (!importer->last_common_uid_found) {
		result = NULL;
		dsync_mailbox_find_common_uid(importer, change, &result);
		i_assert(result != NULL);
	} else {
		result = "New mail";
	}

	imp_debug(importer, "Import change type=%s GUID=%s UID=%u hdr_hash=%s result=%s",
		  dsync_mail_change_type_names[change->type],
		  change->guid != NULL ? change->guid : "<unknown>", change->uid,
		  change->hdr_hash != NULL ? change->hdr_hash : "", result);

	if (importer->failed)
		return -1;
	if (importer->require_full_resync)
		return 0;

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
			return 0;
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
				 importer->cur_mail == NULL ||
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
	return importer->failed ? -1 : 0;
}

static int
importer_new_mail_final_uid_cmp(struct importer_new_mail *const *newmail1,
				struct importer_new_mail *const *newmail2)
{
	if ((*newmail1)->final_uid < (*newmail2)->final_uid)
		return -1;
	if ((*newmail1)->final_uid > (*newmail2)->final_uid)
		return 1;
	return 0;
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
			i_assert(newmail->final_uid != 0);
			continue;
		}

		/* figure out what UID to use for the mail */
		if (newmail->uid_is_usable) {
			/* keep the UID */
			new_uid = newmail->final_uid;
		} else if (newmail->link != NULL &&
			   newmail->link->uid_is_usable) {
			/* we can use the linked message's UID and expunge
			   this mail */
			new_uid = newmail->link->final_uid;
		} else {
			i_assert(!importer->revert_local_changes);
			new_uid = common_uid_next++;
			imp_debug(importer, "UID %u isn't usable, assigning new UID %u",
				  newmail->final_uid, new_uid);
		}

		newmail->final_uid = new_uid;
		if (newmail->link != NULL && newmail->link != newmail) {
			/* skip processing the linked mail */
			newmail->link->skip = TRUE;
		}
	}
	importer->last_common_uid = common_uid_next-1;
	importer->new_uids_assigned = TRUE;
	/* Sort the newmails by their final_uid. This is used for tracking
	   whether an intermediate commit is allowed. */
	array_sort(&importer->newmails, importer_new_mail_final_uid_cmp);
}

static int
dsync_mailbox_import_local_uid(struct dsync_mailbox_importer *importer,
			       struct mail *mail, uint32_t uid, const char *guid,
			       struct dsync_mail *dmail_r)
{
	const char *error_field, *errstr;
	enum mail_error error;

	if (!mail_set_uid(mail, uid))
		return 0;

	/* NOTE: Errors are logged, but they don't cause the entire import
	   to fail. */
	if (dsync_mail_fill(mail, TRUE, dmail_r, &error_field) < 0) {
		errstr = mailbox_get_last_internal_error(mail->box, &error);
		if (error == MAIL_ERROR_EXPUNGED)
			return 0;

		i_error("Mailbox %s: Can't lookup %s for UID=%u: %s",
			mailbox_get_vname(importer->box),
			error_field, uid, errstr);
		return -1;
	}
	if (*guid != '\0' && strcmp(guid, dmail_r->guid) != 0) {
		dsync_import_unexpected_state(importer, t_strdup_printf(
			"Unexpected GUID mismatch (3) for UID=%u: %s != %s",
			uid, dmail_r->guid, guid));
		return -1;
	}
	return 1;
}

static void
dsync_mailbox_import_saved_uid(struct dsync_mailbox_importer *importer,
			       uint32_t uid)
{
	i_assert(importer->search_ctx == NULL);

	if (importer->highest_wanted_uid < uid)
		importer->highest_wanted_uid = uid;
	array_push_back(&importer->wanted_uids, &uid);
}

static void
dsync_mailbox_import_update_first_saved(struct dsync_mailbox_importer *importer)
{
	struct importer_new_mail *const *newmails;
	unsigned int count;

	newmails = array_get(&importer->newmails, &count);
	while (importer->first_unsaved_idx < count) {
		if (!newmails[importer->first_unsaved_idx]->saved)
			break;
		importer->first_unsaved_idx++;
	}
}

static void
dsync_mailbox_import_saved_newmail(struct dsync_mailbox_importer *importer,
				   struct importer_new_mail *newmail)
{
	dsync_mailbox_import_saved_uid(importer, newmail->final_uid);
	newmail->saved = TRUE;

	dsync_mailbox_import_update_first_saved(importer);
	importer->saves_since_commit++;
	/* we can commit only if all the upcoming mails will have UIDs that
	   are larger than we're committing.

	   Note that if any existing UIDs have been changed, the new UID is
	   usually higher than anything that is being saved so we can't do
	   an intermediate commit. It's too much extra work to try to handle
	   that situation. So here this never happens, because then
	   array_count(wanted_uids) is always higher than first_unsaved_idx. */
	if (importer->saves_since_commit >= importer->commit_msgs_interval &&
	    importer->first_unsaved_idx == array_count(&importer->wanted_uids)) {
		if (dsync_mailbox_import_commit(importer, FALSE) < 0)
			importer->failed = TRUE;
		importer->saves_since_commit = 0;
	}
}

static bool
dsync_msg_change_uid(struct dsync_mailbox_importer *importer,
		     uint32_t old_uid, uint32_t new_uid)
{
	struct mail_save_context *save_ctx;

	IMPORTER_DEBUG_CHANGE(importer);

	if (!mail_set_uid(importer->mail, old_uid))
		return FALSE;

	save_ctx = mailbox_save_alloc(importer->ext_trans);
	mailbox_save_copy_flags(save_ctx, importer->mail);
	mailbox_save_set_uid(save_ctx, new_uid);
	if (mailbox_move(&save_ctx, importer->mail) < 0)
		return FALSE;
	dsync_mailbox_import_saved_uid(importer, new_uid);
	return TRUE;
}

static bool
dsync_mailbox_import_change_uid(struct dsync_mailbox_importer *importer,
				ARRAY_TYPE(seq_range) *unwanted_uids,
				uint32_t wanted_uid)
{
	const struct seq_range *range;
	unsigned int count, n;
	struct seq_range_iter iter;
	uint32_t uid;

	/* optimize by first trying to use the latest UID */
	range = array_get(unwanted_uids, &count);
	if (count == 0)
		return FALSE;
	if (dsync_msg_change_uid(importer, range[count-1].seq2, wanted_uid)) {
		seq_range_array_remove(unwanted_uids, range[count-1].seq2);
		return TRUE;
	}
	if (mailbox_get_last_mail_error(importer->box) == MAIL_ERROR_EXPUNGED)
		seq_range_array_remove(unwanted_uids, range[count-1].seq2);

	/* now try to use any of them by iterating through them. (would be
	   easier&faster to just iterate backwards, but probably too much
	   trouble to add such API) */
	n = 0; seq_range_array_iter_init(&iter, unwanted_uids);
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		if (dsync_msg_change_uid(importer, uid, wanted_uid)) {
			seq_range_array_remove(unwanted_uids, uid);
			return TRUE;
		}
		if (mailbox_get_last_mail_error(importer->box) == MAIL_ERROR_EXPUNGED)
			seq_range_array_remove(unwanted_uids, uid);
	}
	return FALSE;
}

static bool
dsync_mailbox_import_try_local(struct dsync_mailbox_importer *importer,
			       struct importer_new_mail *all_newmails,
			       ARRAY_TYPE(seq_range) *local_uids,
			       ARRAY_TYPE(seq_range) *wanted_uids)
{
	ARRAY_TYPE(seq_range) assigned_uids, unwanted_uids;
	struct seq_range_iter local_iter, wanted_iter;
	unsigned int local_n, wanted_n;
	uint32_t local_uid, wanted_uid;
	struct importer_new_mail *mail;
	struct dsync_mail dmail;

	if (array_count(local_uids) == 0)
		return FALSE;

	local_n = wanted_n = 0;
	seq_range_array_iter_init(&local_iter, local_uids);
	seq_range_array_iter_init(&wanted_iter, wanted_uids);

	/* wanted_uids contains UIDs that need to exist at the end. those that
	   don't already exist in local_uids have a higher UID than any
	   existing local UID */
	t_array_init(&assigned_uids, array_count(wanted_uids));
	t_array_init(&unwanted_uids, 8);
	while (seq_range_array_iter_nth(&local_iter, local_n++, &local_uid)) {
		if (seq_range_array_iter_nth(&wanted_iter, wanted_n,
					     &wanted_uid)) {
			if (local_uid == wanted_uid) {
				/* we have exactly the UID we want. keep it. */
				seq_range_array_add(&assigned_uids, wanted_uid);
				wanted_n++;
				continue;
			}
			i_assert(local_uid < wanted_uid);
		}
		/* we no longer want this local UID. */
		seq_range_array_add(&unwanted_uids, local_uid);
	}

	/* reuse as many existing messages as possible by changing their UIDs */
	while (seq_range_array_iter_nth(&wanted_iter, wanted_n, &wanted_uid)) {
		if (!dsync_mailbox_import_change_uid(importer, &unwanted_uids,
						     wanted_uid))
			break;
		seq_range_array_add(&assigned_uids, wanted_uid);
		wanted_n++;
	}

	/* expunge all unwanted messages */
	local_n = 0; seq_range_array_iter_init(&local_iter, &unwanted_uids);
	while (seq_range_array_iter_nth(&local_iter, local_n++, &local_uid)) {
		IMPORTER_DEBUG_CHANGE(importer);
		if (mail_set_uid(importer->mail, local_uid))
			mail_expunge(importer->mail);
	}

	/* mark mails whose UIDs we got to be skipped over later */
	for (mail = all_newmails; mail != NULL; mail = mail->next) {
		if (!mail->skip &&
		    seq_range_exists(&assigned_uids, mail->final_uid))
			mail->skip = TRUE;
	}

	if (!seq_range_array_iter_nth(&wanted_iter, wanted_n, &wanted_uid)) {
		/* we've assigned all wanted UIDs */
		return TRUE;
	}

	/* try to find one existing message that we can use to copy to the
	   other instances */
	local_n = 0; seq_range_array_iter_init(&local_iter, local_uids);
	while (seq_range_array_iter_nth(&local_iter, local_n++, &local_uid)) {
		if (dsync_mailbox_import_local_uid(importer, importer->mail,
						   local_uid, all_newmails->guid,
						   &dmail) > 0) {
			if (dsync_mailbox_save_newmails(importer, &dmail,
							all_newmails, FALSE))
				return TRUE;
		}
	}
	return FALSE;
}

static bool
dsync_mailbox_import_try_virtual_all(struct dsync_mailbox_importer *importer,
				     struct importer_new_mail *all_newmails)
{
	struct dsync_mail dmail;

	if (all_newmails->virtual_all_uid == 0)
		return FALSE;

	if (dsync_mailbox_import_local_uid(importer, importer->virtual_mail,
					   all_newmails->virtual_all_uid,
					   all_newmails->guid, &dmail) > 0) {
		if (dsync_mailbox_save_newmails(importer, &dmail,
						all_newmails, FALSE))
			return TRUE;
	}
	return FALSE;
}

static bool
dsync_mailbox_import_handle_mail(struct dsync_mailbox_importer *importer,
				 struct importer_new_mail *all_newmails)
{
	ARRAY_TYPE(seq_range) local_uids, wanted_uids;
	struct dsync_mail_request *request;
	struct importer_new_mail *mail;
	const char *request_guid = NULL;
	uint32_t request_uid = 0;

	i_assert(all_newmails != NULL);

	/* get the list of the current local UIDs and the wanted UIDs.
	   find the first remote instance that we can request in case there are
	   no local instances */
	t_array_init(&local_uids, 8);
	t_array_init(&wanted_uids, 8);
	for (mail = all_newmails; mail != NULL; mail = mail->next) {
		if (mail->uid_in_local)
			seq_range_array_add(&local_uids, mail->local_uid);
		else if (request_guid == NULL) {
			if (*mail->guid != '\0')
				request_guid = mail->guid;
			request_uid = mail->remote_uid;
			i_assert(request_uid != 0);
		}
		if (!mail->skip)
			seq_range_array_add(&wanted_uids, mail->final_uid);
	}
	i_assert(array_count(&wanted_uids) > 0);

	if (!dsync_mailbox_import_try_local(importer, all_newmails,
					    &local_uids, &wanted_uids) &&
	    !dsync_mailbox_import_try_virtual_all(importer, all_newmails)) {
		/* no local instance. request from remote */
		IMPORTER_DEBUG_CHANGE(importer);
		if (importer->want_mail_requests) {
			request = array_append_space(&importer->mail_requests);
			request->guid = request_guid;
			request->uid = request_uid;
		}
		return FALSE;
	}
	/* successfully handled all the mails locally */
	importer->import_pos++;
	return TRUE;
}

static void
dsync_mailbox_import_find_virtual_uids(struct dsync_mailbox_importer *importer)
{
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct importer_new_mail *newmail;
	struct mail *mail;
	const char *guid;

	if (mailbox_sync(importer->virtual_all_box, 0) < 0) {
		i_error("Couldn't sync \\All mailbox '%s': %s",
			mailbox_get_vname(importer->virtual_all_box),
			mailbox_get_last_internal_error(importer->virtual_all_box, NULL));
		return;
	}

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	importer->virtual_trans =
		mailbox_transaction_begin(importer->virtual_all_box,
					  importer->transaction_flags,
					  __func__);
	search_ctx = mailbox_search_init(importer->virtual_trans, search_args,
					 NULL, MAIL_FETCH_GUID, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) < 0) {
			/* ignore errors */
			continue;
		}
		newmail = hash_table_lookup(importer->import_guids, guid);
		if (newmail != NULL && newmail->virtual_all_uid == 0)
			newmail->virtual_all_uid = mail->uid;
	}
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Couldn't search \\All mailbox '%s': %s",
			mailbox_get_vname(importer->virtual_all_box),
			mailbox_get_last_internal_error(importer->virtual_all_box, NULL));
	}

	importer->virtual_mail = mail_alloc(importer->virtual_trans, 0, NULL);
}

static void
dsync_mailbox_import_handle_local_mails(struct dsync_mailbox_importer *importer)
{
	struct hash_iterate_context *iter;
	const char *key;
	void *key2;
	struct importer_new_mail *mail;

	if (importer->virtual_all_box != NULL &&
	    hash_table_count(importer->import_guids) > 0) {
		/* find UIDs in \All mailbox for all wanted GUIDs. */
		dsync_mailbox_import_find_virtual_uids(importer);
	}

	iter = hash_table_iterate_init(importer->import_guids);
	while (hash_table_iterate(iter, importer->import_guids, &key, &mail)) {
		T_BEGIN {
			if (dsync_mailbox_import_handle_mail(importer, mail))
				hash_table_remove(importer->import_guids, key);
		} T_END;
	}
	hash_table_iterate_deinit(&iter);

	iter = hash_table_iterate_init(importer->import_uids);
	while (hash_table_iterate(iter, importer->import_uids, &key2, &mail)) {
		T_BEGIN {
			if (dsync_mailbox_import_handle_mail(importer, mail))
				hash_table_remove(importer->import_uids, key2);
		} T_END;
	}
	hash_table_iterate_deinit(&iter);
}

int dsync_mailbox_import_changes_finish(struct dsync_mailbox_importer *importer)
{
	i_assert(!importer->new_uids_assigned);

	if (!importer->last_common_uid_found) {
		/* handle pending expunges and flag updates */
		dsync_mailbox_common_uid_found(importer);
	}
	/* skip common local mails */
	(void)importer_next_mail(importer, importer->last_common_uid+1);
	/* if there are any local mails left, add them to newmails list */
	while (importer->cur_mail != NULL && !importer->failed)
		(void)dsync_mailbox_try_save(importer, NULL);

	if (importer->search_ctx != NULL) {
		if (mailbox_search_deinit(&importer->search_ctx) < 0) {
			i_error("Mailbox %s: Search failed: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			importer->failed = TRUE;
		}
	}
	importer->import_count = hash_table_count(importer->import_guids) +
		hash_table_count(importer->import_uids);

	dsync_mailbox_import_assign_new_uids(importer);
	/* save mails from local sources where possible,
	   request the rest from remote */
	if (!importer->failed)
		dsync_mailbox_import_handle_local_mails(importer);
	return importer->failed ? -1 : 0;
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
		    changes[i][0] == KEYWORD_CHANGE_ADD_AND_FINAL) {
			const char *name = changes[i]+1;

			array_append(&keywords, &name, 1);
		}
	}
	if (array_count(&keywords) == 0)
		return NULL;

	array_append_zero(&keywords);
	return array_first(&keywords);
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

	if (change->modseq > 1) {
		(void)mailbox_enable(importer->box, MAILBOX_FEATURE_CONDSTORE);
		mailbox_save_set_min_modseq(save_ctx, change->modseq);
	}
	/* FIXME: if there already are private flags, they get lost because
	   saving can't handle updating private index. they get added on the
	   next sync though. if this is fixed here, set min_pvt_modseq also. */
}

static int
dsync_msg_try_copy(struct dsync_mailbox_importer *importer,
		   struct mail_save_context **save_ctx_p,
		   struct importer_new_mail **all_newmails_forcopy)
{
	struct importer_new_mail *inst;

	for (inst = *all_newmails_forcopy; inst != NULL; inst = inst->next) {
		if (inst->uid_in_local && !inst->copy_failed &&
		    mail_set_uid(importer->mail, inst->local_uid)) {
			if (mailbox_copy(save_ctx_p, importer->mail) < 0) {
				enum mail_error error;
				const char *errstr;

				errstr = mailbox_get_last_internal_error(importer->box, &error);
				if (error != MAIL_ERROR_EXPUNGED) {
					i_warning("Failed to copy mail from UID=%u: "
						  "%s - falling back to other means",
						 inst->local_uid, errstr);
				}
				inst->copy_failed = TRUE;
				return -1;
			}
			*all_newmails_forcopy = inst;
			return 1;
		}
	}
	*all_newmails_forcopy = NULL;
	return 0;
}

static void
dsync_mailbox_save_set_nonminimal(struct mail_save_context *save_ctx,
				  const struct dsync_mail *mail)
{
	if (mail->pop3_uidl != NULL && *mail->pop3_uidl != '\0')
		mailbox_save_set_pop3_uidl(save_ctx, mail->pop3_uidl);
	if (mail->pop3_order > 0)
		mailbox_save_set_pop3_order(save_ctx, mail->pop3_order);
	mailbox_save_set_received_date(save_ctx, mail->received_date, 0);
}

static struct mail_save_context *
dsync_mailbox_save_init(struct dsync_mailbox_importer *importer,
			const struct dsync_mail *mail,
			struct importer_new_mail *newmail)
{
	struct mail_save_context *save_ctx;

	save_ctx = mailbox_save_alloc(importer->ext_trans);
	mailbox_save_set_uid(save_ctx, newmail->final_uid);
	if (*mail->guid != '\0')
		mailbox_save_set_guid(save_ctx, mail->guid);
	if (mail->saved_date != 0)
		mailbox_save_set_save_date(save_ctx, mail->saved_date);
	dsync_mailbox_save_set_metadata(importer, save_ctx, newmail->change);

	if (!mail->minimal_fields)
		dsync_mailbox_save_set_nonminimal(save_ctx, mail);
	return save_ctx;
}

static bool
dsync_mailbox_save_body(struct dsync_mailbox_importer *importer,
			const struct dsync_mail *mail,
			struct importer_new_mail *newmail,
			struct importer_new_mail **all_newmails_forcopy,
			bool remote_mail)
{
	struct mail_save_context *save_ctx;
	struct istream *input;
	ssize_t ret;
	bool save_failed = FALSE;

	/* try to save the mail by copying an existing mail */
	save_ctx = dsync_mailbox_save_init(importer, mail, newmail);
	if ((ret = dsync_msg_try_copy(importer, &save_ctx, all_newmails_forcopy)) < 0) {
		if (save_ctx == NULL)
			save_ctx = dsync_mailbox_save_init(importer, mail, newmail);
	}
	if (ret <= 0 && mail->input_mail != NULL) {
		/* copy using the source mail */
		i_assert(mail->input_mail->uid == mail->input_mail_uid);
		if (mailbox_copy(&save_ctx, mail->input_mail) == 0)
			ret = 1;
		else {
			enum mail_error error;
			const char *errstr;

			errstr = mailbox_get_last_internal_error(importer->box, &error);
			if (error != MAIL_ERROR_EXPUNGED) {
				i_warning("Failed to copy source UID=%u mail: "
					  "%s - falling back to regular saving",
					  mail->input_mail->uid, errstr);
			}
			ret = -1;
			save_ctx = dsync_mailbox_save_init(importer, mail, newmail);
		}

	}
	if (ret > 0) {
		i_assert(save_ctx == NULL);
		dsync_mailbox_import_saved_newmail(importer, newmail);
		return TRUE;
	}
	/* fallback to saving from remote stream */
	if (!remote_mail) {
		/* the mail isn't remote yet. we were just trying to copy a
		   local mail to avoid downloading the remote mail. */
		mailbox_save_cancel(&save_ctx);
		return FALSE;
	}
	if (mail->minimal_fields) {
		struct dsync_mail mail2;
		const char *error_field;

		i_assert(mail->input_mail != NULL);

		if (dsync_mail_fill_nonminimal(mail->input_mail, &mail2,
					       &error_field) < 0) {
			i_error("Mailbox %s: Failed to read mail %s uid=%u: %s",
				mailbox_get_vname(importer->box),
				error_field, mail->uid,
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			importer->failed = TRUE;
			mailbox_save_cancel(&save_ctx);
			return TRUE;
		}
		dsync_mailbox_save_set_nonminimal(save_ctx, &mail2);
		input = mail2.input;
	} else {
		input = mail->input;
	}

	if (input == NULL) {
		/* it was just expunged in remote, skip it */
		mailbox_save_cancel(&save_ctx);
		return TRUE;
	}

	i_stream_seek(input, 0);
	if (mailbox_save_begin(&save_ctx, input) < 0) {
		i_error("Mailbox %s: Saving failed: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_internal_error(importer->box,
							&importer->mail_error));
		importer->failed = TRUE;
		return TRUE;
	}
	while ((ret = i_stream_read(input)) > 0 || ret == -2) {
		if (mailbox_save_continue(save_ctx) < 0) {
			save_failed = TRUE;
			ret = -1;
			break;
		}
	}
	i_assert(ret == -1);

	if (input->stream_errno != 0) {
		i_error("Mailbox %s: read(msg input) failed: %s",
			mailbox_get_vname(importer->box),
			i_stream_get_error(input));
		mailbox_save_cancel(&save_ctx);
		importer->mail_error = MAIL_ERROR_TEMP;
		importer->failed = TRUE;
	} else if (save_failed) {
		i_error("Mailbox %s: Saving failed: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_internal_error(importer->box,
							&importer->mail_error));
		mailbox_save_cancel(&save_ctx);
		importer->failed = TRUE;
	} else {
		i_assert(input->eof);
		if (mailbox_save_finish(&save_ctx) < 0) {
			i_error("Mailbox %s: Saving failed: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			importer->failed = TRUE;
		} else {
			dsync_mailbox_import_saved_newmail(importer, newmail);
		}
	}
	return TRUE;
}

static bool dsync_mailbox_save_newmails(struct dsync_mailbox_importer *importer,
					const struct dsync_mail *mail,
					struct importer_new_mail *all_newmails,
					bool remote_mail)
{
	struct importer_new_mail *newmail, *all_newmails_forcopy;
	bool ret = TRUE;

	/* if all_newmails list is large, avoid scanning through the
	   uninteresting ones for each newmail */
	all_newmails_forcopy = all_newmails;

	/* save all instances of the message */
	for (newmail = all_newmails; newmail != NULL && ret; newmail = newmail->next) {
		if (!newmail->skip) T_BEGIN {
			if (!dsync_mailbox_save_body(importer, mail, newmail,
						     &all_newmails_forcopy,
						     remote_mail))
				ret = FALSE;
		} T_END;
	}
	return ret;
}

int dsync_mailbox_import_mail(struct dsync_mailbox_importer *importer,
			      const struct dsync_mail *mail)
{
	struct importer_new_mail *all_newmails;

	i_assert(mail->input == NULL || mail->input->seekable);
	i_assert(importer->new_uids_assigned);

	if (importer->failed)
		return -1;
	if (importer->require_full_resync)
		return 0;

	imp_debug(importer, "Import mail body for GUID=%s UID=%u",
		  mail->guid, mail->uid);

	all_newmails = *mail->guid != '\0' ?
		hash_table_lookup(importer->import_guids, mail->guid) :
		hash_table_lookup(importer->import_uids, POINTER_CAST(mail->uid));
	if (all_newmails == NULL) {
		if (importer->want_mail_requests) {
			i_error("Mailbox %s: Remote sent unwanted message body for "
				"GUID=%s UID=%u",
				mailbox_get_vname(importer->box),
				mail->guid, mail->uid);
		} else {
			imp_debug(importer, "Skip unwanted mail body for "
				  "GUID=%s UID=%u", mail->guid, mail->uid);
		}
		return 0;
	}
	if (*mail->guid != '\0')
		hash_table_remove(importer->import_guids, mail->guid);
	else {
		hash_table_remove(importer->import_uids,
				  POINTER_CAST(mail->uid));
	}
	importer->import_pos++;
	if (!dsync_mailbox_save_newmails(importer, mail, all_newmails, TRUE))
		i_unreached();
	return importer->failed ? -1 : 0;
}

static int
reassign_uids_in_seq_range(struct dsync_mailbox_importer *importer,
			   const ARRAY_TYPE(seq_range) *unwanted_uids)
{
	struct mailbox *box = importer->box;
	const enum mailbox_transaction_flags trans_flags =
		importer->transaction_flags |
		MAILBOX_TRANSACTION_FLAG_EXTERNAL |
		MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	struct mail_search_context *search_ctx;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	unsigned int renumber_count = 0;
	int ret = 1;

	if (array_count(unwanted_uids) == 0)
		return 1;

	if (importer->debug) T_BEGIN {
		string_t *str = t_str_new(256);
		imap_write_seq_range(str, unwanted_uids);
		imp_debug(importer, "Reassign UIDs: %s", str_c(str));
	} T_END;

	search_args = mail_search_build_init();
	arg = mail_search_build_add(search_args, SEARCH_UIDSET);
	p_array_init(&arg->value.seqset, search_args->pool,
		     array_count(unwanted_uids));
	array_append_array(&arg->value.seqset, unwanted_uids);

	trans = mailbox_transaction_begin(box, trans_flags, __func__);
	search_ctx = mailbox_search_init(trans, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(search_ctx, &mail)) {
		save_ctx = mailbox_save_alloc(trans);
		mailbox_save_copy_flags(save_ctx, mail);
		if (mailbox_move(&save_ctx, mail) < 0) {
			i_error("Mailbox %s: Couldn't move mail within mailbox: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, &importer->mail_error));
			ret = -1;
		} else if (ret > 0) {
			ret = 0;
		}
		renumber_count++;
	}
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Mailbox %s: mail search failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &importer->mail_error));
		ret = -1;
	}

	if (mailbox_transaction_commit(&trans) < 0) {
		i_error("Mailbox %s: UID reassign commit failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, &importer->mail_error));
		ret = -1;
	}
	if (ret == 0) {
		imp_debug(importer, "Mailbox %s: Change during sync: "
			  "Renumbered %u of %u unwanted UIDs",
			  mailbox_get_vname(box),
			  renumber_count, array_count(unwanted_uids));
	}
	return ret;
}

static int
reassign_unwanted_uids(struct dsync_mailbox_importer *importer,
		       const char **changes_during_sync_r)
{
	ARRAY_TYPE(seq_range) unwanted_uids;
	const uint32_t *wanted_uids, *saved_uids;
	uint32_t highest_seen_uid;
	unsigned int i, wanted_count, saved_count;
	int ret = 0;

	wanted_uids = array_get(&importer->wanted_uids, &wanted_count);
	saved_uids = array_get(&importer->saved_uids, &saved_count);
	i_assert(wanted_count == saved_count);
	if (wanted_count == 0)
		return 0;
	/* wanted_uids contains the UIDs we tried to save mails with.
	   if nothing changed during dsync, we should have the expected UIDs
	   (saved_uids) and all is well.

	   if any new messages got inserted during dsync, we'll need to fix up
	   the UIDs and let the next dsync fix up the other side. for example:

	   remote uids = 5,7,9 = wanted_uids
	   remote uidnext = 12
	   locally added new uid=5 ->
	   saved_uids = 10,7,9

	   we'll now need to reassign UIDs 5 and 10. to be fully future-proof
	   we'll reassign all UIDs between [original local uidnext .. highest
	   UID we think we know] that aren't in saved_uids. */

	/* create uidset for the list of UIDs we don't want to exist */
	t_array_init(&unwanted_uids, 8);
	highest_seen_uid = I_MAX(importer->remote_uid_next-1,
				 importer->highest_wanted_uid);
	i_assert(importer->local_uid_next <= highest_seen_uid);
	seq_range_array_add_range(&unwanted_uids,
				  importer->local_uid_next, highest_seen_uid);
	for (i = 0; i < wanted_count; i++) {
		i_assert(i < wanted_count);
		if (saved_uids[i] == wanted_uids[i])
			seq_range_array_remove(&unwanted_uids, saved_uids[i]);
	}

	ret = reassign_uids_in_seq_range(importer, &unwanted_uids);
	if (ret == 0) {
		*changes_during_sync_r = t_strdup_printf(
			"%u UIDs changed due to UID conflicts",
			seq_range_count(&unwanted_uids));
		/* conflicting changes during sync, revert our last-common-uid
		   back to a safe value. */
		importer->last_common_uid = importer->local_uid_next - 1;
	}
	return ret < 0 ? -1 : 0;
}

static int
dsync_mailbox_import_commit(struct dsync_mailbox_importer *importer, bool final)
{
	struct mail_transaction_commit_changes changes;
	struct seq_range_iter iter;
	uint32_t uid;
	unsigned int n;
	int ret = importer->failed ? -1 : 0;

	mail_free(&importer->mail);
	mail_free(&importer->ext_mail);

	/* commit saves */
	if (mailbox_transaction_commit_get_changes(&importer->ext_trans,
						   &changes) < 0) {
		i_error("Mailbox %s: Save commit failed: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_internal_error(importer->box, &importer->mail_error));
		/* removed wanted_uids that weren't actually saved */
		array_delete(&importer->wanted_uids,
			     array_count(&importer->saved_uids),
			     array_count(&importer->wanted_uids) -
			     array_count(&importer->saved_uids));
		mailbox_transaction_rollback(&importer->trans);
		ret = -1;
	} else {
		/* remember the UIDs that were successfully saved */
		if (importer->debug) T_BEGIN {
			string_t *str = t_str_new(256);
			imap_write_seq_range(str, &changes.saved_uids);
			imp_debug(importer, "Saved UIDs: %s", str_c(str));
		} T_END;
		seq_range_array_iter_init(&iter, &changes.saved_uids); n = 0;
		while (seq_range_array_iter_nth(&iter, n++, &uid))
			array_append(&importer->saved_uids, &uid, 1);
		pool_unref(&changes.pool);

		/* commit flag changes and expunges */
		if (mailbox_transaction_commit(&importer->trans) < 0) {
			i_error("Mailbox %s: Commit failed: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			ret = -1;
		}
	}

	if (!final)
		dsync_mailbox_import_transaction_begin(importer);
	return ret;
}

static int dsync_mailbox_import_finish(struct dsync_mailbox_importer *importer,
				       const char **changes_during_sync_r)
{
	struct mailbox_update update;
	int ret;

	ret = dsync_mailbox_import_commit(importer, TRUE);

	if (ret == 0) {
		/* update mailbox metadata if we successfully saved
		   everything. */
		i_zero(&update);
		update.min_next_uid = importer->remote_uid_next;
		update.min_first_recent_uid =
			I_MIN(importer->last_common_uid+1,
			      importer->remote_first_recent_uid);
		update.min_highest_modseq = importer->remote_highest_modseq;
		update.min_highest_pvt_modseq = importer->remote_highest_pvt_modseq;

		imp_debug(importer, "Finish update: min_next_uid=%u "
			  "min_first_recent_uid=%u min_highest_modseq=%"PRIu64" "
			  "min_highest_pvt_modseq=%"PRIu64,
			  update.min_next_uid, update.min_first_recent_uid,
			  update.min_highest_modseq,
			  update.min_highest_pvt_modseq);

		if (mailbox_update(importer->box, &update) < 0) {
			i_error("Mailbox %s: Update failed: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			ret = -1;
		}
	}

	/* sync mailbox to finish flag changes and expunges. */
	if (mailbox_sync(importer->box, 0) < 0) {
		i_error("Mailbox %s: Sync failed: %s",
			mailbox_get_vname(importer->box),
			mailbox_get_last_internal_error(importer->box,
							&importer->mail_error));
		ret = -1;
	}
	if (ret == 0) {
		/* give new UIDs to messages that got saved with unwanted UIDs.
		   do it only if the whole transaction succeeded. */
		if (reassign_unwanted_uids(importer, changes_during_sync_r) < 0)
			ret = -1;
	}
	return ret;
}

static void
dsync_mailbox_import_check_missing_guid_imports(struct dsync_mailbox_importer *importer)
{
	struct hash_iterate_context *iter;
	const char *key;
	struct importer_new_mail *mail;

	iter = hash_table_iterate_init(importer->import_guids);
	while (hash_table_iterate(iter, importer->import_guids, &key, &mail)) {
		for (; mail != NULL; mail = mail->next) {
			if (mail->skip)
				continue;

			i_error("Mailbox %s: Remote didn't send mail GUID=%s (UID=%u)",
				mailbox_get_vname(importer->box),
				mail->guid, mail->remote_uid);
			importer->mail_error = MAIL_ERROR_TEMP;
			importer->failed = TRUE;
		}
	}
	hash_table_iterate_deinit(&iter);
}

static void
dsync_mailbox_import_check_missing_uid_imports(struct dsync_mailbox_importer *importer)
{
	struct hash_iterate_context *iter;
	void *key;
	struct importer_new_mail *mail;

	iter = hash_table_iterate_init(importer->import_uids);
	while (hash_table_iterate(iter, importer->import_uids, &key, &mail)) {
		for (; mail != NULL; mail = mail->next) {
			if (mail->skip)
				continue;

			i_error("Mailbox %s: Remote didn't send mail UID=%u",
				mailbox_get_vname(importer->box),
				mail->remote_uid);
			importer->mail_error = MAIL_ERROR_TEMP;
			importer->failed = TRUE;
		}
	}
	hash_table_iterate_deinit(&iter);
}

int dsync_mailbox_import_deinit(struct dsync_mailbox_importer **_importer,
				bool success,
				uint32_t *last_common_uid_r,
				uint64_t *last_common_modseq_r,
				uint64_t *last_common_pvt_modseq_r,
				uint32_t *last_messages_count_r,
				const char **changes_during_sync_r,
				bool *require_full_resync_r,
				enum mail_error *error_r)
{
	struct dsync_mailbox_importer *importer = *_importer;
	struct mailbox_status status;
	int ret;

	*_importer = NULL;
	*changes_during_sync_r = NULL;
	*require_full_resync_r = importer->require_full_resync;

	if ((!success || importer->require_full_resync) && !importer->failed) {
		importer->mail_error = MAIL_ERROR_TEMP;
		importer->failed = TRUE;
	}

	if (!importer->new_uids_assigned && !importer->failed)
		dsync_mailbox_import_assign_new_uids(importer);

	if (!importer->failed) {
		dsync_mailbox_import_check_missing_guid_imports(importer);
		dsync_mailbox_import_check_missing_uid_imports(importer);
	}

	if (importer->search_ctx != NULL) {
		if (mailbox_search_deinit(&importer->search_ctx) < 0) {
			i_error("Mailbox %s: Search failed: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			importer->failed = TRUE;
		}
	}
	if (dsync_mailbox_import_finish(importer, changes_during_sync_r) < 0)
		importer->failed = TRUE;

	if (importer->virtual_mail != NULL)
		mail_free(&importer->virtual_mail);
	if (importer->virtual_trans != NULL)
		(void)mailbox_transaction_commit(&importer->virtual_trans);

	hash_table_destroy(&importer->import_guids);
	hash_table_destroy(&importer->import_uids);
	array_free(&importer->maybe_expunge_uids);
	array_free(&importer->maybe_saves);
	array_free(&importer->wanted_uids);
	array_free(&importer->saved_uids);
	array_free(&importer->newmails);
	if (array_is_created(&importer->mail_requests))
		array_free(&importer->mail_requests);

	*last_common_uid_r = importer->last_common_uid;
	if (*changes_during_sync_r == NULL) {
		*last_common_modseq_r = importer->remote_highest_modseq;
		*last_common_pvt_modseq_r = importer->remote_highest_pvt_modseq;
	} else {
		/* local changes occurred during dsync. we exported changes up
		   to local_initial_highestmodseq, so all of the changes have
		   happened after it. we want the next run to see those changes,
		   so return it as the last common modseq */
		*last_common_modseq_r = importer->local_initial_highestmodseq;
		*last_common_pvt_modseq_r = importer->local_initial_highestpvtmodseq;
	}
	if (importer->delete_mailbox) {
		if (mailbox_delete(importer->box) < 0) {
			i_error("Couldn't delete mailbox %s: %s",
				mailbox_get_vname(importer->box),
				mailbox_get_last_internal_error(importer->box,
								&importer->mail_error));
			importer->failed = TRUE;
		}
		*last_messages_count_r = 0;
	} else {
		mailbox_get_open_status(importer->box, STATUS_MESSAGES, &status);
		*last_messages_count_r = status.messages;
	}

	i_assert(importer->failed == (importer->mail_error != 0));
	ret = importer->failed ? -1 : 0;
	*error_r = importer->mail_error;
	pool_unref(&importer->pool);
	return ret;
}

const char *dsync_mailbox_import_get_proctitle(struct dsync_mailbox_importer *importer)
{
	if (importer->search_ctx != NULL)
		return "";
	return t_strdup_printf("%u/%u", importer->import_pos,
			       importer->import_count);
}
