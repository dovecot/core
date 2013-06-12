/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-header-filter.h"
#include "sha1.h"
#include "message-size.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "pop3-migration-plugin.h"

#define POP3_MIGRATION_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_migration_storage_module)
#define POP3_MIGRATION_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_migration_mail_module)

struct pop3_uidl_map {
	uint32_t pop3_seq;
	uint32_t imap_uid;

	/* UIDL */
	const char *pop3_uidl;
	/* LIST size */
	uoff_t size;
	/* sha1(TOP 0) - set only when needed */
	unsigned char hdr_sha1[SHA1_RESULTLEN];
	unsigned int hdr_sha1_set:1;
};

struct imap_msg_map {
	uint32_t uid, pop3_seq;
	uoff_t psize;
	const char *pop3_uidl;

	/* sha1(header) - set only when needed */
	unsigned char hdr_sha1[SHA1_RESULTLEN];
	unsigned int hdr_sha1_set:1;
};

struct pop3_migration_mail_storage {
	union mail_storage_module_context module_ctx;

	const char *pop3_box_vname;
	ARRAY(struct pop3_uidl_map) pop3_uidl_map;

	unsigned int all_mailboxes:1;
	unsigned int pop3_all_hdr_sha1_set:1;
};

struct pop3_migration_mailbox {
	union mailbox_module_context module_ctx;

	ARRAY(struct imap_msg_map) imap_msg_map;
	unsigned int first_unfound_idx;

	unsigned int uidl_synced:1;
	unsigned int uidl_sync_failed:1;
	unsigned int uidl_ordered:1;
};

static const char *hdr_hash_skip_headers[] = {
	"Content-Length",
	"Status",
	"X-IMAP",
	"X-IMAPbase",
	"X-Keywords",
	"X-Message-Flag",
	"X-Status",
	"X-UID",
	"X-UIDL"
};
const char *pop3_migration_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(pop3_migration_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(pop3_migration_mail_module,
				  &mail_module_register);

static int imap_msg_map_uid_cmp(const struct imap_msg_map *map1,
				const struct imap_msg_map *map2)
{
	if (map1->uid < map2->uid)
		return -1;
	if (map1->uid > map2->uid)
		return 1;
	return 0;
}

static int pop3_uidl_map_pop3_seq_cmp(const struct pop3_uidl_map *map1,
				      const struct pop3_uidl_map *map2)
{
	if (map1->pop3_seq < map2->pop3_seq)
		return -1;
	if (map1->pop3_seq > map2->pop3_seq)
		return 1;
	return 0;
}

static int pop3_uidl_map_hdr_cmp(const struct pop3_uidl_map *map1,
				 const struct pop3_uidl_map *map2)
{
	return memcmp(map1->hdr_sha1, map2->hdr_sha1, sizeof(map1->hdr_sha1));
}

static int imap_msg_map_hdr_cmp(const struct imap_msg_map *map1,
				const struct imap_msg_map *map2)
{
	return memcmp(map1->hdr_sha1, map2->hdr_sha1, sizeof(map1->hdr_sha1));
}

static int get_hdr_sha1(struct mail *mail, unsigned char sha1[SHA1_RESULTLEN])
{
	struct message_size hdr_size;
	struct istream *input, *input2;
	const unsigned char *data;
	size_t size;
	struct sha1_ctxt sha1_ctx;

	if (mail_get_hdr_stream(mail, &hdr_size, &input) < 0) {
		i_error("pop3_migration: Failed to get header for msg %u: %s",
			mail->seq, mailbox_get_last_error(mail->box, NULL));
		return -1;
	}
	input2 = i_stream_create_limit(input, hdr_size.physical_size);
	/* hide headers that might change or be different in IMAP vs. POP3 */
	input = i_stream_create_header_filter(input2,
				HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
				hdr_hash_skip_headers,
				N_ELEMENTS(hdr_hash_skip_headers),
				*null_header_filter_callback, (void *)NULL);
	i_stream_unref(&input2);

	sha1_init(&sha1_ctx);
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		sha1_loop(&sha1_ctx, data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0) {
		i_error("pop3_migration: Failed to read header for msg %u: %m",
			mail->seq);
		i_stream_unref(&input);
		return -1;
	}
	sha1_result(&sha1_ctx, sha1);
	i_stream_unref(&input);
	return 0;
}

static struct mailbox *pop3_mailbox_alloc(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(storage);
	struct mail_namespace *ns;

	ns = mail_namespace_find(storage->user->namespaces,
				 mstorage->pop3_box_vname);
	i_assert(ns != NULL);
	return mailbox_alloc(ns->list, mstorage->pop3_box_vname,
			     MAILBOX_FLAG_READONLY | MAILBOX_FLAG_POP3_SESSION);
}

static int pop3_map_read(struct mail_storage *storage, struct mailbox *pop3_box)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(storage);
	struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct pop3_uidl_map *map;
	const char *uidl;
	uoff_t size;
	int ret = 0;

	if (array_is_created(&mstorage->pop3_uidl_map)) {
		/* already read these, just reset the imap_uids */
		array_foreach_modifiable(&mstorage->pop3_uidl_map, map)
			map->imap_uid = 0;
		return 0;
	}
	i_array_init(&mstorage->pop3_uidl_map, 128);

	if (mailbox_sync(pop3_box, 0) < 0) {
		i_error("pop3_migration: Couldn't sync mailbox %s: %s",
			pop3_box->vname, mailbox_get_last_error(pop3_box, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(pop3_box, 0);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL,
				  MAIL_FETCH_VIRTUAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		if (mail_get_virtual_size(mail, &size) < 0) {
			i_error("pop3_migration: Failed to get size for msg %u: %s",
				mail->seq,
				mailbox_get_last_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		if (mail_get_special(mail, MAIL_FETCH_UIDL_BACKEND, &uidl) < 0) {
			i_error("pop3_migration: Failed to get UIDL for msg %u: %s",
				mail->seq,
				mailbox_get_last_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		if (*uidl == '\0') {
			i_warning("pop3_migration: UIDL for msg %u is empty",
				  mail->seq);
			continue;
		}

		map = array_append_space(&mstorage->pop3_uidl_map);
		map->pop3_seq = mail->seq;
		map->pop3_uidl = p_strdup(storage->pool, uidl);
		map->size = size;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static int
pop3_map_read_hdr_hashes(struct mail_storage *storage, struct mailbox *pop3_box,
			 unsigned first_seq)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(storage);
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct pop3_uidl_map *map;
	int ret = 0;

	if (mstorage->pop3_all_hdr_sha1_set)
		return 0;
	if (mstorage->all_mailboxes) {
		/* we may be matching against multiple mailboxes.
		   read all the hashes only once. */
		first_seq = 1;
	}

	t = mailbox_transaction_begin(pop3_box, 0);
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, first_seq,
				     array_count(&mstorage->pop3_uidl_map)+1);
	ctx = mailbox_search_init(t, search_args, NULL,
				  MAIL_FETCH_STREAM_HEADER, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		map = array_idx_modifiable(&mstorage->pop3_uidl_map,
					   mail->seq-1);

		if (get_hdr_sha1(mail, map->hdr_sha1) < 0)
			ret = -1;
		else
			map->hdr_sha1_set = TRUE;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	(void)mailbox_transaction_commit(&t);
	if (ret == 0 && first_seq == 1)
		mstorage->pop3_all_hdr_sha1_set = TRUE;
	return ret;
}

static int imap_map_read(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(box);
	struct mailbox_status status;
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct imap_msg_map *map;
	uoff_t psize;
	int ret = 0;

	mailbox_get_open_status(box, STATUS_MESSAGES, &status);

	i_assert(!array_is_created(&mbox->imap_msg_map));
	p_array_init(&mbox->imap_msg_map, box->pool, status.messages);

	t = mailbox_transaction_begin(box, 0);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL,
				  MAIL_FETCH_PHYSICAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		if (mail_get_physical_size(mail, &psize) < 0) {
			i_error("pop3_migration: Failed to get psize for imap uid %u: %s",
				mail->uid,
				mailbox_get_last_error(box, NULL));
			ret = -1;
			break;
		}

		map = array_append_space(&mbox->imap_msg_map);
		map->uid = mail->uid;
		map->psize = psize;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static int imap_map_read_hdr_hashes(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(box);
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct imap_msg_map *map;
	int ret = 0;

	t = mailbox_transaction_begin(box, 0);
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, mbox->first_unfound_idx+1,
				     array_count(&mbox->imap_msg_map)+1);
	ctx = mailbox_search_init(t, search_args, NULL,
				  MAIL_FETCH_STREAM_HEADER, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		map = array_idx_modifiable(&mbox->imap_msg_map, mail->seq-1);

		if (get_hdr_sha1(mail, map->hdr_sha1) < 0)
			ret = -1;
		else
			map->hdr_sha1_set = TRUE;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static bool pop3_uidl_assign_by_size(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(box->storage);
	struct pop3_uidl_map *pop3_map;
	struct imap_msg_map *imap_map;
	unsigned int i, pop3_count, imap_count, count;

	pop3_map = array_get_modifiable(&mstorage->pop3_uidl_map, &pop3_count);
	imap_map = array_get_modifiable(&mbox->imap_msg_map, &imap_count);
	count = I_MIN(pop3_count, imap_count);

	/* see if we can match the messages using sizes */
	for (i = 0; i < count; i++) {
		if (pop3_map[i].size != imap_map[i].psize)
			break;
		if (i+1 < count && pop3_map[i].size == pop3_map[i+1].size) {
			/* two messages with same size, don't trust them */
			break;
		}

		pop3_map[i].imap_uid = imap_map[i].uid;
		imap_map[i].pop3_uidl = pop3_map[i].pop3_uidl;
		imap_map[i].pop3_seq = pop3_map[i].pop3_seq;
	}
	mbox->first_unfound_idx = i;
	return i == count;
}

static int
pop3_uidl_assign_by_hdr_hash(struct mailbox *box, struct mailbox *pop3_box)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(box->storage);
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(box);
	struct pop3_uidl_map *pop3_map;
	struct imap_msg_map *imap_map;
	unsigned int pop3_idx, imap_idx, pop3_count, imap_count;
	unsigned int first_seq, missing_uids_count;
	int ret;

	first_seq = mbox->first_unfound_idx+1;
	if (pop3_map_read_hdr_hashes(box->storage, pop3_box, first_seq) < 0 ||
	    imap_map_read_hdr_hashes(box) < 0)
		return -1;

	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_hdr_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_hdr_cmp);

	pop3_map = array_get_modifiable(&mstorage->pop3_uidl_map, &pop3_count);
	imap_map = array_get_modifiable(&mbox->imap_msg_map, &imap_count);

	pop3_idx = imap_idx = 0;
	while (pop3_idx < pop3_count && imap_idx < imap_count) {
		if (!pop3_map[pop3_idx].hdr_sha1_set ||
		    pop3_map[pop3_idx].imap_uid != 0) {
			pop3_idx++;
			continue;
		}
		if (!imap_map[imap_idx].hdr_sha1_set ||
		    imap_map[imap_idx].pop3_uidl != NULL) {
			imap_idx++;
			continue;
		}
		ret = memcmp(pop3_map[pop3_idx].hdr_sha1,
			     imap_map[imap_idx].hdr_sha1,
			     sizeof(pop3_map[pop3_idx].hdr_sha1));
		if (ret < 0)
			pop3_idx++;
		else if (ret > 0)
			imap_idx++;
		else {
			pop3_map[pop3_idx].imap_uid = imap_map[imap_idx].uid;
			imap_map[imap_idx].pop3_uidl =
				pop3_map[pop3_idx].pop3_uidl;
			imap_map[imap_idx].pop3_seq =
				pop3_map[pop3_idx].pop3_seq;
		}
	}
	missing_uids_count = 0;
	for (pop3_idx = 0; pop3_idx < pop3_count; pop3_idx++) {
		if (pop3_map[pop3_idx].imap_uid == 0)
			missing_uids_count++;
	}
	if (missing_uids_count > 0 && !mstorage->all_mailboxes) {
		i_warning("pop3_migration: %u POP3 messages have no "
			  "matching IMAP messages", missing_uids_count);
	}
	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_pop3_seq_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_uid_cmp);
	return 0;
}

static int pop3_migration_uidl_sync(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(box->storage);
	struct mailbox *pop3_box;
	const struct pop3_uidl_map *pop3_map;
	unsigned int i, count;
	uint32_t prev_uid;

	if (mbox->uidl_synced)
		return 0;

	pop3_box = pop3_mailbox_alloc(box->storage);
	/* the POP3 server isn't connected to yet. handle all IMAP traffic
	   first before connecting, so POP3 server won't disconnect us due to
	   idling. */
	if (imap_map_read(box) < 0 ||
	    pop3_map_read(box->storage, pop3_box) < 0) {
		mailbox_free(&pop3_box);
		return -1;
	}

	if (!pop3_uidl_assign_by_size(box)) {
		/* everything wasn't assigned, figure out the rest with
		   header hashes */
		if (pop3_uidl_assign_by_hdr_hash(box, pop3_box) < 0) {
			mailbox_free(&pop3_box);
			return -1;
		}
	}

	/* see if the POP3 UIDL order is the same as IMAP UID order */
	mbox->uidl_ordered = TRUE;
	pop3_map = array_get(&mstorage->pop3_uidl_map, &count);
	prev_uid = 0;
	for (i = 0; i < count; i++) {
		if (pop3_map[i].imap_uid == 0)
			continue;

		if (prev_uid > pop3_map[i].imap_uid) {
			mbox->uidl_ordered = FALSE;
			break;
		}
		prev_uid = pop3_map[i].imap_uid;
	}

	mbox->uidl_synced = TRUE;
	mailbox_free(&pop3_box);
	return 0;
}

static int
pop3_migration_get_special(struct mail *_mail, enum mail_fetch_field field,
			   const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *mmail = POP3_MIGRATION_MAIL_CONTEXT(mail);
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT(_mail->box);
	struct imap_msg_map map_key, *map;

	if (field == MAIL_FETCH_UIDL_BACKEND ||
	    field == MAIL_FETCH_POP3_ORDER) {
		if (mbox->uidl_sync_failed ||
		    pop3_migration_uidl_sync(_mail->box) < 0) {
			mbox->uidl_sync_failed = TRUE;
			mail_storage_set_error(_mail->box->storage,
					       MAIL_ERROR_TEMP,
					       "POP3 UIDLs couldn't be synced");
			return -1;
		}

		memset(&map_key, 0, sizeof(map_key));
		map_key.uid = _mail->uid;
		map = array_bsearch(&mbox->imap_msg_map, &map_key,
				    imap_msg_map_uid_cmp);
		if (map != NULL && map->pop3_uidl != NULL) {
			if (field == MAIL_FETCH_UIDL_BACKEND)
				*value_r = map->pop3_uidl;
			else
				*value_r = t_strdup_printf("%u", map->pop3_seq);
			return 0;
		}
		/* not found from POP3 server, fallback to default */
	}
	return mmail->super.get_special(_mail, field, value_r);
}

static void pop3_migration_mail_allocated(struct mail *_mail)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(_mail->box->storage);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;
	struct mail_namespace *ns;

	if (mstorage == NULL ||
	    (!mstorage->all_mailboxes && !_mail->box->inbox_user)) {
		/* assigns UIDLs only for INBOX */
		return;
	}

	ns = mail_namespace_find(_mail->box->storage->user->namespaces,
				 mstorage->pop3_box_vname);
	if (ns == mailbox_get_namespace(_mail->box)) {
		/* we're accessing the pop3-migration namespace itself */
		return;
	}

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->get_special = pop3_migration_get_special;
	MODULE_CONTEXT_SET_SELF(mail, pop3_migration_mail_module, mmail);
}

static void pop3_migration_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct pop3_migration_mailbox *mbox;

	mbox = p_new(box->pool, struct pop3_migration_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;

	MODULE_CONTEXT_SET(box, pop3_migration_storage_module, mbox);
}

static void pop3_migration_mail_storage_destroy(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(storage);

	if (array_is_created(&mstorage->pop3_uidl_map))
		array_free(&mstorage->pop3_uidl_map);

	mstorage->module_ctx.super.destroy(storage);
}

static void pop3_migration_mail_storage_created(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;
	const char *pop3_box_vname;

	pop3_box_vname = mail_user_plugin_getenv(storage->user,
						 "pop3_migration_mailbox");
	if (pop3_box_vname == NULL)
		return;

	mstorage = p_new(storage->pool, struct pop3_migration_mail_storage, 1);
	mstorage->module_ctx.super = *v;
	storage->vlast = &mstorage->module_ctx.super;
	v->destroy = pop3_migration_mail_storage_destroy;

	mstorage->pop3_box_vname = p_strdup(storage->pool, pop3_box_vname);
	mstorage->all_mailboxes =
		mail_user_plugin_getenv(storage->user,
					"pop3_migration_all_mailboxes") != NULL;

	MODULE_CONTEXT_SET(storage, pop3_migration_storage_module, mstorage);
}

static struct mail_storage_hooks pop3_migration_mail_storage_hooks = {
	.mail_allocated = pop3_migration_mail_allocated,
	.mailbox_allocated = pop3_migration_mailbox_allocated,
	.mail_storage_created = pop3_migration_mail_storage_created
};

void pop3_migration_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &pop3_migration_mail_storage_hooks);
}

void pop3_migration_plugin_deinit(void)
{
	mail_storage_hooks_remove(&pop3_migration_mail_storage_hooks);
}
