/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "hex-binary.h"
#include "network.h"
#include "istream.h"
#include "settings-parser.h"
#include "mailbox-log.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "dsync-worker-private.h"

#include <ctype.h>

struct local_dsync_worker_mailbox_iter {
	struct dsync_worker_mailbox_iter iter;
	pool_t ret_pool;
	struct mailbox_list_iterate_context *list_iter;
	struct hash_iterate_context *deleted_iter;
	struct hash_iterate_context *deleted_dir_iter;
};

struct local_dsync_worker_subs_iter {
	struct dsync_worker_subs_iter iter;
	struct mailbox_list_iterate_context *list_iter;
	struct hash_iterate_context *deleted_iter;
};

struct local_dsync_worker_msg_iter {
	struct dsync_worker_msg_iter iter;
	mailbox_guid_t *mailboxes;
	unsigned int mailbox_idx, mailbox_count;

	struct mail_search_context *search_ctx;
	struct mail *mail;

	string_t *tmp_guid_str;
	ARRAY_TYPE(mailbox_expunge_rec) expunges;
	unsigned int expunge_idx;
	unsigned int expunges_set:1;
};

struct local_dsync_mailbox {
	struct mail_namespace *ns;
	mailbox_guid_t guid;
	const char *storage_name;
	bool deleted;
};

struct local_dsync_mailbox_change {
	mailbox_guid_t guid;
	time_t last_delete;

	unsigned int deleted_mailbox:1;
};

struct local_dsync_dir_change {
	mailbox_guid_t name_sha1;
	struct mailbox_list *list;

	time_t last_rename;
	time_t last_delete;
	time_t last_subs_change;

	unsigned int unsubscribed:1;
	unsigned int deleted_dir:1;
};

struct local_dsync_worker_msg_get {
	mailbox_guid_t mailbox;
	uint32_t uid;
	dsync_worker_msg_callback_t *callback;
	void *context;
};

struct local_dsync_worker {
	struct dsync_worker worker;
	struct mail_user *user;

	pool_t pool;
	/* mailbox_guid_t -> struct local_dsync_mailbox* */
	struct hash_table *mailbox_hash;
	/* mailbox_guid_t -> struct local_dsync_mailbox_change* */
	struct hash_table *mailbox_changes_hash;
	/* <-> struct local_dsync_dir_change */
	struct hash_table *dir_changes_hash;

	char alt_char;
	ARRAY_DEFINE(subs_namespaces, struct mail_namespace *);

	mailbox_guid_t selected_box_guid;
	struct mailbox *selected_box;
	struct mail *mail, *ext_mail;

	ARRAY_TYPE(uint32_t) saved_uids;

	mailbox_guid_t get_mailbox;
	struct mail *get_mail;
	ARRAY_DEFINE(msg_get_queue, struct local_dsync_worker_msg_get);

	struct io *save_io;
	struct mail_save_context *save_ctx;
	struct istream *save_input;
	dsync_worker_save_callback_t *save_callback;
	void *save_context;

	dsync_worker_finish_callback_t *finish_callback;
	void *finish_context;

	unsigned int reading_mail:1;
	unsigned int finishing:1;
	unsigned int finished:1;
};

extern struct dsync_worker_vfuncs local_dsync_worker;

static void local_worker_mailbox_close(struct local_dsync_worker *worker);
static void local_worker_msg_box_close(struct local_dsync_worker *worker);
static void
local_worker_msg_get_next(struct local_dsync_worker *worker,
			  const struct local_dsync_worker_msg_get *get);

static int mailbox_guid_cmp(const void *p1, const void *p2)
{
	const mailbox_guid_t *g1 = p1, *g2 = p2;

	return memcmp(g1->guid, g2->guid, sizeof(g1->guid));
}

static unsigned int mailbox_guid_hash(const void *p)
{
	const mailbox_guid_t *guid = p;
        const uint8_t *s = guid->guid;
	unsigned int i, g, h = 0;

	for (i = 0; i < sizeof(guid->guid); i++) {
		h = (h << 4) + s[i];
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}
	return h;
}

static struct mail_namespace *
namespace_find_set(struct mail_user *user,
		   const struct mail_namespace_settings *set)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		/* compare settings pointers so that it'll work
		   for shared namespaces */
		if (ns->set == set)
			return ns;
	}
	return NULL;
}

static void dsync_drop_extra_namespaces(struct local_dsync_worker *worker)
{
	struct mail_user *user = worker->user;
	struct mail_namespace_settings *const *ns_unset, *const *ns_set;
	struct mail_namespace *ns;
	unsigned int i, count, count2;

	if (!array_is_created(&user->unexpanded_set->namespaces))
		return;

	/* drop all namespaces that have a location defined internally */
	ns_unset = array_get(&user->unexpanded_set->namespaces, &count);
	ns_set = array_get(&user->set->namespaces, &count2);
	i_assert(count == count2);
	for (i = 0; i < count; i++) {
		if (strcmp(ns_unset[i]->location,
			   SETTING_STRVAR_UNEXPANDED) == 0)
			continue;

		ns = namespace_find_set(user, ns_set[i]);
		i_assert(ns != NULL);
		if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0) {
			/* remember the subscriptions=no namespaces so we can
			   handle their subscriptions in parent namespaces
			   properly */
			mail_namespace_ref(ns);
			array_append(&worker->subs_namespaces, &ns, 1);
		}
		mail_namespace_destroy(ns);
	}
	if (user->namespaces == NULL) {
		i_fatal("All your namespaces have a location setting. "
			"It should be empty (default mail_location) in the "
			"namespace to be converted.");
	}
}

struct dsync_worker *
dsync_worker_init_local(struct mail_user *user, char alt_char)
{
	struct local_dsync_worker *worker;
	pool_t pool;

	pool = pool_alloconly_create("local dsync worker", 10240);
	worker = p_new(pool, struct local_dsync_worker, 1);
	worker->worker.v = local_dsync_worker;
	worker->user = user;
	worker->pool = pool;
	worker->alt_char = alt_char;
	worker->mailbox_hash =
		hash_table_create(default_pool, pool, 0,
				  mailbox_guid_hash, mailbox_guid_cmp);
	i_array_init(&worker->saved_uids, 128);
	i_array_init(&worker->msg_get_queue, 32);
	p_array_init(&worker->subs_namespaces, pool, 8);
	dsync_drop_extra_namespaces(worker);
	return &worker->worker;
}

static void local_worker_deinit(struct dsync_worker *_worker)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mail_namespace **nsp;

	i_assert(worker->save_input == NULL);

	array_foreach_modifiable(&worker->subs_namespaces, nsp)
		mail_namespace_unref(nsp);

	local_worker_msg_box_close(worker);
	local_worker_mailbox_close(worker);
	hash_table_destroy(&worker->mailbox_hash);
	if (worker->mailbox_changes_hash != NULL)
		hash_table_destroy(&worker->mailbox_changes_hash);
	if (worker->dir_changes_hash != NULL)
		hash_table_destroy(&worker->dir_changes_hash);
	array_free(&worker->msg_get_queue);
	array_free(&worker->saved_uids);
	pool_unref(&worker->pool);
}

static bool local_worker_is_output_full(struct dsync_worker *worker ATTR_UNUSED)
{
	return FALSE;
}

static int local_worker_output_flush(struct dsync_worker *worker ATTR_UNUSED)
{
	return 1;
}

static void
dsync_worker_save_mailbox_change(struct local_dsync_worker *worker,
				 const struct mailbox_log_record *rec)
{
	struct local_dsync_mailbox_change *change;
	time_t stamp;

	change = hash_table_lookup(worker->mailbox_changes_hash,
				   rec->mailbox_guid);
	if (change == NULL) {
		change = i_new(struct local_dsync_mailbox_change, 1);
		memcpy(change->guid.guid, rec->mailbox_guid,
		       sizeof(change->guid.guid));
		hash_table_insert(worker->mailbox_changes_hash,
				  change->guid.guid, change);
	}

	stamp = mailbox_log_record_get_timestamp(rec);
	switch (rec->type) {
	case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
		change->deleted_mailbox = TRUE;
		if (change->last_delete < stamp)
			change->last_delete = stamp;
		break;
	case MAILBOX_LOG_RECORD_DELETE_DIR:
	case MAILBOX_LOG_RECORD_RENAME:
	case MAILBOX_LOG_RECORD_SUBSCRIBE:
	case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
		i_unreached();
	}
}

static void
dsync_worker_save_dir_change(struct local_dsync_worker *worker,
			     struct mailbox_list *list,
			     const struct mailbox_log_record *rec)
{
	struct local_dsync_dir_change *change, new_change;
	time_t stamp;

	memset(&new_change, 0, sizeof(new_change));
	new_change.list = list;
	memcpy(new_change.name_sha1.guid, rec->mailbox_guid,
	       sizeof(new_change.name_sha1.guid));

	stamp = mailbox_log_record_get_timestamp(rec);
	change = hash_table_lookup(worker->dir_changes_hash, &new_change);
	if (change == NULL) {
		change = i_new(struct local_dsync_dir_change, 1);
		*change = new_change;
		hash_table_insert(worker->dir_changes_hash, change, change);
	}

	switch (rec->type) {
	case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
		i_unreached();
	case MAILBOX_LOG_RECORD_DELETE_DIR:
		change->deleted_dir = TRUE;
		if (change->last_delete < stamp)
			change->last_delete = stamp;
		break;
	case MAILBOX_LOG_RECORD_RENAME:
		if (change->last_rename < stamp)
			change->last_rename = stamp;
		break;
	case MAILBOX_LOG_RECORD_SUBSCRIBE:
	case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
		if (change->last_subs_change > stamp) {
			/* we've already seen a newer subscriptions state. this
			   is probably a stale record created by dsync */
		} else {
			change->last_subs_change = stamp;
			change->unsubscribed =
				rec->type == MAILBOX_LOG_RECORD_UNSUBSCRIBE;
		}
		break;
	}
}

static int
dsync_worker_get_list_mailbox_log(struct local_dsync_worker *worker,
				  struct mailbox_list *list)
{
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	const struct mailbox_log_record *rec;

	log = mailbox_list_get_changelog(list);
	iter = mailbox_log_iter_init(log);
	while ((rec = mailbox_log_iter_next(iter)) != NULL) {
		switch (rec->type) {
		case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
			dsync_worker_save_mailbox_change(worker, rec);
			break;
		case MAILBOX_LOG_RECORD_DELETE_DIR:
		case MAILBOX_LOG_RECORD_RENAME:
		case MAILBOX_LOG_RECORD_SUBSCRIBE:
		case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
			dsync_worker_save_dir_change(worker, list, rec);
			break;
		}
	}
	return mailbox_log_iter_deinit(&iter);
}

static unsigned int mailbox_log_record_hash(const void *p)
{
	const uint8_t *guid = p;

	return ((unsigned int)guid[0] << 24) |
		((unsigned int)guid[1] << 16) |
		((unsigned int)guid[2] << 8) |
		(unsigned int)guid[3];
}

static int mailbox_log_record_cmp(const void *p1, const void *p2)
{
	return memcmp(p1, p2, MAIL_GUID_128_SIZE);
}

static unsigned int dir_change_hash(const void *p)
{
	const struct local_dsync_dir_change *change = p;

	return mailbox_log_record_hash(change->name_sha1.guid) ^
		POINTER_CAST_TO(change->list, unsigned int);
}

static int dir_change_cmp(const void *p1, const void *p2)
{
	const struct local_dsync_dir_change *c1 = p1, *c2 = p2;

	if (c1->list != c2->list)
		return 1;

	return memcmp(c1->name_sha1.guid, c2->name_sha1.guid,
		      MAIL_GUID_128_SIZE);
}

static int dsync_worker_get_mailbox_log(struct local_dsync_worker *worker)
{
	struct mail_namespace *ns;
	int ret = 0;

	if (worker->mailbox_changes_hash != NULL)
		return 0;

	worker->mailbox_changes_hash =
		hash_table_create(default_pool, worker->pool, 0,
				  mailbox_log_record_hash,
				  mailbox_log_record_cmp);
	worker->dir_changes_hash =
		hash_table_create(default_pool, worker->pool, 0,
				  dir_change_hash, dir_change_cmp);
	for (ns = worker->user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->alias_for != NULL)
			continue;

		if (dsync_worker_get_list_mailbox_log(worker, ns->list) < 0)
			ret = -1;
	}
	return ret;
}

static struct dsync_worker_mailbox_iter *
local_worker_mailbox_iter_init(struct dsync_worker *_worker)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct local_dsync_worker_mailbox_iter *iter;
	enum mailbox_list_iter_flags list_flags =
		MAILBOX_LIST_ITER_SKIP_ALIASES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX;
	static const char *patterns[] = { "*", NULL };

	iter = i_new(struct local_dsync_worker_mailbox_iter, 1);
	iter->iter.worker = _worker;
	iter->ret_pool = pool_alloconly_create("local mailbox iter", 1024);
	iter->list_iter =
		mailbox_list_iter_init_namespaces(worker->user->namespaces,
						  patterns, NAMESPACE_PRIVATE,
						  list_flags);
	(void)dsync_worker_get_mailbox_log(worker);
	return &iter->iter;
}

static void
local_dsync_worker_add_mailbox(struct local_dsync_worker *worker,
			       struct mail_namespace *ns,
			       const char *storage_name,
			       const mailbox_guid_t *guid)
{
	struct local_dsync_mailbox *lbox;

	lbox = p_new(worker->pool, struct local_dsync_mailbox, 1);
	lbox->ns = ns;
	memcpy(lbox->guid.guid, guid->guid, sizeof(lbox->guid.guid));
	lbox->storage_name = p_strdup(worker->pool, storage_name);

	hash_table_insert(worker->mailbox_hash, &lbox->guid, lbox);
}

static int
iter_next_deleted(struct local_dsync_worker_mailbox_iter *iter,
		  struct local_dsync_worker *worker,
		  struct dsync_mailbox *dsync_box_r)
{
	void *key, *value;

	if (iter->deleted_iter == NULL) {
		iter->deleted_iter =
			hash_table_iterate_init(worker->mailbox_changes_hash);
	}
	while (hash_table_iterate(iter->deleted_iter, &key, &value)) {
		const struct local_dsync_mailbox_change *change = value;

		if (change->deleted_mailbox) {
			/* the name doesn't matter */
			dsync_box_r->name = "";
			dsync_box_r->mailbox_guid = change->guid;
			dsync_box_r->last_change = change->last_delete;
			dsync_box_r->flags |=
				DSYNC_MAILBOX_FLAG_DELETED_MAILBOX;
			return 1;
		}
	}

	if (iter->deleted_dir_iter == NULL) {
		iter->deleted_dir_iter =
			hash_table_iterate_init(worker->dir_changes_hash);
	}
	while (hash_table_iterate(iter->deleted_dir_iter, &key, &value)) {
		const struct local_dsync_dir_change *change = value;

		if (change->deleted_dir) {
			/* the name doesn't matter */
			dsync_box_r->name = "";
			dsync_box_r->name_sha1 = change->name_sha1;
			dsync_box_r->last_change = change->last_delete;
			dsync_box_r->flags |= DSYNC_MAILBOX_FLAG_NOSELECT |
				DSYNC_MAILBOX_FLAG_DELETED_DIR;
			return 1;
		}
	}
	hash_table_iterate_deinit(&iter->deleted_iter);
	return -1;
}

static int
local_worker_mailbox_iter_next(struct dsync_worker_mailbox_iter *_iter,
			       struct dsync_mailbox *dsync_box_r)
{
	struct local_dsync_worker_mailbox_iter *iter =
		(struct local_dsync_worker_mailbox_iter *)_iter;
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_iter->worker;
	enum mailbox_flags flags =
		MAILBOX_FLAG_READONLY | MAILBOX_FLAG_KEEP_RECENT;
	const struct mailbox_info *info;
	const char *storage_name;
	struct mailbox *box;
	struct mailbox_status status;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];
	struct local_dsync_mailbox_change *change;
	struct local_dsync_dir_change *dir_change, change_lookup;
	struct local_dsync_mailbox *old_lbox;
	enum mail_error error;
	const char *const *fields;
	unsigned int i, field_count;

	memset(dsync_box_r, 0, sizeof(*dsync_box_r));

	info = mailbox_list_iter_next(iter->list_iter);
	if (info == NULL)
		return iter_next_deleted(iter, worker, dsync_box_r);

	dsync_box_r->name = info->name;
	dsync_box_r->name_sep = info->ns->sep;

	storage_name = mail_namespace_get_storage_name(info->ns, info->name);
	dsync_str_sha_to_guid(storage_name, &dsync_box_r->name_sha1);

	/* get last change timestamp */
	change_lookup.list = info->ns->list;
	change_lookup.name_sha1 = dsync_box_r->name_sha1;
	dir_change = hash_table_lookup(worker->dir_changes_hash,
				       &change_lookup);
	if (dir_change != NULL) {
		/* it shouldn't be marked as deleted, but drop it to be sure */
		dir_change->deleted_dir = FALSE;
		dsync_box_r->last_change = dir_change->last_rename;
	}

	if ((info->flags & MAILBOX_NOSELECT) != 0) {
		dsync_box_r->flags |= DSYNC_MAILBOX_FLAG_NOSELECT;
		local_dsync_worker_add_mailbox(worker, info->ns, storage_name,
					       &dsync_box_r->name_sha1);
		return 1;
	}

	box = mailbox_alloc(info->ns->list, storage_name, flags);
	if (mailbox_sync(box, 0) < 0 ||
	    mailbox_get_guid(box, mailbox_guid) < 0) {
		struct mail_storage *storage = mailbox_get_storage(box);

		i_error("Failed to sync mailbox %s: %s", info->name,
			mail_storage_get_last_error(storage, &error));
		mailbox_free(&box);
		if (error == MAIL_ERROR_NOTFOUND ||
		    error == MAIL_ERROR_NOTPOSSIBLE) {
			/* Mailbox isn't selectable, try the next one. We
			   should have already caught \Noselect mailboxes, but
			   check them anyway here. The NOTPOSSIBLE check is
			   mainly for invalid mbox files. */
			return local_worker_mailbox_iter_next(_iter,
							      dsync_box_r);
		}
		_iter->failed = TRUE;
		return -1;
	}

	mailbox_get_status(box, STATUS_UIDNEXT | STATUS_UIDVALIDITY |
			   STATUS_HIGHESTMODSEQ | STATUS_CACHE_FIELDS |
			   STATUS_FIRST_RECENT_UID, &status);

	change = hash_table_lookup(worker->mailbox_changes_hash, mailbox_guid);
	if (change != NULL) {
		/* it shouldn't be marked as deleted, but drop it to be sure */
		change->deleted_mailbox = FALSE;
	}

	memcpy(dsync_box_r->mailbox_guid.guid, mailbox_guid,
	       sizeof(dsync_box_r->mailbox_guid.guid));
	dsync_box_r->uid_validity = status.uidvalidity;
	dsync_box_r->uid_next = status.uidnext;
	dsync_box_r->message_count = status.messages;
	dsync_box_r->first_recent_uid = status.first_recent_uid;
	dsync_box_r->highest_modseq = status.highest_modseq;

	p_clear(iter->ret_pool);
	fields = array_get(status.cache_fields, &field_count);
	p_array_init(&dsync_box_r->cache_fields, iter->ret_pool, field_count);
	for (i = 0; i < field_count; i++) {
		const char *field_name = p_strdup(iter->ret_pool, fields[i]);

		array_append(&dsync_box_r->cache_fields, &field_name, 1);
	}

	old_lbox = hash_table_lookup(worker->mailbox_hash,
				     &dsync_box_r->mailbox_guid);
	if (old_lbox != NULL) {
		i_error("Mailboxes don't have unique GUIDs: "
			"%s is shared by %s and %s",
			dsync_guid_to_str(&dsync_box_r->mailbox_guid),
			old_lbox->storage_name, storage_name);
		mailbox_free(&box);
		_iter->failed = TRUE;
		return -1;
	}
	local_dsync_worker_add_mailbox(worker, info->ns, storage_name,
				       &dsync_box_r->mailbox_guid);
	mailbox_free(&box);
	return 1;
}

static int
local_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter *_iter)
{
	struct local_dsync_worker_mailbox_iter *iter =
		(struct local_dsync_worker_mailbox_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	if (mailbox_list_iter_deinit(&iter->list_iter) < 0)
		ret = -1;
	pool_unref(&iter->ret_pool);
	i_free(iter);
	return ret;
}

static struct dsync_worker_subs_iter *
local_worker_subs_iter_init(struct dsync_worker *_worker)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct local_dsync_worker_subs_iter *iter;
	enum mailbox_list_iter_flags list_flags =
		MAILBOX_LIST_ITER_SKIP_ALIASES |
		MAILBOX_LIST_ITER_SELECT_SUBSCRIBED;
	static const char *patterns[] = { "*", NULL };

	iter = i_new(struct local_dsync_worker_subs_iter, 1);
	iter->iter.worker = _worker;
	iter->list_iter =
		mailbox_list_iter_init_namespaces(worker->user->namespaces,
						  patterns, NAMESPACE_PRIVATE,
						  list_flags);
	(void)dsync_worker_get_mailbox_log(worker);
	return &iter->iter;
}

static struct mail_namespace *
find_subscription_ns(struct local_dsync_worker *worker, const char *vname)
{
	struct mail_namespace *const *nsp;

	array_foreach(&worker->subs_namespaces, nsp) {
		if (strncmp((*nsp)->prefix, vname, (*nsp)->prefix_len) == 0)
			return *nsp;
	}
	return NULL;
}

static int
local_worker_subs_iter_next(struct dsync_worker_subs_iter *_iter,
			    struct dsync_worker_subscription *rec_r)
{
	struct local_dsync_worker_subs_iter *iter =
		(struct local_dsync_worker_subs_iter *)_iter;
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_iter->worker;
	struct local_dsync_dir_change *change, change_lookup;
	const struct mailbox_info *info;
	struct mail_namespace *subs_ns;
	const char *storage_name;

	memset(rec_r, 0, sizeof(*rec_r));

	info = mailbox_list_iter_next(iter->list_iter);
	if (info == NULL)
		return -1;

	subs_ns = find_subscription_ns(worker, info->name);
	if (subs_ns == NULL)
		subs_ns = info->ns;
	storage_name = mail_namespace_get_storage_name(subs_ns, info->name);
	if (subs_ns != info->ns)
		storage_name = t_strconcat(subs_ns->prefix, storage_name, NULL);

	dsync_str_sha_to_guid(storage_name, &change_lookup.name_sha1);
	change_lookup.list = info->ns->list;

	change = hash_table_lookup(worker->dir_changes_hash,
				   &change_lookup);
	if (change != NULL) {
		/* it shouldn't be marked as unsubscribed, but drop it to
		   be sure */
		change->unsubscribed = FALSE;
		rec_r->last_change = change->last_subs_change;
	}
	rec_r->ns_prefix = info->ns->prefix;
	rec_r->vname = info->name;
	rec_r->storage_name = storage_name;
	return 1;
}

static int
local_worker_subs_iter_next_un(struct dsync_worker_subs_iter *_iter,
			       struct dsync_worker_unsubscription *rec_r)
{
	struct local_dsync_worker_subs_iter *iter =
		(struct local_dsync_worker_subs_iter *)_iter;
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_iter->worker;
	void *key, *value;

	if (iter->deleted_iter == NULL) {
		iter->deleted_iter =
			hash_table_iterate_init(worker->dir_changes_hash);
	}
	while (hash_table_iterate(iter->deleted_iter, &key, &value)) {
		const struct local_dsync_dir_change *change = value;

		if (change->unsubscribed) {
			/* the name doesn't matter */
			struct mail_namespace *ns =
				mailbox_list_get_namespace(change->list);
			memset(rec_r, 0, sizeof(*rec_r));
			rec_r->name_sha1 = change->name_sha1;
			rec_r->ns_prefix = ns->prefix;
			rec_r->last_change = change->last_subs_change;
			return 1;
		}
	}
	hash_table_iterate_deinit(&iter->deleted_iter);
	return -1;
}

static int
local_worker_subs_iter_deinit(struct dsync_worker_subs_iter *_iter)
{
	struct local_dsync_worker_subs_iter *iter =
		(struct local_dsync_worker_subs_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	if (mailbox_list_iter_deinit(&iter->list_iter) < 0)
		ret = -1;
	i_free(iter);
	return ret;
}

static void
local_worker_set_subscribed(struct dsync_worker *_worker,
			    const char *name, time_t last_change, bool set)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mail_namespace *ns, *subs_ns;
	const char *storage_name;

	storage_name = name;
	ns = mail_namespace_find(worker->user->namespaces,
				 &storage_name);
	if (ns == NULL) {
		i_error("Can't find namespace for mailbox %s", name);
		return;
	}

	subs_ns = find_subscription_ns(worker, name);
	if (subs_ns != NULL) {
		/* subscription is being written to a different namespace
		   than where the mailbox exists. */
		storage_name = mail_namespace_get_storage_name(subs_ns, name);
		storage_name = t_strconcat(subs_ns->prefix, storage_name, NULL);
		/* drop the common prefix */
		i_assert(strncmp(ns->prefix, storage_name,
				 strlen(ns->prefix)) == 0);
		storage_name += strlen(ns->prefix);
	}

	mailbox_list_set_changelog_timestamp(ns->list, last_change);
	if (mailbox_list_set_subscribed(ns->list, storage_name, set) < 0) {
		dsync_worker_set_failure(_worker);
		i_error("Can't update subscription %s: %s", name,
			mailbox_list_get_last_error(ns->list, NULL));
	}
	mailbox_list_set_changelog_timestamp(ns->list, (time_t)-1);
}

static int local_mailbox_open(struct local_dsync_worker *worker,
			      const mailbox_guid_t *guid,
			      struct mailbox **box_r)
{
	enum mailbox_flags flags = MAILBOX_FLAG_KEEP_RECENT;
	struct local_dsync_mailbox *lbox;
	struct mailbox *box;
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];

	lbox = hash_table_lookup(worker->mailbox_hash, guid);
	if (lbox == NULL) {
		i_error("Trying to open a non-listed mailbox with guid=%s",
			dsync_guid_to_str(guid));
		return -1;
	}
	if (lbox->deleted) {
		*box_r = NULL;
		return 0;
	}

	box = mailbox_alloc(lbox->ns->list, lbox->storage_name, flags);
	if (mailbox_sync(box, 0) < 0 ||
	    mailbox_get_guid(box, mailbox_guid) < 0) {
		struct mail_storage *storage = mailbox_get_storage(box);

		i_error("Failed to sync mailbox %s: %s", lbox->storage_name,
			mail_storage_get_last_error(storage, NULL));
		mailbox_free(&box);
		return -1;
	}

	if (memcmp(mailbox_guid, guid->guid, sizeof(guid->guid)) != 0) {
		i_error("Mailbox %s changed its GUID (%s -> %s)",
			lbox->storage_name, dsync_guid_to_str(guid),
			mail_guid_128_to_string(mailbox_guid));
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 1;
}

static int iter_local_mailbox_open(struct local_dsync_worker_msg_iter *iter)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)iter->iter.worker;
	mailbox_guid_t *guid;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	int ret;

	for (;;) {
		if (iter->mailbox_idx == iter->mailbox_count) {
			/* no more mailboxes */
			return -1;
		}

		guid = &iter->mailboxes[iter->mailbox_idx];
		ret = local_mailbox_open(worker, guid, &box);
		if (ret != 0)
			break;
		/* mailbox was deleted. try next one. */
		iter->mailbox_idx++;
	}
	if (ret < 0) {
		i_error("msg iteration failed: Couldn't open mailbox %s",
			dsync_guid_to_str(guid));
		iter->iter.failed = TRUE;
		return -1;
	}

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	trans = mailbox_transaction_begin(box, 0);
	iter->search_ctx = mailbox_search_init(trans, search_args, NULL);
	iter->mail = mail_alloc(trans, MAIL_FETCH_FLAGS | MAIL_FETCH_GUID,
				NULL);
	return 0;
}

static void
iter_local_mailbox_close(struct local_dsync_worker_msg_iter *iter)
{
	struct mailbox *box = iter->mail->box;
	struct mailbox_transaction_context *trans = iter->mail->transaction;

	iter->expunges_set = FALSE;
	mail_free(&iter->mail);
	if (mailbox_search_deinit(&iter->search_ctx) < 0) {
		struct mail_storage *storage =
			mailbox_get_storage(iter->mail->box);

		i_error("msg search failed: %s",
			mail_storage_get_last_error(storage, NULL));
		iter->iter.failed = TRUE;
	}
	(void)mailbox_transaction_commit(&trans);
	mailbox_free(&box);
}

static struct dsync_worker_msg_iter *
local_worker_msg_iter_init(struct dsync_worker *worker,
			   const mailbox_guid_t mailboxes[],
			   unsigned int mailbox_count)
{
	struct local_dsync_worker_msg_iter *iter;
	unsigned int i;

	iter = i_new(struct local_dsync_worker_msg_iter, 1);
	iter->iter.worker = worker;
	iter->mailboxes = mailbox_count == 0 ? NULL :
		i_new(mailbox_guid_t, mailbox_count);
	iter->mailbox_count = mailbox_count;
	for (i = 0; i < mailbox_count; i++) {
		memcpy(iter->mailboxes[i].guid, &mailboxes[i],
		       sizeof(iter->mailboxes[i].guid));
	}
	i_array_init(&iter->expunges, 32);
	iter->tmp_guid_str = str_new(default_pool, MAIL_GUID_128_SIZE * 2 + 1);
	(void)iter_local_mailbox_open(iter);
	return &iter->iter;
}

static int mailbox_expunge_rec_cmp(const struct mailbox_expunge_rec *e1,
				   const struct mailbox_expunge_rec *e2)
{
	if (e1->uid < e2->uid)
		return -1;
	else if (e1->uid > e2->uid)
		return 1;
	else
		return 0;
}

static bool
iter_local_mailbox_next_expunge(struct local_dsync_worker_msg_iter *iter,
				uint32_t prev_uid, struct dsync_message *msg_r)
{
	struct mailbox *box = iter->mail->box;
	struct mailbox_status status;
	const uint8_t *guid_128;
	const struct mailbox_expunge_rec *expunges;
	unsigned int count;

	if (iter->expunges_set) {
		expunges = array_get(&iter->expunges, &count);
		if (iter->expunge_idx == count)
			return FALSE;

		memset(msg_r, 0, sizeof(*msg_r));
		str_truncate(iter->tmp_guid_str, 0);
		guid_128 = expunges[iter->expunge_idx].guid_128;
		if (!mail_guid_128_is_empty(guid_128)) {
			binary_to_hex_append(iter->tmp_guid_str, guid_128,
					     MAIL_GUID_128_SIZE);
		}
		msg_r->guid = str_c(iter->tmp_guid_str);
		msg_r->uid = expunges[iter->expunge_idx].uid;
		msg_r->flags = DSYNC_MAIL_FLAG_EXPUNGED;
		iter->expunge_idx++;
		return TRUE;
	}

	/* initialize list of expunged messages at the end of mailbox */
	iter->expunge_idx = 0;
	array_clear(&iter->expunges);
	iter->expunges_set = TRUE;

	mailbox_get_status(box, STATUS_UIDNEXT, &status);
	if (prev_uid + 1 >= status.uidnext) {
		/* no expunged messages at the end of mailbox */
		return FALSE;
	}

	T_BEGIN {
		ARRAY_TYPE(seq_range) uids_filter;

		t_array_init(&uids_filter, 1);
		seq_range_array_add_range(&uids_filter, prev_uid + 1,
					  status.uidnext - 1);
		(void)mailbox_get_expunges(box, 0, &uids_filter,
					   &iter->expunges);
		array_sort(&iter->expunges, mailbox_expunge_rec_cmp);
	} T_END;
	return iter_local_mailbox_next_expunge(iter, prev_uid, msg_r);
}

static int
local_worker_msg_iter_next(struct dsync_worker_msg_iter *_iter,
			   unsigned int *mailbox_idx_r,
			   struct dsync_message *msg_r)
{
	struct local_dsync_worker_msg_iter *iter =
		(struct local_dsync_worker_msg_iter *)_iter;
	const char *guid;
	uint32_t prev_uid;

	if (_iter->failed || iter->search_ctx == NULL)
		return -1;

	prev_uid = iter->mail->uid;
	if (!mailbox_search_next(iter->search_ctx, iter->mail)) {
		if (iter_local_mailbox_next_expunge(iter, prev_uid, msg_r)) {
			*mailbox_idx_r = iter->mailbox_idx;
			return 1;
		}
		iter_local_mailbox_close(iter);
		iter->mailbox_idx++;
		if (iter_local_mailbox_open(iter) < 0)
			return -1;
		return local_worker_msg_iter_next(_iter, mailbox_idx_r, msg_r);
	}
	*mailbox_idx_r = iter->mailbox_idx;

	if (mail_get_special(iter->mail, MAIL_FETCH_GUID, &guid) < 0) {
		if (!iter->mail->expunged) {
			struct mail_storage *storage =
				mailbox_get_storage(iter->mail->box);

			i_error("msg guid lookup failed: %s",
				mail_storage_get_last_error(storage, NULL));
			_iter->failed = TRUE;
			return -1;
		}
		return local_worker_msg_iter_next(_iter, mailbox_idx_r, msg_r);
	}

	memset(msg_r, 0, sizeof(*msg_r));
	msg_r->guid = guid;
	msg_r->uid = iter->mail->uid;
	msg_r->flags = mail_get_flags(iter->mail);
	msg_r->keywords = mail_get_keywords(iter->mail);
	msg_r->modseq = mail_get_modseq(iter->mail);
	if (mail_get_save_date(iter->mail, &msg_r->save_date) < 0)
		msg_r->save_date = (time_t)-1;
	return 1;
}

static int
local_worker_msg_iter_deinit(struct dsync_worker_msg_iter *_iter)
{
	struct local_dsync_worker_msg_iter *iter =
		(struct local_dsync_worker_msg_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	if (iter->mail != NULL)
		iter_local_mailbox_close(iter);
	array_free(&iter->expunges);
	str_free(&iter->tmp_guid_str);
	i_free(iter->mailboxes);
	i_free(iter);
	return ret;
}

static void
local_worker_copy_mailbox_update(const struct dsync_mailbox *dsync_box,
				 struct mailbox_update *update_r)
{
	memset(update_r, 0, sizeof(*update_r));
	memcpy(update_r->mailbox_guid, dsync_box->mailbox_guid.guid,
	       sizeof(update_r->mailbox_guid));
	update_r->uid_validity = dsync_box->uid_validity;
	update_r->min_next_uid = dsync_box->uid_next;
	update_r->min_first_recent_uid = dsync_box->first_recent_uid;
	update_r->min_highest_modseq = dsync_box->highest_modseq;
}

static const char *
mailbox_name_convert(struct local_dsync_worker *worker,
		     const char *name, char src_sep, char dest_sep)
{
	char *dest_name, *p;

	dest_name = t_strdup_noconst(name);
	for (p = dest_name; *p != '\0'; p++) {
		if (*p == dest_sep && worker->alt_char != '\0')
			*p = worker->alt_char;
		else if (*p == src_sep)
			*p = dest_sep;
	}
	return dest_name;
}

static const char *
mailbox_name_cleanup(const char *input, char real_sep, char alt_char)
{
	char *output, *p;

	output = t_strdup_noconst(input);
	for (p = output; *p != '\0'; p++) {
		if (*p == real_sep || (uint8_t)*input < 32 ||
		    (uint8_t)*input >= 0x80)
			*p = alt_char;
	}
	return output;
}

static const char *mailbox_name_force_cleanup(const char *input, char alt_char)
{
	char *output, *p;

	output = t_strdup_noconst(input);
	for (p = output; *p != '\0'; p++) {
		if (!i_isalnum(*p))
			*p = alt_char;
	}
	return output;
}

static const char *
local_worker_convert_mailbox_name(struct local_dsync_worker *worker,
				  const char *name, struct mail_namespace *ns,
				  const struct dsync_mailbox *dsync_box,
				  bool creating)
{
	if (dsync_box->name_sep != ns->sep) {
		/* mailbox names use different separators. convert them. */
		name = mailbox_name_convert(worker, name,
					    dsync_box->name_sep, ns->sep);
	}
	if (creating) {
		if (!mailbox_list_is_valid_create_name(ns->list, name)) {
			/* change any real separators to alt separators,
			   drop any potentially invalid characters */
			name = mailbox_name_cleanup(name, ns->real_sep,
						    worker->alt_char);
		}
		if (!mailbox_list_is_valid_create_name(ns->list, name)) {
			/* still not working, apparently it's not valid mUTF-7.
			   just drop all non-alphanumeric characters. */
			name = mailbox_name_force_cleanup(name,
							  worker->alt_char);
		}
		if (!mailbox_list_is_valid_create_name(ns->list, name)) {
			/* probably some reserved name (e.g. dbox-Mails) */
			name = t_strconcat("_", name, NULL);
		}
		if (!mailbox_list_is_valid_create_name(ns->list, name)) {
			/* name is too long? just give up and generate a
			   unique name */
			uint8_t guid[MAIL_GUID_128_SIZE];

			mail_generate_guid_128(guid);
			name = mail_guid_128_to_string(guid);
		}
		i_assert(mailbox_list_is_valid_create_name(ns->list, name));
	}
	return name;
}

static struct mailbox *
local_worker_mailbox_alloc(struct local_dsync_worker *worker,
			   const struct dsync_mailbox *dsync_box, bool creating)
{
	struct mail_namespace *ns;
	struct local_dsync_mailbox *lbox;
	const char *name;

	lbox = dsync_mailbox_is_noselect(dsync_box) ? NULL :
		hash_table_lookup(worker->mailbox_hash,
				  &dsync_box->mailbox_guid);
	if (lbox != NULL) {
		/* use the existing known mailbox name */
		return mailbox_alloc(lbox->ns->list, lbox->storage_name, 0);
	}

	name = dsync_box->name;
	ns = mail_namespace_find(worker->user->namespaces, &name);
	if (ns == NULL) {
		i_error("Can't find namespace for mailbox %s", dsync_box->name);
		return NULL;
	}

	name = local_worker_convert_mailbox_name(worker, name, ns,
						 dsync_box, creating);
	if (!dsync_mailbox_is_noselect(dsync_box)) {
		local_dsync_worker_add_mailbox(worker, ns, name,
					       &dsync_box->mailbox_guid);
	}
	return mailbox_alloc(ns->list, name, 0);
}

static int local_worker_create_dir(struct mailbox *box,
				   const struct dsync_mailbox *dsync_box)
{
	struct mailbox_list *list = mailbox_get_namespace(box)->list;
	const char *errstr;
	enum mail_error error;

	if (mailbox_list_create_dir(list, mailbox_get_name(box)) == 0)
		return 0;

	errstr = mailbox_list_get_last_error(list, &error);
	switch (error) {
	case MAIL_ERROR_EXISTS:
		/* directory already exists - that's ok */
		return 0;
	case MAIL_ERROR_NOTPOSSIBLE:
		/* \noselect mailboxes not supported - just ignore them
		   (we don't want to create a selectable mailbox if the other
		   side of the sync doesn't support dual-use mailboxes,
		   e.g. mbox) */
		return 0;
	default:
		i_error("Can't create mailbox %s: %s", dsync_box->name, errstr);
		return -1;
	}
}

static int
local_worker_create_allocated_mailbox(struct local_dsync_worker *worker,
				      struct mailbox *box,
				      const struct dsync_mailbox *dsync_box)
{
	struct mailbox_update update;
	const char *errstr;
	enum mail_error error;

	local_worker_copy_mailbox_update(dsync_box, &update);

	if (dsync_mailbox_is_noselect(dsync_box)) {
		if (local_worker_create_dir(box, dsync_box) < 0) {
			dsync_worker_set_failure(&worker->worker);
			return -1;
		}
		return 1;
	}

	if (mailbox_create(box, &update, FALSE) < 0) {
		errstr = mail_storage_get_last_error(mailbox_get_storage(box),
						     &error);
		if (error == MAIL_ERROR_EXISTS) {
			/* mailbox already exists */
			return 0;
		}

		dsync_worker_set_failure(&worker->worker);
		i_error("Can't create mailbox %s: %s", dsync_box->name, errstr);
		return -1;
	}

	local_dsync_worker_add_mailbox(worker,
				       mailbox_get_namespace(box),
				       mailbox_get_name(box),
				       &dsync_box->mailbox_guid);
	return 1;
}

static void
local_worker_create_mailbox(struct dsync_worker *_worker,
			    const struct dsync_mailbox *dsync_box)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mailbox *box;
	struct mail_namespace *ns;
	const char *new_name;
	int ret;

	box = local_worker_mailbox_alloc(worker, dsync_box, TRUE);
	if (box == NULL) {
		dsync_worker_set_failure(_worker);
		return;
	}

	ret = local_worker_create_allocated_mailbox(worker, box, dsync_box);
	if (ret != 0) {
		mailbox_free(&box);
		return;
	}

	/* mailbox name already exists. add mailbox guid to the name,
	   that shouldn't exist. */
	new_name = t_strconcat(mailbox_get_name(box), "_",
			       dsync_guid_to_str(&dsync_box->mailbox_guid),
			       NULL);
	ns = mailbox_get_namespace(box);
	mailbox_free(&box);

	local_dsync_worker_add_mailbox(worker, ns, new_name,
				       &dsync_box->mailbox_guid);
	box = mailbox_alloc(ns->list, new_name, 0);
	(void)local_worker_create_allocated_mailbox(worker, box, dsync_box);
	mailbox_free(&box);
}

static void
local_worker_delete_mailbox(struct dsync_worker *_worker,
			    const struct dsync_mailbox *dsync_box)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct local_dsync_mailbox *lbox;
	const mailbox_guid_t *mailbox = &dsync_box->mailbox_guid;
	struct mailbox *box;

	lbox = hash_table_lookup(worker->mailbox_hash, mailbox);
	if (lbox == NULL) {
		i_error("Trying to delete a non-listed mailbox with guid=%s",
			dsync_guid_to_str(mailbox));
		dsync_worker_set_failure(_worker);
		return;
	}

	mailbox_list_set_changelog_timestamp(lbox->ns->list,
					     dsync_box->last_change);
	box = mailbox_alloc(lbox->ns->list, lbox->storage_name, 0);
	if (mailbox_delete(box) < 0) {
		struct mail_storage *storage = mailbox_get_storage(box);

		i_error("Can't delete mailbox %s: %s", lbox->storage_name,
			mail_storage_get_last_error(storage, NULL));
		dsync_worker_set_failure(_worker);
	} else {
		lbox->deleted = TRUE;
	}
	mailbox_free(&box);
	mailbox_list_set_changelog_timestamp(lbox->ns->list, (time_t)-1);
}

static void
local_worker_delete_dir(struct dsync_worker *_worker,
			const struct dsync_mailbox *dsync_box)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mail_namespace *ns;
	const char *storage_name;

	storage_name = dsync_box->name;
	ns = mail_namespace_find(worker->user->namespaces, &storage_name);

	mailbox_list_set_changelog_timestamp(ns->list, dsync_box->last_change);
	if (mailbox_list_delete_dir(ns->list, storage_name) < 0) {
		i_error("Can't delete mailbox directory %s: %s",
			dsync_box->name,
			mailbox_list_get_last_error(ns->list, NULL));
	}
	mailbox_list_set_changelog_timestamp(ns->list, (time_t)-1);
}

static void
local_worker_rename_mailbox(struct dsync_worker *_worker,
			    const mailbox_guid_t *mailbox,
			    const struct dsync_mailbox *dsync_box)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct local_dsync_mailbox *lbox;
	struct mailbox_list *list;
	struct mailbox *old_box, *new_box;
	const char *newname;

	lbox = hash_table_lookup(worker->mailbox_hash, mailbox);
	if (lbox == NULL) {
		i_error("Trying to rename a non-listed mailbox with guid=%s",
			dsync_guid_to_str(mailbox));
		dsync_worker_set_failure(_worker);
		return;
	}

	list = lbox->ns->list;
	newname = local_worker_convert_mailbox_name(worker, dsync_box->name,
						    lbox->ns, dsync_box, TRUE);
	if (strcmp(lbox->storage_name, newname) == 0) {
		/* nothing changed after all. probably because some characters
		   in mailbox name weren't valid. */
		return;
	}

	mailbox_list_set_changelog_timestamp(list, dsync_box->last_change);
	old_box = mailbox_alloc(list, lbox->storage_name, 0);
	new_box = mailbox_alloc(list, newname, 0);
	if (mailbox_rename(old_box, new_box, FALSE) < 0) {
		struct mail_storage *storage = mailbox_get_storage(old_box);

		i_error("Can't rename mailbox %s to %s: %s", lbox->storage_name,
			newname, mail_storage_get_last_error(storage, NULL));
		dsync_worker_set_failure(_worker);
	} else {
		lbox->storage_name = p_strdup(worker->pool, newname);
	}
	mailbox_free(&old_box);
	mailbox_free(&new_box);
	mailbox_list_set_changelog_timestamp(list, (time_t)-1);
}

static bool
has_expected_save_uids(struct local_dsync_worker *worker,
		       const struct mail_transaction_commit_changes *changes)
{
	struct seq_range_iter iter;
	const uint32_t *expected_uids;
	uint32_t uid;
	unsigned int i, n, expected_count;

	expected_uids = array_get(&worker->saved_uids, &expected_count);
	seq_range_array_iter_init(&iter, &changes->saved_uids); i = n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		if (i == expected_count || uid != expected_uids[i++])
			return FALSE;
	}
	return i == expected_count;
}

static void local_worker_mailbox_close(struct local_dsync_worker *worker)
{
	struct mailbox_transaction_context *trans, *ext_trans;
	struct mail_transaction_commit_changes changes;

	i_assert(worker->save_input == NULL);

	memset(&worker->selected_box_guid, 0,
	       sizeof(worker->selected_box_guid));

	if (worker->selected_box == NULL)
		return;

	trans = worker->mail->transaction;
	ext_trans = worker->ext_mail->transaction;
	mail_free(&worker->mail);
	mail_free(&worker->ext_mail);

	/* all saves and copies go to ext_trans */
	if (mailbox_transaction_commit_get_changes(&ext_trans, &changes) < 0)
		dsync_worker_set_failure(&worker->worker);
	else {
		if (changes.ignored_modseq_changes != 0) {
			if (worker->worker.verbose) {
				i_info("%s: Ignored %u modseq changes",
				       mailbox_get_vname(worker->selected_box),
				       changes.ignored_modseq_changes);
			}
			worker->worker.unexpected_changes = TRUE;
		}
		if (!has_expected_save_uids(worker, &changes)) {
			if (worker->worker.verbose) {
				i_info("%s: Couldn't keep all uids",
				       mailbox_get_vname(worker->selected_box));
			}
			worker->worker.unexpected_changes = TRUE;
		}
		pool_unref(&changes.pool);
	}
	array_clear(&worker->saved_uids);

	if (mailbox_transaction_commit(&trans) < 0 ||
	    mailbox_sync(worker->selected_box, MAILBOX_SYNC_FLAG_FULL_WRITE) < 0)
		dsync_worker_set_failure(&worker->worker);

	mailbox_free(&worker->selected_box);
}

static void
local_worker_update_mailbox(struct dsync_worker *_worker,
			    const struct dsync_mailbox *dsync_box)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mailbox *box;
	struct mailbox_update update;
	bool selected = FALSE;

	/* if we're updating a selected mailbox, close it first so that all
	   pending changes get committed. */
	selected = worker->selected_box != NULL &&
		dsync_guid_equals(&dsync_box->mailbox_guid,
				  &worker->selected_box_guid);
	if (selected)
		local_worker_mailbox_close(worker);

	box = local_worker_mailbox_alloc(worker, dsync_box, FALSE);
	if (box == NULL) {
		dsync_worker_set_failure(_worker);
		return;
	}

	local_worker_copy_mailbox_update(dsync_box, &update);
	if (mailbox_update(box, &update) < 0) {
		dsync_worker_set_failure(_worker);
		i_error("Can't update mailbox %s: %s", dsync_box->name,
			mail_storage_get_last_error(mailbox_get_storage(box),
						    NULL));
	}
	mailbox_free(&box);

	if (selected)
		dsync_worker_select_mailbox(_worker, dsync_box);
}

static void
local_worker_set_cache_fields(struct local_dsync_worker *worker,
			      const ARRAY_TYPE(const_string) *cache_fields)
{
	struct mailbox_update update;
	const char *const *fields, **new_fields;
	unsigned int count;

	fields = array_get(cache_fields, &count);
	new_fields = t_new(const char *, count + 1);
	memcpy(new_fields, fields, sizeof(const char *) * count);

	memset(&update, 0, sizeof(update));
	update.cache_fields = new_fields;
	mailbox_update(worker->selected_box, &update);
}

static void
local_worker_select_mailbox(struct dsync_worker *_worker,
			    const mailbox_guid_t *mailbox,
			    const ARRAY_TYPE(const_string) *cache_fields)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mailbox_transaction_context *trans, *ext_trans;

	if (dsync_guid_equals(&worker->selected_box_guid, mailbox)) {
		/* already selected or previous select failed */
		i_assert(worker->selected_box != NULL || _worker->failed);
		return;
	}
	if (worker->selected_box != NULL)
		local_worker_mailbox_close(worker);
	worker->selected_box_guid = *mailbox;

	if (local_mailbox_open(worker, mailbox, &worker->selected_box) <= 0) {
		dsync_worker_set_failure(_worker);
		return;
	}
	if (cache_fields != NULL && array_is_created(cache_fields))
		local_worker_set_cache_fields(worker, cache_fields);

	ext_trans = mailbox_transaction_begin(worker->selected_box,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL |
					MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS);
	trans = mailbox_transaction_begin(worker->selected_box, 0);
	worker->mail = mail_alloc(trans, 0, NULL);
	worker->ext_mail = mail_alloc(ext_trans, 0, NULL);
}

static void
local_worker_msg_update_metadata(struct dsync_worker *_worker,
				 const struct dsync_message *msg)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mail_keywords *keywords;

	if (msg->modseq > 1) {
		(void)mailbox_enable(worker->mail->box,
				     MAILBOX_FEATURE_CONDSTORE);
	}

	if (!mail_set_uid(worker->mail, msg->uid))
		dsync_worker_set_failure(_worker);
	else {
		mail_update_flags(worker->mail, MODIFY_REPLACE, msg->flags);

		keywords = mailbox_keywords_create_valid(worker->mail->box,
							 msg->keywords);
		mail_update_keywords(worker->mail, MODIFY_REPLACE, keywords);
		mailbox_keywords_unref(worker->mail->box, &keywords);
		mail_update_modseq(worker->mail, msg->modseq);
	}
}

static void
local_worker_msg_update_uid(struct dsync_worker *_worker,
			    uint32_t old_uid, uint32_t new_uid)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mail_save_context *save_ctx;

	if (!mail_set_uid(worker->ext_mail, old_uid)) {
		dsync_worker_set_failure(_worker);
		return;
	}

	save_ctx = mailbox_save_alloc(worker->ext_mail->transaction);
	mailbox_save_copy_flags(save_ctx, worker->ext_mail);
	mailbox_save_set_uid(save_ctx, new_uid);
	if (mailbox_copy(&save_ctx, worker->ext_mail) == 0)
		mail_expunge(worker->ext_mail);
}

static void local_worker_msg_expunge(struct dsync_worker *_worker, uint32_t uid)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;

	if (mail_set_uid(worker->mail, uid))
		mail_expunge(worker->mail);
}

static void
local_worker_msg_save_set_metadata(struct local_dsync_worker *worker,
				   struct mailbox *box,
				   struct mail_save_context *save_ctx,
				   const struct dsync_message *msg)
{
	struct mail_keywords *keywords;

	i_assert(msg->uid != 0);

	if (msg->modseq > 1)
		(void)mailbox_enable(box, MAILBOX_FEATURE_CONDSTORE);

	keywords = str_array_length(msg->keywords) == 0 ? NULL :
		mailbox_keywords_create_valid(box, msg->keywords);
	mailbox_save_set_flags(save_ctx, msg->flags, keywords);
	if (keywords != NULL)
		mailbox_keywords_unref(box, &keywords);
	mailbox_save_set_uid(save_ctx, msg->uid);
	mailbox_save_set_save_date(save_ctx, msg->save_date);
	mailbox_save_set_min_modseq(save_ctx, msg->modseq);

	array_append(&worker->saved_uids, &msg->uid, 1);
}

static void
local_worker_msg_copy(struct dsync_worker *_worker,
		      const mailbox_guid_t *src_mailbox, uint32_t src_uid,
		      const struct dsync_message *dest_msg,
		      dsync_worker_copy_callback_t *callback, void *context)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mailbox *src_box;
	struct mailbox_transaction_context *src_trans;
	struct mail *src_mail;
	struct mail_save_context *save_ctx;
	int ret;

	if (local_mailbox_open(worker, src_mailbox, &src_box) <= 0) {
		callback(FALSE, context);
		return;
	}

	src_trans = mailbox_transaction_begin(src_box, 0);
	src_mail = mail_alloc(src_trans, 0, NULL);
	if (!mail_set_uid(src_mail, src_uid))
		ret = -1;
	else {
		save_ctx = mailbox_save_alloc(worker->ext_mail->transaction);
		local_worker_msg_save_set_metadata(worker, worker->mail->box,
						   save_ctx, dest_msg);
		ret = mailbox_copy(&save_ctx, src_mail);
	}

	mail_free(&src_mail);
	(void)mailbox_transaction_commit(&src_trans);
	mailbox_free(&src_box);

	callback(ret == 0, context);
}

static void dsync_worker_try_finish(struct local_dsync_worker *worker)
{
	if (worker->finish_callback == NULL)
		return;
	if (worker->save_io != NULL || worker->reading_mail)
		return;

	i_assert(worker->finishing);
	i_assert(!worker->finished);
	worker->finishing = FALSE;
	worker->finished = TRUE;
	worker->finish_callback(!worker->worker.failed, worker->finish_context);
}

static void
local_worker_save_msg_continue(struct local_dsync_worker *worker)
{
	struct mailbox *dest_box = worker->ext_mail->box;
	dsync_worker_save_callback_t *callback;
	ssize_t ret;

	while ((ret = i_stream_read(worker->save_input)) > 0) {
		if (mailbox_save_continue(worker->save_ctx) < 0)
			break;
	}
	if (ret == 0) {
		if (worker->save_io != NULL)
			return;
		worker->save_io =
			io_add(i_stream_get_fd(worker->save_input), IO_READ,
			       local_worker_save_msg_continue, worker);
		return;
	}
	i_assert(ret == -1);

	/* drop save_io before destroying save_input, so that save_input's
	   destroy callback can add io back to its fd. */
	if (worker->save_io != NULL)
		io_remove(&worker->save_io);
	if (worker->save_input->stream_errno != 0) {
		errno = worker->save_input->stream_errno;
		i_error("read(msg input) failed: %m");
		mailbox_save_cancel(&worker->save_ctx);
		dsync_worker_set_failure(&worker->worker);
	} else {
		i_assert(worker->save_input->eof);
		if (mailbox_save_finish(&worker->save_ctx) < 0) {
			struct mail_storage *storage =
				mailbox_get_storage(dest_box);

			i_error("Can't save message to mailbox %s: %s",
				mailbox_get_vname(dest_box),
				mail_storage_get_last_error(storage, NULL));
			dsync_worker_set_failure(&worker->worker);
		}
	}
	callback = worker->save_callback;
	worker->save_callback = NULL;
	i_stream_unref(&worker->save_input);

	dsync_worker_try_finish(worker);
	/* call the callback last, since it could call worker code again and
	   cause problems (e.g. if _try_finish() is called again, it could
	   cause a duplicate finish_callback()) */
	callback(worker->save_context);
}

static void
local_worker_msg_save(struct dsync_worker *_worker,
		      const struct dsync_message *msg,
		      const struct dsync_msg_static_data *data,
		      dsync_worker_save_callback_t *callback,
		      void *context)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct mailbox *dest_box = worker->ext_mail->box;
	struct mail_save_context *save_ctx;

	i_assert(worker->save_input == NULL);

	save_ctx = mailbox_save_alloc(worker->ext_mail->transaction);
	mailbox_save_set_guid(save_ctx, msg->guid);
	local_worker_msg_save_set_metadata(worker, worker->mail->box,
					   save_ctx, msg);
	if (*data->pop3_uidl != '\0')
		mailbox_save_set_pop3_uidl(save_ctx, data->pop3_uidl);

	mailbox_save_set_received_date(save_ctx, data->received_date, 0);

	if (mailbox_save_begin(&save_ctx, data->input) < 0) {
		struct mail_storage *storage = mailbox_get_storage(dest_box);
		i_error("Can't save message to mailbox %s: %s",
			mailbox_get_vname(dest_box),
			mail_storage_get_last_error(storage, NULL));
		dsync_worker_set_failure(_worker);
		callback(context);
		return;
	}

	worker->save_callback = callback;
	worker->save_context = context;
	worker->save_input = data->input;
	worker->save_ctx = save_ctx;
	i_stream_ref(worker->save_input);
	local_worker_save_msg_continue(worker);
}

static void local_worker_msg_save_cancel(struct dsync_worker *_worker)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;

	if (worker->save_input == NULL)
		return;

	if (worker->save_io != NULL)
		io_remove(&worker->save_io);
	mailbox_save_cancel(&worker->save_ctx);
	i_stream_unref(&worker->save_input);
}

static void local_worker_msg_get_done(struct local_dsync_worker *worker)
{
	const struct local_dsync_worker_msg_get *gets;
	struct local_dsync_worker_msg_get get;
	unsigned int count;

	worker->reading_mail = FALSE;

	gets = array_get(&worker->msg_get_queue, &count);
	if (count == 0)
		dsync_worker_try_finish(worker);
	else {
		get = gets[0];
		array_delete(&worker->msg_get_queue, 0, 1);
		local_worker_msg_get_next(worker, &get);
	}
}

static void local_worker_msg_box_close(struct local_dsync_worker *worker)
{
	struct mailbox_transaction_context *trans;
	struct mailbox *box;

	if (worker->get_mail == NULL)
		return;

	box = worker->get_mail->box;
	trans = worker->get_mail->transaction;

	mail_free(&worker->get_mail);
	(void)mailbox_transaction_commit(&trans);
	mailbox_free(&box);
	memset(&worker->get_mailbox, 0, sizeof(worker->get_mailbox));
}

static void
local_worker_msg_get_next(struct local_dsync_worker *worker,
			  const struct local_dsync_worker_msg_get *get)
{
	struct dsync_msg_static_data data;
	struct mailbox_transaction_context *trans;
	struct mailbox *box;

	i_assert(!worker->reading_mail);

	if (!dsync_guid_equals(&worker->get_mailbox, &get->mailbox)) {
		local_worker_msg_box_close(worker);
		if (local_mailbox_open(worker, &get->mailbox, &box) <= 0) {
			get->callback(DSYNC_MSG_GET_RESULT_FAILED,
				      NULL, get->context);
			return;
		}
		worker->get_mailbox = get->mailbox;

		trans = mailbox_transaction_begin(box, 0);
		worker->get_mail = mail_alloc(trans, 0, NULL);
	}

	if (!mail_set_uid(worker->get_mail, get->uid)) {
		get->callback(DSYNC_MSG_GET_RESULT_EXPUNGED,
			      NULL, get->context);
		return;
	}

	memset(&data, 0, sizeof(data));
	if (mail_get_special(worker->get_mail, MAIL_FETCH_UIDL_BACKEND,
			     &data.pop3_uidl) < 0 ||
	    mail_get_received_date(worker->get_mail, &data.received_date) < 0 ||
	    mail_get_stream(worker->get_mail, NULL, NULL, &data.input) < 0) {
		get->callback(worker->get_mail->expunged ?
			      DSYNC_MSG_GET_RESULT_EXPUNGED :
			      DSYNC_MSG_GET_RESULT_FAILED, NULL, get->context);
	} else {
		worker->reading_mail = TRUE;
		data.pop3_uidl = t_strdup(data.pop3_uidl);
		data.input = i_stream_create_limit(data.input, (uoff_t)-1);
		i_stream_set_destroy_callback(data.input,
					      local_worker_msg_get_done,
					      worker);
		get->callback(DSYNC_MSG_GET_RESULT_SUCCESS,
			      &data, get->context);
	}
}

static void
local_worker_msg_get(struct dsync_worker *_worker,
		     const mailbox_guid_t *mailbox, uint32_t uid,
		     dsync_worker_msg_callback_t *callback, void *context)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;
	struct local_dsync_worker_msg_get get;

	memset(&get, 0, sizeof(get));
	get.mailbox = *mailbox;
	get.uid = uid;
	get.callback = callback;
	get.context = context;

	if (!worker->reading_mail)
		local_worker_msg_get_next(worker, &get);
	else
		array_append(&worker->msg_get_queue, &get, 1);
}

static void
local_worker_finish(struct dsync_worker *_worker,
		    dsync_worker_finish_callback_t *callback, void *context)
{
	struct local_dsync_worker *worker =
		(struct local_dsync_worker *)_worker;

	i_assert(!worker->finishing);

	worker->finishing = TRUE;
	worker->finished = FALSE;
	worker->finish_callback = callback;
	worker->finish_context = context;

	dsync_worker_try_finish(worker);
}

struct dsync_worker_vfuncs local_dsync_worker = {
	local_worker_deinit,

	local_worker_is_output_full,
	local_worker_output_flush,

	local_worker_mailbox_iter_init,
	local_worker_mailbox_iter_next,
	local_worker_mailbox_iter_deinit,

	local_worker_subs_iter_init,
	local_worker_subs_iter_next,
	local_worker_subs_iter_next_un,
	local_worker_subs_iter_deinit,
	local_worker_set_subscribed,

	local_worker_msg_iter_init,
	local_worker_msg_iter_next,
	local_worker_msg_iter_deinit,

	local_worker_create_mailbox,
	local_worker_delete_mailbox,
	local_worker_delete_dir,
	local_worker_rename_mailbox,
	local_worker_update_mailbox,

	local_worker_select_mailbox,
	local_worker_msg_update_metadata,
	local_worker_msg_update_uid,
	local_worker_msg_expunge,
	local_worker_msg_copy,
	local_worker_msg_save,
	local_worker_msg_save_cancel,
	local_worker_msg_get,
	local_worker_finish
};
