/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "mail-index-view-private.h"
#include "mail-storage-hooks.h"
#include "mail-storage-private.h"
#include "mailbox-list-index-storage.h"
#include "mailbox-list-index-sync.h"

#define MAILBOX_LIST_INDEX_REFRESH_DELAY_MSECS 1000

/* dovecot.list.index.log doesn't have to be kept for that long. */
#define MAILBOX_LIST_INDEX_LOG_ROTATE_MIN_SIZE (8*1024)
#define MAILBOX_LIST_INDEX_LOG_ROTATE_MAX_SIZE (64*1024)
#define MAILBOX_LIST_INDEX_LOG_ROTATE_MIN_AGE_SECS (5*60)
#define MAILBOX_LIST_INDEX_LOG2_MAX_AGE_SECS (10*60)

static void mailbox_list_index_init_finish(struct mailbox_list *list);

struct mailbox_list_index_module mailbox_list_index_module =
	MODULE_CONTEXT_INIT(&mailbox_list_module_register);

void mailbox_list_index_set_index_error(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	mailbox_list_set_internal_error(list);
	mail_index_reset_error(ilist->index);
}

static void mailbox_list_index_init_pool(struct mailbox_list_index *ilist)
{
	ilist->mailbox_pool = pool_alloconly_create("mailbox list index", 4096);
	hash_table_create_direct(&ilist->mailbox_names, ilist->mailbox_pool, 0);
	hash_table_create_direct(&ilist->mailbox_hash, ilist->mailbox_pool, 0);
}

void mailbox_list_index_reset(struct mailbox_list_index *ilist)
{
	hash_table_destroy(&ilist->mailbox_names);
	hash_table_destroy(&ilist->mailbox_hash);
	pool_unref(&ilist->mailbox_pool);

	ilist->mailbox_tree = NULL;
	ilist->highest_name_id = 0;
	ilist->sync_log_file_seq = 0;
	ilist->sync_log_file_offset = 0;

	mailbox_list_index_init_pool(ilist);
}

int mailbox_list_index_index_open(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	const struct mail_storage_settings *set = list->mail_set;
	enum mail_index_open_flags index_flags;
	unsigned int lock_timeout;

	if (ilist->opened)
		return 0;

	if (mailbox_list_mkdir_missing_list_index_root(list) < 0)
		return -1;

	i_assert(ilist->index != NULL);

	index_flags = mail_storage_settings_to_index_flags(set);
	if (strcmp(list->name, MAILBOX_LIST_NAME_INDEX) == 0) {
		/* LAYOUT=index. this is the only location for the mailbox
		   data, so we must never move it into memory. */
		index_flags |= MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;
	}
	lock_timeout = set->mail_max_lock_timeout == 0 ? UINT_MAX :
		set->mail_max_lock_timeout;

	if (!mail_index_use_existing_permissions(ilist->index)) {
		struct mailbox_permissions perm;

		mailbox_list_get_root_permissions(list, &perm);
		mail_index_set_permissions(ilist->index, perm.file_create_mode,
					   perm.file_create_gid,
					   perm.file_create_gid_origin);
	}
	const struct mail_index_optimization_settings optimize_set = {
		.log = {
			.min_size = MAILBOX_LIST_INDEX_LOG_ROTATE_MIN_SIZE,
			.max_size = MAILBOX_LIST_INDEX_LOG_ROTATE_MAX_SIZE,
			.min_age_secs = MAILBOX_LIST_INDEX_LOG_ROTATE_MIN_AGE_SECS,
			.log2_max_age_secs = MAILBOX_LIST_INDEX_LOG2_MAX_AGE_SECS,
		},
	};
	mail_index_set_optimization_settings(ilist->index, &optimize_set);

	mail_index_set_fsync_mode(ilist->index, set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(ilist->index, set->parsed_lock_method,
				   lock_timeout);
	if (mail_index_open_or_create(ilist->index, index_flags) < 0) {
		if (mail_index_move_to_memory(ilist->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now, except if it fails with
			   LAYOUT=index backend. */
			if (mail_index_open_or_create(ilist->index,
						      index_flags) < 0) {
				mailbox_list_set_internal_error(list);
				return -1;
			}
		}
	}
	ilist->opened = TRUE;
	return 0;
}

struct mailbox_list_index_node *
mailbox_list_index_node_find_sibling(const struct mailbox_list *list,
				     struct mailbox_list_index_node *node,
				     const char *name)
{
	mailbox_list_name_unescape(&name, list->set.storage_name_escape_char);

	while (node != NULL) {
		if (strcmp(node->raw_name, name) == 0)
			return node;
		node = node->next;
	}
	return NULL;
}

static struct mailbox_list_index_node *
mailbox_list_index_lookup_real(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_index_node *node = ilist->mailbox_tree;
	const char *const *path;
	unsigned int i;
	char sep[2];

	if (*name == '\0')
		return mailbox_list_index_node_find_sibling(list, node, "");

	sep[0] = mailbox_list_get_hierarchy_sep(list); sep[1] = '\0';
	path = t_strsplit(name, sep);
	for (i = 0;; i++) {
		node = mailbox_list_index_node_find_sibling(list, node, path[i]);
		if (node == NULL || path[i+1] == NULL)
			break;
		node = node->children;
	}
	return node;
}

struct mailbox_list_index_node *
mailbox_list_index_lookup(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index_node *node;

	T_BEGIN {
		node = mailbox_list_index_lookup_real(list, name);
	} T_END;
	return node;
}

struct mailbox_list_index_node *
mailbox_list_index_lookup_uid(struct mailbox_list_index *ilist, uint32_t uid)
{
	return hash_table_lookup(ilist->mailbox_hash, POINTER_CAST(uid));
}

void mailbox_list_index_node_get_path(const struct mailbox_list_index_node *node,
				      char sep, string_t *str)
{
	if (node->parent != NULL) {
		mailbox_list_index_node_get_path(node->parent, sep, str);
		str_append_c(str, sep);
	}
	str_append(str, node->raw_name);
}

void mailbox_list_index_node_unlink(struct mailbox_list_index *ilist,
				    struct mailbox_list_index_node *node)
{
	struct mailbox_list_index_node **prev;

	prev = node->parent == NULL ?
		&ilist->mailbox_tree : &node->parent->children;

	while (*prev != node)
		prev = &(*prev)->next;
	*prev = node->next;
}

static int mailbox_list_index_parse_header(struct mailbox_list_index *ilist,
					   struct mail_index_view *view)
{
	const void *data, *name_start, *p;
	size_t i, len, size;
	uint32_t id, prev_id = 0;
	string_t *str;
	char *name;
	int ret = 0;

	mail_index_map_get_header_ext(view, view->map, ilist->ext_id, &data, &size);
	if (size == 0)
		return 0;

	str = t_str_new(128);
	for (i = sizeof(struct mailbox_list_index_header); i < size; ) {
		/* get id */
		if (i + sizeof(id) > size)
			return -1;
		memcpy(&id, CONST_PTR_OFFSET(data, i), sizeof(id));
		i += sizeof(id);

		if (id <= prev_id) {
			/* allow extra space in the end as long as last id=0 */
			return id == 0 ? 0 : -1;
		}
		prev_id = id;

		/* get name */
		p = memchr(CONST_PTR_OFFSET(data, i), '\0', size-i);
		if (p == NULL)
			return -1;
		name_start = CONST_PTR_OFFSET(data, i);
		len = (const char *)p - (const char *)name_start;

		if (uni_utf8_get_valid_data(name_start, len, str)) {
			name = p_strndup(ilist->mailbox_pool, name_start, len);
		} else {
			/* corrupted index. fix the name. */
			name = p_strdup(ilist->mailbox_pool, str_c(str));
			str_truncate(str, 0);
			ret = -1;
		}

		i += len + 1;

		/* add id => name to hash table */
		hash_table_insert(ilist->mailbox_names, POINTER_CAST(id), name);
		ilist->highest_name_id = id;
	}
	i_assert(i == size);
	return ret;
}

static void
mailbox_list_index_generate_name(struct mailbox_list_index *ilist,
				 struct mailbox_list_index_node *node,
				 const char *prefix)
{
	guid_128_t guid;
	char *name;

	i_assert(node->name_id != 0);

	guid_128_generate(guid);
	name = p_strdup_printf(ilist->mailbox_pool, "%s%s", prefix,
			       guid_128_to_string(guid));
	node->raw_name = name;
	node->flags |= MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME;

	hash_table_insert(ilist->mailbox_names,
			  POINTER_CAST(node->name_id), name);
	if (ilist->highest_name_id < node->name_id)
		ilist->highest_name_id = node->name_id;
}

static int mailbox_list_index_node_cmp(const struct mailbox_list_index_node *n1,
				       const struct mailbox_list_index_node *n2)
{
	return  n1->parent == n2->parent &&
		strcmp(n1->raw_name, n2->raw_name) == 0 ? 0 : -1;
}

static unsigned int
mailbox_list_index_node_hash(const struct mailbox_list_index_node *node)
{
	return str_hash(node->raw_name) ^
		POINTER_CAST_TO(node->parent, unsigned int);
}

static bool node_has_parent(const struct mailbox_list_index_node *parent,
			    const struct mailbox_list_index_node *node)
{
	const struct mailbox_list_index_node *n;

	for (n = parent; n != NULL; n = n->parent) {
		if (n == node)
			return TRUE;
	}
	return FALSE;
}

static int mailbox_list_index_parse_records(struct mailbox_list_index *ilist,
					    struct mail_index_view *view,
					    const char **error_r)
{
	struct mailbox_list_index_node *node, *parent;
	HASH_TABLE(struct mailbox_list_index_node *,
		   struct mailbox_list_index_node *) duplicate_hash;
	const struct mail_index_record *rec;
	const struct mailbox_list_index_record *irec;
	const void *data;
	bool expunged;
	uint32_t seq, uid, count;
	HASH_TABLE(uint8_t *, struct mailbox_list_index_node *) duplicate_guid;

	*error_r = NULL;

	pool_t dup_pool =
		pool_alloconly_create(MEMPOOL_GROWING"duplicate pool", 2048);
	hash_table_create(&duplicate_hash, dup_pool, 0,
			  mailbox_list_index_node_hash,
			  mailbox_list_index_node_cmp);
	count = mail_index_view_get_messages_count(view);
	if (!ilist->has_backing_store)
		hash_table_create(&duplicate_guid, dup_pool, 0, guid_128_hash,
				  guid_128_cmp);

	for (seq = 1; seq <= count; seq++) {
		node = p_new(ilist->mailbox_pool,
			     struct mailbox_list_index_node, 1);
		rec = mail_index_lookup(view, seq);
		node->uid = rec->uid;
		node->flags = rec->flags;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		if (data == NULL) {
			*error_r = "Missing list extension data";
			/* list index is missing, no point trying
			   to do second scan either */
			count = 0;
			break;
		}
		irec = data;

		node->name_id = irec->name_id;
		if (node->name_id == 0) {
			/* invalid name_id - assign a new one */
			node->name_id = ++ilist->highest_name_id;
			node->corrupted_ext = TRUE;
		}
		node->raw_name = hash_table_lookup(ilist->mailbox_names,
					       POINTER_CAST(irec->name_id));
		if (node->raw_name == NULL) {
			*error_r = t_strdup_printf(
				"name_id=%u not in index header", irec->name_id);
			if (ilist->has_backing_store)
				break;
			/* generate a new name and use it */
			mailbox_list_index_generate_name(ilist, node, "unknown-");
		}

		if (!ilist->has_backing_store && guid_128_is_empty(irec->guid) &&
		    (rec->flags & (MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
				   MAILBOX_LIST_INDEX_FLAG_NOSELECT)) == 0) {
			/* no backing store and mailbox has no GUID.
			   it can't be selectable, but the flag is missing. */
			node->flags |= MAILBOX_LIST_INDEX_FLAG_NOSELECT;
			*error_r = t_strdup_printf(
				"mailbox '%s' (uid=%u) is missing GUID - "
				"marking it non-selectable", node->raw_name, node->uid);
			node->corrupted_flags = TRUE;
		}
		if (!ilist->has_backing_store && !guid_128_is_empty(irec->guid) &&
		    (rec->flags & (MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
				   MAILBOX_LIST_INDEX_FLAG_NOSELECT)) != 0) {
			node->flags &= ENUM_NEGATE(MAILBOX_LIST_INDEX_FLAG_NONEXISTENT | MAILBOX_LIST_INDEX_FLAG_NOSELECT);
			*error_r = t_strdup_printf(
				"non-selectable mailbox '%s' (uid=%u) already has GUID - "
				"marking it selectable", node->raw_name, node->uid);
			node->corrupted_flags = TRUE;
		}

		if (!ilist->has_backing_store && !guid_128_is_empty(irec->guid)) {
			struct mailbox_list_index_node *dup_node;
			uint8_t *guid_p = p_memdup(dup_pool, irec->guid,
						   sizeof(guid_128_t));
			if ((dup_node = hash_table_lookup(duplicate_guid, guid_p)) != NULL) {
				*error_r = t_strdup_printf(
						"duplicate GUID %s for mailbox '%s' and '%s'",
						guid_128_to_string(guid_p),
						node->raw_name,
						dup_node->raw_name);
				node->corrupted_ext = TRUE;
				ilist->corrupted_names_or_parents = TRUE;
				ilist->call_corruption_callback = TRUE;
			} else {
				hash_table_insert(duplicate_guid, guid_p, node);
			}
		}

		hash_table_insert(ilist->mailbox_hash,
				  POINTER_CAST(node->uid), node);
	}

	/* do a second scan to create the actual mailbox tree hierarchy.
	   this is needed because the parent_uid may be smaller or higher than
	   the current node's uid */
	if (*error_r != NULL && ilist->has_backing_store)
		count = 0;
	for (seq = 1; seq <= count; seq++) {
		mail_index_lookup_uid(view, seq, &uid);
		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		irec = data;

		node = mailbox_list_index_lookup_uid(ilist, uid);
		i_assert(node != NULL);

		if (irec->parent_uid != 0) {
			/* node should have a parent */
			parent = mailbox_list_index_lookup_uid(ilist,
							       irec->parent_uid);
			if (parent == NULL) {
				*error_r = t_strdup_printf(
					"parent_uid=%u points to nonexistent record",
					irec->parent_uid);
				if (ilist->has_backing_store)
					break;
				/* just place it under the root */
				node->corrupted_ext = TRUE;
			} else if (node_has_parent(parent, node)) {
				*error_r = t_strdup_printf(
					"parent_uid=%u loops to node itself (%s)",
					uid, node->raw_name);
				if (ilist->has_backing_store)
					break;
				/* just place it under the root */
				node->corrupted_ext = TRUE;
			} else {
				node->parent = parent;
				node->next = parent->children;
				parent->children = node;
			}
		} else if (strcasecmp(node->raw_name, "INBOX") == 0) {
			ilist->rebuild_on_missing_inbox = FALSE;
		}
		if (hash_table_lookup(duplicate_hash, node) == NULL)
			hash_table_insert(duplicate_hash, node, node);
		else {
			const char *old_name = node->raw_name;

			if (ilist->has_backing_store) {
				*error_r = t_strdup_printf(
					"Duplicate mailbox '%s' in index",
					node->raw_name);
				break;
			}

			/* we have only the mailbox list index and this node
			   may have a different GUID, so rename it. */
			node->corrupted_ext = TRUE;
			node->name_id = ++ilist->highest_name_id;
			mailbox_list_index_generate_name(ilist, node,
				t_strconcat(node->raw_name, "-duplicate-", NULL));
			*error_r = t_strdup_printf(
				"Duplicate mailbox '%s' in index, renaming to %s",
				old_name, node->raw_name);
		}
		if (node->parent == NULL) {
			node->next = ilist->mailbox_tree;
			ilist->mailbox_tree = node;
		}
	}
	hash_table_destroy(&duplicate_hash);
	if (!ilist->has_backing_store)
		hash_table_destroy(&duplicate_guid);
	pool_unref(&dup_pool);
	return *error_r == NULL ? 0 : -1;
}

int mailbox_list_index_parse(struct mailbox_list *list,
			     struct mail_index_view *view, bool force)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	const struct mail_index_header *hdr;
	const char *error;

	hdr = mail_index_get_header(view);
	if (!force &&
	    hdr->log_file_seq == ilist->sync_log_file_seq &&
	    hdr->log_file_head_offset == ilist->sync_log_file_offset) {
		/* nothing changed */
		return 0;
	}
	if ((hdr->flags & MAIL_INDEX_HDR_FLAG_FSCKD) != 0) {
		mailbox_list_set_critical(list,
			"Mailbox list index was marked as fsck'd %s", ilist->path);
		ilist->call_corruption_callback = TRUE;
	}

	mailbox_list_index_reset(ilist);
	ilist->sync_log_file_seq = hdr->log_file_seq;
	ilist->sync_log_file_offset = hdr->log_file_head_offset;

	if (mailbox_list_index_parse_header(ilist, view) < 0) {
		mailbox_list_set_critical(list,
			"Corrupted mailbox list index header %s", ilist->path);
		if (ilist->has_backing_store) {
			mail_index_mark_corrupted(ilist->index);
			return -1;
		}
		ilist->call_corruption_callback = TRUE;
		ilist->corrupted_names_or_parents = TRUE;
	}
	if (mailbox_list_index_parse_records(ilist, view, &error) < 0) {
		mailbox_list_set_critical(list,
			"Corrupted mailbox list index %s: %s",
			ilist->path, error);
		if (ilist->has_backing_store) {
			mail_index_mark_corrupted(ilist->index);
			return -1;
		}
		ilist->call_corruption_callback = TRUE;
		ilist->corrupted_names_or_parents = TRUE;
	}
	return 0;
}

const unsigned char *
mailbox_name_hdr_encode(struct mailbox_list *list, const char *storage_name,
			size_t *name_len_r)
{
	const char sep[] = {
		mailbox_list_get_hierarchy_sep(list),
		'\0'
	};
	const char **name_parts =
		(const char **)p_strsplit(unsafe_data_stack_pool, storage_name, sep);
	if (list->set.storage_name_escape_char != '\0') {
		for (unsigned int i = 0; name_parts[i] != NULL; i++) {
			mailbox_list_name_unescape(&name_parts[i],
				list->set.storage_name_escape_char);
		}
	}

	i_assert(name_parts[0] != NULL);
	string_t *str = t_str_new(64);
	str_append(str, name_parts[0]);
	for (unsigned int i = 1; name_parts[i] != NULL; i++) {
		str_append_c(str, '\0');
		str_append(str, name_parts[i]);
	}
	*name_len_r = str_len(str);
	return str_data(str);
}

const char *
mailbox_name_hdr_decode_storage_name(struct mailbox_list *list,
				     const unsigned char *name_hdr,
				     size_t name_hdr_size)
{
	const char list_sep = mailbox_list_get_hierarchy_sep(list);
	const char escape_char = list->set.storage_name_escape_char;
	string_t *storage_name = t_str_new(name_hdr_size);
	while (name_hdr_size > 0) {
		const unsigned char *p = memchr(name_hdr, '\0', name_hdr_size);
		size_t name_part_len;
		if (p == NULL) {
			name_part_len = name_hdr_size;
			name_hdr_size = 0;
		} else {
			name_part_len = p - name_hdr;
			i_assert(name_hdr_size > name_part_len);
			name_hdr_size -= name_part_len + 1;
		}

		if (escape_char == '\0')
			str_append_data(storage_name, name_hdr, name_part_len);
		else {
			const char *name_part =
				t_strndup(name_hdr, name_part_len);
			str_append(storage_name,
				   mailbox_list_escape_name_params(name_part,
					"", '\0', list_sep, escape_char,
					list->set.maildir_name));
		}

		if (p != NULL) {
			name_hdr += name_part_len + 1;
			str_append_c(storage_name, list_sep);
		}
	}
	return str_c(storage_name);
}

bool mailbox_list_index_need_refresh(struct mailbox_list_index *ilist,
				     struct mail_index_view *view)
{
	const struct mailbox_list_index_header *hdr;
	const void *data;
	size_t size;

	if (!ilist->has_backing_store)
		return FALSE;

	mail_index_get_header_ext(view, ilist->ext_id, &data, &size);
	hdr = data;
	return hdr != NULL && hdr->refresh_flag != 0;
}

int mailbox_list_index_refresh(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	if (ilist->syncing)
		return 0;
	if (ilist->last_refresh_timeval.tv_usec == ioloop_timeval.tv_usec &&
	    ilist->last_refresh_timeval.tv_sec == ioloop_timeval.tv_sec) {
		/* we haven't been to ioloop since last refresh, skip checking
		   it. when we're accessing many mailboxes at once (e.g.
		   opening a virtual mailbox) we don't want to stat/read the
		   index every single time. */
		return ilist->last_refresh_success ? 0 : -1;
	}

	return mailbox_list_index_refresh_force(list);
}

int mailbox_list_index_refresh_force(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mail_index_view *view;
	int ret;
	bool refresh, handle_corruption = TRUE;

	i_assert(!ilist->syncing);

	if (mailbox_list_index_index_open(list) < 0)
		return -1;
	if (mail_index_refresh(ilist->index) < 0) {
		mailbox_list_index_set_index_error(list);
		return -1;
	}

	view = mail_index_view_open(ilist->index);
	if ((refresh = mailbox_list_index_need_refresh(ilist, view)) ||
	    ilist->mailbox_tree == NULL) {
		/* refresh list of mailboxes */
		ret = mailbox_list_index_sync(list, refresh);
		if (ret < 0) {
			/* I/O failure - don't try to handle corruption,
			   since we don't have the latest state. */
			handle_corruption = FALSE;
		}
	} else {
		ret = mailbox_list_index_parse(list, view, FALSE);
	}
	mail_index_view_close(&view);

	if (handle_corruption &&
	    mailbox_list_index_handle_corruption(list) < 0) {
		const char *errstr;
		enum mail_error error;

		errstr = mailbox_list_get_last_internal_error(list, &error);
		mailbox_list_set_error(list, error, t_strdup_printf(
			"Failed to rebuild mailbox list index: %s", errstr));
		ret = -1;
	}
	ilist->last_refresh_timeval = ioloop_timeval;
	ilist->last_refresh_success = (ret == 0);
	return ret;
}

static void mailbox_list_index_refresh_timeout(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	timeout_remove(&ilist->to_refresh);
	(void)mailbox_list_index_refresh(list);
}

void mailbox_list_index_refresh_later(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_index_header new_hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;

	memset(&ilist->last_refresh_timeval, 0,
	       sizeof(ilist->last_refresh_timeval));

	if (!ilist->has_backing_store)
		return;

	(void)mailbox_list_index_index_open(list);

	view = mail_index_view_open(ilist->index);
	if (!mailbox_list_index_need_refresh(ilist, view)) {
		new_hdr.refresh_flag = 1;

		trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
		mail_index_update_header_ext(trans, ilist->ext_id,
			offsetof(struct mailbox_list_index_header, refresh_flag),
			&new_hdr.refresh_flag, sizeof(new_hdr.refresh_flag));
		if (mail_index_transaction_commit(&trans) < 0)
			mail_index_mark_corrupted(ilist->index);

	}
	mail_index_view_close(&view);

	if (ilist->to_refresh == NULL) {
		ilist->to_refresh =
			timeout_add(MAILBOX_LIST_INDEX_REFRESH_DELAY_MSECS,
				    mailbox_list_index_refresh_timeout, list);
	}
}

static int
list_handle_corruption_locked(struct mailbox_list *list,
			      enum mail_storage_list_index_rebuild_reason reason)
{
	struct mail_storage *storage;
	const char *errstr;
	enum mail_error error;

	array_foreach_elem(&list->ns->all_storages, storage) {
		if (storage->v.list_index_rebuild == NULL)
			continue;

		if (storage->v.list_index_rebuild(storage, reason) < 0) {
			errstr = mail_storage_get_last_internal_error(storage, &error);
			mailbox_list_set_error(list, error, errstr);
			return -1;
		} else {
			/* FIXME: implement a generic handler that
			   just lists mailbox directories in filesystem
			   and adds the missing ones to the index. */
		}
	}
	return mailbox_list_index_set_uncorrupted(list);
}

int mailbox_list_index_handle_corruption(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	enum mail_storage_list_index_rebuild_reason reason;
	int ret;

	if (ilist->call_corruption_callback)
		reason = MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_CORRUPTED;
	else if (ilist->rebuild_on_missing_inbox)
		reason = MAIL_STORAGE_LIST_INDEX_REBUILD_REASON_NO_INBOX;
	else
		return 0;

	if (list->disable_rebuild_on_corruption)
		return 0;

	/* make sure we don't recurse */
	if (ilist->handling_corruption)
		return 0;
	ilist->handling_corruption = TRUE;

	/* Perform the rebuilding locked. Note that if we're here because
	   INBOX wasn't found, this may be because another process is in the
	   middle of creating it. Waiting for the lock here makes sure that
	   we don't start rebuilding before it's finished. In that case the
	   rebuild is a bit unnecessary, but harmless (and avoiding the rebuild
	   just adds extra code complexity). */
	if (mailbox_list_lock(list) < 0)
		ret = -1;
	else {
		ret = list_handle_corruption_locked(list, reason);
		mailbox_list_unlock(list);
	}
	ilist->handling_corruption = FALSE;
	return ret;
}

int mailbox_list_index_set_uncorrupted(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_index_sync_context *sync_ctx;

	ilist->call_corruption_callback = FALSE;
	ilist->rebuild_on_missing_inbox = FALSE;

	if (mailbox_list_index_sync_begin(list, &sync_ctx) < 0)
		return -1;

	mail_index_unset_fscked(sync_ctx->trans);
	return mailbox_list_index_sync_end(&sync_ctx, TRUE);
}

bool mailbox_list_index_get_index(struct mailbox_list *list,
				  struct mail_index **index_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	if (ilist == NULL)
		return FALSE;
	*index_r = ilist->index;
	return TRUE;
}

int mailbox_list_index_view_open(struct mailbox *box, bool require_refreshed,
				 struct mail_index_view **view_r,
				 uint32_t *seq_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mailbox_list_index_node *node;
	struct mail_index_view *view;
	const char *reason = NULL;
	uint32_t seq;
	int ret;

	if (ilist == NULL) {
		/* mailbox list indexes aren't enabled */
		return 0;
	}
	if (MAILBOX_IS_NEVER_IN_INDEX(box) && require_refreshed) {
		/* Optimization: Caller wants the list index to be up-to-date
		   for this mailbox, but this mailbox isn't updated to the list
		   index at all. */
		return 0;
	}
	if (mailbox_list_index_refresh(box->list) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}

	node = mailbox_list_index_lookup(box->list, box->name);
	if (node == NULL) {
		/* mailbox not found */
		e_debug(box->event, "Couldn't open mailbox in list index: "
			"Mailbox not found");
		return 0;
	}

	view = mail_index_view_open(ilist->index);
	if (mailbox_list_index_need_refresh(ilist, view)) {
		/* mailbox_list_index_refresh_later() was called.
		   Can't trust the index's contents. */
		reason = "Refresh-flag set";
		ret = 1;
	} else if (!mail_index_lookup_seq(view, node->uid, &seq)) {
		/* our in-memory tree is out of sync */
		ret = 1;
		reason = "Mailbox no longer exists in index";
	} else if (!require_refreshed) {
		/* this operation doesn't need the index to be up-to-date */
		ret = 0;
	} else {
		ret = box->v.list_index_has_changed == NULL ? 0 :
			box->v.list_index_has_changed(box, view, seq, FALSE,
						      &reason);
		i_assert(ret <= 0 || reason != NULL);
	}

	if (ret != 0) {
		/* error / mailbox has changed. we'll need to sync it. */
		if (ret < 0)
			mailbox_list_index_refresh_later(box->list);
		else {
			i_assert(reason != NULL);
			e_debug(box->event,
				"Couldn't open mailbox in list index: %s",
				reason);
			ilist->index_last_check_changed = TRUE;
		}
		mail_index_view_close(&view);
		return ret < 0 ? -1 : 0;
	}

	*view_r = view;
	*seq_r = seq;
	return 1;
}

static void mailbox_list_index_deinit(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	timeout_remove(&ilist->to_refresh);
	if (ilist->index != NULL) {
		hash_table_destroy(&ilist->mailbox_hash);
		hash_table_destroy(&ilist->mailbox_names);
		pool_unref(&ilist->mailbox_pool);
		if (ilist->opened)
			mail_index_close(ilist->index);
		mail_index_free(&ilist->index);
	}
	ilist->module_ctx.super.deinit(list);
}

static void
mailbox_list_index_refresh_if_found(struct mailbox_list *list,
				    const char *name, bool selectable)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
	struct mailbox_list_index_node *node;

	if (ilist->syncing)
		return;

	mailbox_list_last_error_push(list);
	(void)mailbox_list_index_refresh_force(list);
	node = mailbox_list_index_lookup(list, name);
	if (node != NULL &&
	    (!selectable ||
	     (node->flags & (MAILBOX_LIST_INDEX_FLAG_NONEXISTENT |
			     MAILBOX_LIST_INDEX_FLAG_NOSELECT)) == 0)) {
		/* index is out of sync - refresh */
		mailbox_list_index_refresh_later(list);
	}
	mailbox_list_last_error_pop(list);
}

static void mailbox_list_index_refresh_if_not_found(struct mailbox_list *list,
						    const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	if (ilist->syncing)
		return;

	mailbox_list_last_error_push(list);
	(void)mailbox_list_index_refresh_force(list);
	if (mailbox_list_index_lookup(list, name) == NULL) {
		/* index is out of sync - refresh */
		mailbox_list_index_refresh_later(list);
	}
	mailbox_list_last_error_pop(list);
}

static int mailbox_list_index_open_mailbox(struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.open(box) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND)
			mailbox_list_index_refresh_if_found(box->list, box->name, TRUE);
		return -1;
	}
	return 0;
}

static int
mailbox_list_index_create_mailbox(struct mailbox *box,
				  const struct mailbox_update *update,
				  bool directory)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.create_box(box, update, directory) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_EXISTS)
			mailbox_list_index_refresh_if_not_found(box->list, box->name);
		return -1;
	}
	mailbox_list_index_refresh_later(box->list);
	return 0;
}

static int
mailbox_list_index_update_mailbox(struct mailbox *box,
				  const struct mailbox_update *update)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.update_box(box, update) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND)
			mailbox_list_index_refresh_if_found(box->list, box->name, TRUE);
		return -1;
	}

	mailbox_list_index_update_mailbox_index(box, update);
	return 0;
}

static int
mailbox_list_index_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	if (ilist->module_ctx.super.delete_mailbox(list, name) < 0) {
		if (mailbox_list_get_last_mail_error(list) == MAIL_ERROR_NOTFOUND)
			mailbox_list_index_refresh_if_found(list, name, FALSE);
		return -1;
	}
	mailbox_list_index_refresh_later(list);
	return 0;
}

static int
mailbox_list_index_delete_dir(struct mailbox_list *list, const char *name)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	if (ilist->module_ctx.super.delete_dir(list, name) < 0) {
		if (mailbox_list_get_last_mail_error(list) == MAIL_ERROR_NOTFOUND)
			mailbox_list_index_refresh_if_found(list, name, FALSE);
		return -1;
	}
	mailbox_list_index_refresh_later(list);
	return 0;
}

static int
mailbox_list_index_rename_mailbox(struct mailbox_list *oldlist,
				  const char *oldname,
				  struct mailbox_list *newlist,
				  const char *newname)
{
	struct mailbox_list_index *oldilist = INDEX_LIST_CONTEXT_REQUIRE(oldlist);

	if (oldilist->module_ctx.super.rename_mailbox(oldlist, oldname,
						      newlist, newname) < 0) {
		if (mailbox_list_get_last_mail_error(oldlist) == MAIL_ERROR_NOTFOUND)
			mailbox_list_index_refresh_if_found(oldlist, oldname, FALSE);
		if (mailbox_list_get_last_mail_error(newlist) == MAIL_ERROR_EXISTS)
			mailbox_list_index_refresh_if_not_found(newlist, newname);
		return -1;
	}
	mailbox_list_index_refresh_later(oldlist);
	if (oldlist != newlist)
		mailbox_list_index_refresh_later(newlist);
	return 0;
}

static int
mailbox_list_index_set_subscribed(struct mailbox_list *_list,
				  const char *name, bool set)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(_list);
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const void *data;
	size_t size;
	uint32_t counter;

	if (ilist->module_ctx.super.set_subscribed(_list, name, set) < 0)
		return -1;

	/* update the "subscriptions changed" counter/timestamp. its purpose
	   is to trigger NOTIFY watcher to handle SubscriptionChange events */
	if (mailbox_list_index_index_open(_list) < 0)
		return -1;
	view = mail_index_view_open(ilist->index);
	mail_index_get_header_ext(view, ilist->subs_hdr_ext_id, &data, &size);
	if (size != sizeof(counter))
		counter = ioloop_time32;
	else {
		memcpy(&counter, data, size);
		if (++counter < ioloop_time32)
			counter = ioloop_time32;
	}

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header_ext(trans, ilist->subs_hdr_ext_id,
				     0, &counter, sizeof(counter));
	(void)mail_index_transaction_commit(&trans);
	mail_index_view_close(&view);
	return 0;
}

static bool mailbox_list_index_is_enabled(struct mailbox_list *list)
{
	if (!list->mail_set->mailbox_list_index ||
	    (list->props & MAILBOX_LIST_PROP_NO_LIST_INDEX) != 0)
		return FALSE;

	i_assert(list->set.list_index_fname != NULL);
	if (list->set.list_index_fname[0] == '\0')
		return FALSE;
	return TRUE;
}

static void mailbox_list_index_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct mailbox_list_index *ilist;
	bool has_backing_store;

	/* layout=index doesn't have any backing store */
	has_backing_store = strcmp(list->name, MAILBOX_LIST_NAME_INDEX) != 0;

	if (!mailbox_list_index_is_enabled(list)) {
		/* reserve the module context anyway, so syncing code knows
		   that the index is disabled */
		i_assert(has_backing_store);
		ilist = NULL;
		MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);
		return;
	}

	ilist = p_new(list->pool, struct mailbox_list_index, 1);
	ilist->module_ctx.super = *v;
	list->vlast = &ilist->module_ctx.super;
	ilist->has_backing_store = has_backing_store;
	ilist->pending_init = TRUE;

	v->deinit = mailbox_list_index_deinit;
	v->iter_init = mailbox_list_index_iter_init;
	v->iter_deinit = mailbox_list_index_iter_deinit;
	v->iter_next = mailbox_list_index_iter_next;

	v->delete_mailbox = mailbox_list_index_delete_mailbox;
	v->delete_dir = mailbox_list_index_delete_dir;
	v->rename_mailbox = mailbox_list_index_rename_mailbox;
	v->set_subscribed = mailbox_list_index_set_subscribed;

	v->notify_init = mailbox_list_index_notify_init;
	v->notify_next = mailbox_list_index_notify_next;
	v->notify_deinit = mailbox_list_index_notify_deinit;
	v->notify_wait = mailbox_list_index_notify_wait;
	v->notify_flush = mailbox_list_index_notify_flush;

	MODULE_CONTEXT_SET(list, mailbox_list_index_module, ilist);

	if ((list->flags & MAILBOX_LIST_FLAG_SECONDARY) != 0) {
		/* secondary lists aren't accessible via namespaces, so we
		   need to finish them now. */
		mailbox_list_index_init_finish(list);
	}
}

static void mailbox_list_index_init_finish(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const char *dir;

	if (ilist == NULL || !ilist->pending_init)
		return;
	ilist->pending_init = FALSE;

	/* we've delayed this part of the initialization so that mbox format
	   can override the index root directory path */
	if (!mailbox_list_get_root_path(list, MAILBOX_LIST_PATH_TYPE_LIST_INDEX,
					&dir)) {
		/* in-memory indexes */
		dir = NULL;
	}
	i_assert(ilist->has_backing_store || dir != NULL);

	i_assert(list->set.list_index_fname != NULL);
	ilist->path = dir == NULL ? "(in-memory mailbox list index)" :
		p_strdup_printf(list->pool, "%s/%s", dir, list->set.list_index_fname);
	ilist->index = mail_index_alloc(list->ns->user->event,
					dir, list->set.list_index_fname);
	ilist->rebuild_on_missing_inbox = !ilist->has_backing_store &&
		(list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0;

	ilist->ext_id = mail_index_ext_register(ilist->index, "list",
				sizeof(struct mailbox_list_index_header),
				sizeof(struct mailbox_list_index_record),
				sizeof(uint32_t));
	ilist->subs_hdr_ext_id = mail_index_ext_register(ilist->index, "subs",
							 sizeof(uint32_t), 0,
							 sizeof(uint32_t));
	mailbox_list_index_init_pool(ilist);

	mailbox_list_index_status_init_finish(list);
}

static void
mailbox_list_index_namespaces_added(struct mail_namespace *namespaces)
{
	struct mail_namespace *ns;

	for (ns = namespaces; ns != NULL; ns = ns->next)
		mailbox_list_index_init_finish(ns->list);
}

static struct mailbox_sync_context *
mailbox_list_index_sync_init(struct mailbox *box,
			     enum mailbox_sync_flags flags)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	mailbox_list_index_status_sync_init(box);
	if (!ibox->have_backend)
		mailbox_list_index_backend_sync_init(box, flags);
	return ibox->module_ctx.super.sync_init(box, flags);
}

static int
mailbox_list_index_sync_deinit(struct mailbox_sync_context *ctx,
			       struct mailbox_sync_status *status_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(ctx->box);
	struct mailbox *box = ctx->box;

	if (ibox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	mailbox_list_index_status_sync_deinit(box);
	if (ibox->have_backend)
		return mailbox_list_index_backend_sync_deinit(box);
	else
		return 0;
}

static void mailbox_list_index_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct index_list_mailbox *ibox;

	if (ilist == NULL)
		return;

	ibox = p_new(box->pool, struct index_list_mailbox, 1);
	ibox->module_ctx.super = *v;
	box->vlast = &ibox->module_ctx.super;
	MODULE_CONTEXT_SET(box, index_list_storage_module, ibox);

	/* for layout=index these get overridden */
	v->open = mailbox_list_index_open_mailbox;
	v->create_box = mailbox_list_index_create_mailbox;
	v->update_box = mailbox_list_index_update_mailbox;

	/* These are used by both status and backend code, but they can't both
	   be overriding the same function pointer since they share the
	   super pointer. */
	v->sync_init = mailbox_list_index_sync_init;
	v->sync_deinit = mailbox_list_index_sync_deinit;

	mailbox_list_index_status_init_mailbox(v);
	ibox->have_backend = mailbox_list_index_backend_init_mailbox(box, v);
}

static struct mail_storage_hooks mailbox_list_index_hooks = {
	.mailbox_list_created = mailbox_list_index_created,
	.mail_namespaces_added = mailbox_list_index_namespaces_added,
	.mailbox_allocated = mailbox_list_index_mailbox_allocated
};

void mailbox_list_index_init(void); /* called in mailbox-list-register.c */

void mailbox_list_index_init(void)
{
	mail_storage_hooks_add_internal(&mailbox_list_index_hooks);
}
