/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ioloop.h"
#include "str.h"
#include "imap-parser.h"
#include "mkdir-parents.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mailbox-list-private.h"
#include "index-storage.h"
#include "index-mail.h"
#include "index-thread-private.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* How many seconds to keep index opened for reuse after it's been closed */
#define INDEX_CACHE_TIMEOUT 10
/* How many closed indexes to keep */
#define INDEX_CACHE_MAX 3

#define LOCK_NOTIFY_INTERVAL 30

struct index_list {
	union mail_index_module_context module_ctx;
	struct index_list *next;

	struct mail_index *index;
	char *mailbox_path;
	int refcount;

	dev_t index_dir_dev;
	ino_t index_dir_ino;

	time_t destroy_time;
};

static struct index_list *indexes = NULL;
static struct timeout *to_index = NULL;

static struct index_list *
index_storage_add(struct mail_index *index,
		  const char *mailbox_path, struct stat *st)
{
	struct index_list *list;

	list = i_new(struct index_list, 1);
	list->refcount = 1;
	list->index = index;

	list->mailbox_path = i_strdup(mailbox_path);
	list->index_dir_dev = st->st_dev;
	list->index_dir_ino = st->st_ino;

	list->next = indexes;
	indexes = list;

	MODULE_CONTEXT_SET(index, mail_storage_mail_index_module, list);
	return list;
}

static void index_list_free(struct index_list *list)
{
	mail_index_free(&list->index);
	i_free(list->mailbox_path);
	i_free(list);
}

int index_list_create_missing_index_dir(struct mailbox_list *list,
					const char *name)
{
	const char *root_dir, *index_dir, *p, *parent_dir;
	const char *origin, *parent_origin;
	mode_t mode, parent_mode;
	gid_t gid, parent_gid;
	int n = 0;

	root_dir = mailbox_list_get_path(list, name,
					 MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = mailbox_list_get_path(list, name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (strcmp(index_dir, root_dir) == 0 || *index_dir == '\0')
		return 0;

	mailbox_list_get_dir_permissions(list, name, &mode, &gid, &origin);
	while (mkdir_chgrp(index_dir, mode, gid, origin) < 0) {
		if (errno == EEXIST)
			break;

		p = strrchr(index_dir, '/');
		if (errno != ENOENT || p == NULL || ++n == 2) {
			mailbox_list_set_critical(list,
				"mkdir(%s) failed: %m", index_dir);
			return -1;
		}
		/* create the parent directory first */
		mailbox_list_get_dir_permissions(list, NULL, &parent_mode,
						 &parent_gid, &parent_origin);
		parent_dir = t_strdup_until(index_dir, p);
		if (mkdir_parents_chgrp(parent_dir, parent_mode,
					parent_gid, parent_origin) < 0 &&
		    errno != EEXIST) {
			mailbox_list_set_critical(list,
				"mkdir(%s) failed: %m", parent_dir);
			return -1;
		}
	}
	return 0;
}

static const char *
get_index_dir(struct mailbox_list *list, const char *name,
	      enum mailbox_flags flags, struct stat *st_r)
{
	const char *index_dir;

	index_dir = (flags & MAILBOX_FLAG_NO_INDEX_FILES) != 0 ? "" :
		mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*index_dir == '\0') {
		/* disabled */
		return NULL;
	}

	if (stat(index_dir, st_r) < 0) {
		if (errno == ENOENT) {
			/* it'll be created later */
			memset(st_r, 0, sizeof(*st_r));
			return index_dir;
		}
		if (errno == EACCES) {
			mailbox_list_set_critical(list, "%s",
				mail_error_eacces_msg("stat", index_dir));
			return NULL;
		}

		mailbox_list_set_critical(list, "stat(%s) failed: %m",
					  index_dir);
		return NULL;
	}
	return index_dir;
}

static struct mail_index *
index_storage_alloc(struct mailbox_list *list, const char *name,
		    enum mailbox_flags flags, const char *prefix)
{
	struct index_list **indexp, *rec, *match;
	struct stat st, st2;
	const char *index_dir, *mailbox_path;
	int destroy_count;

	mailbox_path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = get_index_dir(list, name, flags, &st);

	if (index_dir == NULL)
		memset(&st, 0, sizeof(st));

	/* compare index_dir inodes so we don't break even with symlinks.
	   if index_dir doesn't exist yet or if using in-memory indexes, just
	   compare mailbox paths */
	destroy_count = 0; match = NULL;
	for (indexp = &indexes; *indexp != NULL;) {
		rec = *indexp;

		if (match != NULL) {
			/* already found the index. we're just going through
			   the rest of them to drop 0 refcounts */
		} else if (index_dir != NULL && rec->index_dir_ino != 0) {
			if (st.st_ino == rec->index_dir_ino &&
			    CMP_DEV_T(st.st_dev, rec->index_dir_dev)) {
				/* make sure the directory still exists.
				   it might have been renamed and we're trying
				   to access it via its new path now. */
				if (stat(rec->index->dir, &st2) < 0 ||
				    st2.st_ino != st.st_ino ||
				    !CMP_DEV_T(st2.st_dev, st.st_dev))
					rec->destroy_time = 0;
				else
					match = rec;
			}
		} else {
			if (strcmp(mailbox_path, rec->mailbox_path) == 0)
				match = rec;
		}

		if (rec->refcount == 0 && rec != match) {
			if (rec->destroy_time <= ioloop_time ||
			    destroy_count >= INDEX_CACHE_MAX) {
				*indexp = rec->next;
				index_list_free(rec);
				continue;
			} else {
				destroy_count++;
			}
		}

                indexp = &(*indexp)->next;
	}

	if (match == NULL) {
		match = index_storage_add(mail_index_alloc(index_dir, prefix),
					  mailbox_path, &st);
	} else {
		match->refcount++;
	}
	i_assert(match->index != NULL);
	return match->index;
}

static void destroy_unrefed(bool all)
{
	struct index_list **list, *rec;

	for (list = &indexes; *list != NULL;) {
		rec = *list;

		if (rec->refcount == 0 &&
		    (all || rec->destroy_time <= ioloop_time)) {
			*list = rec->next;
			index_list_free(rec);
		} else {
			list = &(*list)->next;
		}
	}

	if (indexes == NULL && to_index != NULL)
		timeout_remove(&to_index);
}

static void index_removal_timeout(void *context ATTR_UNUSED)
{
	destroy_unrefed(FALSE);
}

void index_storage_unref(struct mail_index *index)
{
	struct index_list *list;

	for (list = indexes; list != NULL; list = list->next) {
		if (list->index == index)
			break;
	}

	i_assert(list != NULL);
	i_assert(list->refcount > 0);

	list->refcount--;
	list->destroy_time = ioloop_time + INDEX_CACHE_TIMEOUT;
	if (to_index == NULL) {
		to_index = timeout_add(INDEX_CACHE_TIMEOUT*1000/2,
				       index_removal_timeout, NULL);
	}
}

void index_storage_destroy_unrefed(void)
{
	destroy_unrefed(TRUE);
}

void index_storage_destroy(struct mail_storage *storage ATTR_UNUSED)
{
	index_storage_destroy_unrefed();
}

static void set_cache_decisions(const char *set, const char *fields,
				enum mail_cache_decision_type dec)
{
	const char *const *arr;
	int i;

	if (fields == NULL || *fields == '\0')
		return;

	for (arr = t_strsplit_spaces(fields, " ,"); *arr != NULL; arr++) {
		for (i = 0; i < MAIL_INDEX_CACHE_FIELD_COUNT; i++) {
			if (strcasecmp(global_cache_fields[i].name,
				       *arr) == 0) {
				global_cache_fields[i].decision = dec;
				break;
			}
		}
		if (i == MAIL_INDEX_CACHE_FIELD_COUNT) {
			i_error("%s: Invalid cache field name '%s', ignoring ",
				set, *arr);
		}
	}
}

static void index_cache_register_defaults(struct index_mailbox *ibox)
{
	const struct mail_storage_settings *set = ibox->box.storage->set;
	static bool initialized = FALSE;
	struct mail_cache *cache = ibox->cache;

	if (!initialized) {
		initialized = TRUE;

		set_cache_decisions("mail_cache_fields",
				    set->mail_cache_fields,
				    MAIL_CACHE_DECISION_TEMP);
		set_cache_decisions("mail_never_cache_fields",
				    set->mail_never_cache_fields,
				    MAIL_CACHE_DECISION_NO |
				    MAIL_CACHE_DECISION_FORCED);
	}

	ibox->cache_fields = i_malloc(sizeof(global_cache_fields));
	memcpy(ibox->cache_fields, global_cache_fields,
	       sizeof(global_cache_fields));
	mail_cache_register_fields(cache, ibox->cache_fields,
				   MAIL_INDEX_CACHE_FIELD_COUNT);
}

void index_storage_lock_notify(struct index_mailbox *ibox,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left)
{
	struct mail_storage *storage = ibox->box.storage;
	const char *str;
	time_t now;

	/* if notify type changes, print the message immediately */
	now = time(NULL);
	if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE ||
	    ibox->last_notify_type == notify_type) {
		if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE &&
		    notify_type == MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE) {
			/* first override notification, show it */
		} else {
			if (now < ibox->next_lock_notify || secs_left < 15)
				return;
		}
	}

	ibox->next_lock_notify = now + LOCK_NOTIFY_INTERVAL;
        ibox->last_notify_type = notify_type;

	switch (notify_type) {
	case MAILBOX_LOCK_NOTIFY_NONE:
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT:
		if (storage->callbacks.notify_no == NULL)
			break;

		str = t_strdup_printf("Mailbox is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks.notify_no(&ibox->box, str,
					     storage->callback_context);
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE:
		if (storage->callbacks.notify_ok == NULL)
			break;

		str = t_strdup_printf("Stale mailbox lock file detected, "
				      "will override in %u seconds", secs_left);
		storage->callbacks.notify_ok(&ibox->box, str,
					     storage->callback_context);
		break;
	}
}

void index_storage_lock_notify_reset(struct index_mailbox *ibox)
{
	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	ibox->last_notify_type = MAILBOX_LOCK_NOTIFY_NONE;
}

int index_storage_mailbox_open(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct index_list *list = MAIL_STORAGE_CONTEXT(ibox->index);
	enum file_lock_method lock_method =
		box->storage->set->parsed_lock_method;
	enum mail_index_open_flags index_flags;
	const char *index_dir;
	struct stat st;
	int ret;

	i_assert(!box->opened);

	index_flags = ibox->index_flags;
	if (ibox->move_to_memory)
		ibox->index_flags &= ~MAIL_INDEX_OPEN_FLAG_CREATE;

	if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
		if (mail_index_is_in_memory(ibox->index)) {
			mail_storage_set_critical(box->storage,
				"Couldn't create index file");
			return -1;
		}
	}

	if (index_list_create_missing_index_dir(box->list, box->name) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	index_dir = mailbox_list_get_path(box->list, box->name,
					  MAILBOX_LIST_PATH_TYPE_INDEX);
	if (list->index_dir_ino == 0 && *index_dir != '\0') {
		/* newly created index directory. update its stat. */
		if (stat(index_dir, &st) == 0) {
			list->index_dir_ino = st.st_ino;
			list->index_dir_dev = st.st_dev;
		}
	}

	ret = mail_index_open(ibox->index, index_flags, lock_method);
	if (ret <= 0 || ibox->move_to_memory) {
		if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		if (mail_index_move_to_memory(ibox->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now. */
			if (mail_index_open_or_create(ibox->index,
						      index_flags,
						      lock_method) < 0)
				i_panic("in-memory index creation failed");
		}
	}

	ibox->cache = mail_index_get_cache(ibox->index);
	index_cache_register_defaults(ibox);
	ibox->view = mail_index_view_open(ibox->index);
	ibox->keyword_names = mail_index_get_keywords(ibox->index);

	MODULE_CONTEXT_SET_FULL(ibox->view, mail_storage_mail_index_module,
				ibox, &ibox->view_module_ctx);

	box->opened = TRUE;

	index_thread_mailbox_opened(ibox);
	if (hook_mailbox_opened != NULL)
		hook_mailbox_opened(box);
	return 0;
}

void index_storage_mailbox_alloc(struct index_mailbox *ibox, const char *name,
				 struct istream *input,
				 enum mailbox_flags flags,
				 const char *index_prefix)
{
	struct mailbox *box = &ibox->box;
	const char *path;
	gid_t dir_gid;
	const char *origin, *dir_origin;
	string_t *vname;

	if (name != NULL) {
		box->name = p_strdup(box->pool, name);
		vname = t_str_new(128);
		mail_namespace_get_vname(box->storage->user->namespaces,
					 vname, name);
		box->vname = p_strdup(box->pool, str_c(vname));
	} else {
		i_assert(input != NULL);
		box->name = "(read-only input stream)";
		box->vname = box->name;
	}

	if (input != NULL) {
		flags |= MAILBOX_FLAG_READONLY;
		box->input = input;
		i_stream_ref(input);
	}
	box->flags = flags;

	p_array_init(&box->search_results, box->pool, 16);
	array_create(&box->module_contexts,
		     box->pool, sizeof(void *), 5);

	path = mailbox_list_get_path(box->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	ibox->box.path = p_strdup(box->pool, path);

	ibox->index_flags = MAIL_INDEX_OPEN_FLAG_CREATE |
		mail_storage_settings_to_index_flags(box->storage->set);

	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	ibox->index = index_storage_alloc(box->list, name, flags, index_prefix);

	if (box->file_create_mode == 0) {
		mailbox_list_get_permissions(box->list, name,
					     &box->file_create_mode,
					     &box->file_create_gid, &origin);
		box->file_create_gid_origin = p_strdup(box->pool, origin);
		mailbox_list_get_dir_permissions(box->list, name,
						 &box->dir_create_mode,
						 &dir_gid, &dir_origin);
		mail_index_set_permissions(ibox->index,
					   box->file_create_mode,
					   box->file_create_gid, origin);
	}
}

int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	if ((feature & MAILBOX_FEATURE_CONDSTORE) != 0) {
		box->enabled_features |= MAILBOX_FEATURE_CONDSTORE;
		if (!box->opened) {
			if (mailbox_open(box) < 0)
				return -1;
		}
		T_BEGIN {
			mail_index_modseq_enable(ibox->index);
		} T_END;
	}
	return 0;
}

void index_storage_mailbox_close(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	if (ibox->view != NULL)
		mail_index_view_close(&ibox->view);

	index_mailbox_check_remove_all(ibox);
	if (ibox->box.input != NULL)
		i_stream_unref(&ibox->box.input);
	if (ibox->index != NULL)
		index_storage_unref(ibox->index);
	if (array_is_created(&ibox->recent_flags))
		array_free(&ibox->recent_flags);
	i_free(ibox->cache_fields);

	pool_unref(&box->pool);
}

static void
index_storage_mailbox_update_cache_fields(struct index_mailbox *ibox,
					  const struct mailbox_update *update)
{
	const char *const *field_names = update->cache_fields;
	ARRAY_DEFINE(new_fields, struct mail_cache_field);
	const struct mail_cache_field *old_fields;
	struct mail_cache_field field;
	unsigned int i, j, old_count;

	old_fields = mail_cache_register_get_list(ibox->cache,
						  pool_datastack_create(),
						  &old_count);

	/* There shouldn't be many fields, so don't worry about O(n^2). */
	t_array_init(&new_fields, 32);
	for (i = 0; field_names[i] != NULL; i++) {
		/* see if it's an existing field */
		for (j = 0; j < old_count; j++) {
			if (strcmp(field_names[i], old_fields[j].name) == 0)
				break;
		}
		if (j != old_count) {
			field = old_fields[i];
			if (field.decision == MAIL_CACHE_DECISION_NO)
				field.decision = MAIL_CACHE_DECISION_TEMP;
			array_append(&new_fields, &field, 1);
		} else if (strncmp(field_names[i], "hdr.", 4) == 0) {
			/* new header */
			memset(&field, 0, sizeof(field));
			field.name = field_names[i];
			field.type = MAIL_CACHE_FIELD_HEADER;
			field.decision = MAIL_CACHE_DECISION_TEMP;
			array_append(&new_fields, &field, 1);
		} else {
			/* new unknown field. we can't do anything about
			   this since we don't know its type */
		}
	}
	if (array_count(&new_fields) > 0) {
		mail_cache_register_fields(ibox->cache,
					   array_idx_modifiable(&new_fields, 0),
					   array_count(&new_fields));
	}
}

int index_storage_mailbox_update(struct mailbox *box,
				 const struct mailbox_update *update)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	const struct mail_index_header *hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	int ret;

	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (update->cache_fields != NULL)
		index_storage_mailbox_update_cache_fields(ibox, update);

	/* make sure we get the latest index info */
	(void)mail_index_refresh(ibox->index);
	view = mail_index_view_open(ibox->index);
	hdr = mail_index_get_header(view);

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	if (update->uid_validity != 0 &&
	    hdr->uid_validity != update->uid_validity) {
		uint32_t uid_validity = update->uid_validity;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (update->min_next_uid != 0 &&
	    hdr->next_uid < update->min_next_uid) {
		uint32_t next_uid = update->min_next_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}
	if (update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(view) < update->min_highest_modseq) {
		mail_index_update_highest_modseq(trans,
						 update->min_highest_modseq);
	}

	if ((ret = mail_index_transaction_commit(&trans)) < 0)
		mail_storage_set_internal_error(box->storage);
	mail_index_view_close(&view);
	return ret;
}

bool index_storage_is_readonly(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return (box->flags & MAILBOX_FLAG_READONLY) != 0 ||
		ibox->backend_readonly;
}

bool index_storage_allow_new_keywords(struct mailbox *box)
{
	/* FIXME: return FALSE if we're full */
	return !index_storage_is_readonly(box);
}

bool index_storage_is_inconsistent(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;

	return mail_index_view_is_inconsistent(ibox->view);
}

void mail_storage_set_index_error(struct index_mailbox *ibox)
{
	mail_storage_set_internal_error(ibox->box.storage);
	mail_index_reset_error(ibox->index);
}

bool index_keyword_is_valid(struct mailbox *box, const char *keyword,
			    const char **error_r)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	unsigned int i, idx;

	/* if it already exists, skip validity checks */
	if (mail_index_keyword_lookup(ibox->index, keyword, &idx))
		return TRUE;

	if (*keyword == '\0') {
		*error_r = "Empty keywords not allowed";
		return FALSE;
	}

	/* these are IMAP-specific restrictions, but for now IMAP is all we
	   care about */
	for (i = 0; keyword[i] != '\0'; i++) {
		if (IS_ATOM_SPECIAL((unsigned char)keyword[i])) {
			*error_r = "Invalid characters in keyword";
			return FALSE;
		}
		if ((unsigned char)keyword[i] >= 0x80) {
			*error_r = "8bit characters in keyword";
			return FALSE;
		}
	}
	if (i > ibox->box.storage->set->mail_max_keyword_length) {
		*error_r = "Keyword length too long";
		return FALSE;
	}
	return TRUE;
}

static struct mail_keywords *
index_keywords_create_skip(struct index_mailbox *ibox,
			   const char *const keywords[])
{
	ARRAY_DEFINE(valid_keywords, const char *);
	const char *error;

	t_array_init(&valid_keywords, 32);
	for (; *keywords != NULL; keywords++) {
		if (mailbox_keyword_is_valid(&ibox->box, *keywords, &error))
			array_append(&valid_keywords, keywords, 1);
	}
	(void)array_append_space(&valid_keywords); /* NULL-terminate */
	return mail_index_keywords_create(ibox->index, keywords);
}

int index_keywords_create(struct mailbox *_box, const char *const keywords[],
			  struct mail_keywords **keywords_r, bool skip_invalid)
{
	struct index_mailbox *ibox = (struct index_mailbox *)_box;
	const char *error;
	unsigned int i;

	for (i = 0; keywords[i] != NULL; i++) {
		if (mailbox_keyword_is_valid(_box, keywords[i], &error))
			continue;

		if (!skip_invalid) {
			mail_storage_set_error(_box->storage,
					       MAIL_ERROR_PARAMS, error);
			return -1;
		}

		/* found invalid keywords, do this the slow way */
		T_BEGIN {
			*keywords_r = index_keywords_create_skip(ibox,
								 keywords);
		} T_END;
		return 0;
	}

	*keywords_r = mail_index_keywords_create(ibox->index, keywords);
	return 0;
}

struct mail_keywords *
index_keywords_create_from_indexes(struct mailbox *_box,
				   const ARRAY_TYPE(keyword_indexes) *idx)
{
	struct index_mailbox *ibox = (struct index_mailbox *)_box;

	return mail_index_keywords_create_from_indexes(ibox->index, idx);
}

void index_keywords_ref(struct mail_keywords *keywords)
{
	mail_index_keywords_ref(keywords);
}

void index_keywords_unref(struct mail_keywords *keywords)
{
	mail_index_keywords_unref(&keywords);
}

void index_save_context_free(struct mail_save_context *ctx)
{
	i_free_and_null(ctx->from_envelope);
	i_free_and_null(ctx->guid);
	i_free_and_null(ctx->pop3_uidl);
}
