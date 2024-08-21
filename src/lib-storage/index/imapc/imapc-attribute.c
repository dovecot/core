/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-quote.h"
#include "imapc-storage.h"
#include "imapc-attribute.h"

#define DEPTH_INFINITY (-1)
#define DEPTH_NONE     0

#define ITER_CONTAINER(_iter) \
	container_of(_iter, struct imapc_storage_attribute_iter, iter);

enum imapc_attribute_command_enum {
	GETMETADATA = 1,
	SETMETADATA = 2
};

struct imapc_storage_attribute_iter {
	struct mailbox_attribute_iter iter;
	struct imapc_storage_attribute_context *actx;
	struct mailbox_attribute_iter *ictx;
	bool failed:1;
};

static inline struct imapc_storage_attribute_context *
imapc_storage_attribute_context_create(void)
{
	pool_t pool = pool_alloconly_create("imapc storage attribute context", 256);
	struct imapc_storage_attribute_context *actx =
		p_new(pool, struct imapc_storage_attribute_context, 1);
	actx->pool = pool;
	return actx;
}

static void
imapc_storage_attribute_context_destroy(struct imapc_storage_attribute_context **_actx)
{
	struct imapc_storage_attribute_context *actx = *_actx;
	*_actx = NULL;
	pool_unref(&actx->pool);
}

static struct imapc_storage_attribute_iter *imapc_storage_attribute_iter_create()
{
	struct imapc_storage_attribute_context *actx =
		imapc_storage_attribute_context_create();

	struct imapc_storage_attribute_iter *iter =
		p_new(actx->pool, struct imapc_storage_attribute_iter, 1);
	iter->actx = actx;
	return iter;
}

static void
imapc_storage_attribute_iter_destroy(struct imapc_storage_attribute_iter **_iter)
{
	struct imapc_storage_attribute_iter *iter = *_iter;
	imapc_storage_attribute_context_destroy(&iter->actx);
	*_iter = NULL;
}

static void
imapc_storage_attribute_get_cb(const struct imapc_untagged_reply *reply,
			       struct imapc_storage_client *client)
{
        struct imapc_storage_attribute_context *actx =
		client->_storage->cur_attribute_context;
	pool_t pool = actx->pool;

	/* If the 2nd argument is a list, then we are handling the
	   untagged response to the GETMETADATA command we called */
	const struct imap_arg *list;
	unsigned int list_len;
	if (!imap_arg_get_list_full(&reply->args[1], &list, &list_len)) {
		/* ... otherwise this is an unsolicited untagged response,
		       ignore it */
		return;
	}
	if (list_len % 2 != 0 || (!actx->iterating && list_len != 2)) {
		actx->error = p_strdup_printf(pool,
			"attribute's list length is wrong: %d", list_len);
		return;
	}

	const char *mbname;
	if (!imap_arg_get_astring(&reply->args[0], &mbname)) {
		actx->error = "mailbox name missing or not an ASTRING";
		return;
	}

	ARRAY_TYPE(const_string) keys;
	p_array_init(&keys, actx->pool, actx->iterating ? 8 : 1);
	for (; list_len > 0; list += 2, list_len -= 2)  {
		const char *key;
		if (!imap_arg_get_astring(&list[0], &key)) {
			actx->error = "attribute's key is not an ASTRING";
			return;
		}
		if (*key != '/') {
			actx->error = p_strdup_printf(pool,
				"attribute's key doesn't start with '/': %s", key);
			return;
		}
		key = p_strdup(pool, key);
		array_push_back(&keys, &key);

		if (!actx->iterating) {
			const char *value;
			if (!imap_arg_get_nstring(&list[1], &value)) {
				actx->error = "attribute's value is not an nstring";
				return;
			}
			actx->value = p_strdup(pool, value);
		}
	}

	array_append_zero(&keys);
	actx->keys = array_front(&keys);
}

static const char *
imapc_storage_attribute_build_cmd(struct imapc_mailbox *mbox,
				  enum imapc_attribute_command_enum command,
				  int depth,
				  enum mail_attribute_type type_flags,
				  const char *key, const char *value)
{
	const char *mbname = imapc_mailbox_get_remote_name(mbox);
	const char *fkey = t_strdup_printf(
		"/%s/%s", type_flags == MAIL_ATTRIBUTE_TYPE_PRIVATE ?
		"private" : "shared", key);
	fkey = t_str_rtrim(fkey, "/");

	string_t *text = t_str_new(64);
	str_append(text, command == GETMETADATA ? "GETMETADATA" : "SETMETADATA");

	if (command == GETMETADATA) {
		if (depth < 0)
			str_append(text, " (DEPTH infinity)");
		else if (depth > 0)
			str_printfa(text, " (DEPTH %d)", depth);
	}

	str_append_c(text, ' ');
	imap_append_astring(text, mbname);

	str_append_c(text, ' ');
	if (command == GETMETADATA) {
		imap_append_astring(text, fkey);
	} else {
		str_append_c(text, '(');
		imap_append_astring(text, fkey);
		str_append_c(text, ' ');
		imap_append_nstring(text, value);
		str_append_c(text, ')');
	}
	return str_c(text);
}

static int
imapc_storage_attribute_run_cmd(struct imapc_mailbox *mbox, const char *line,
				bool iterating,
				struct imapc_storage_attribute_context *actx)
{
	struct imapc_storage_client *client = mbox->storage->client;
	struct imapc_simple_context sctx;
	struct imapc_command *cmd;

	imapc_simple_context_init(&sctx, client);
	cmd = imapc_client_cmd(client->client, imapc_simple_callback, &sctx);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);

	if (actx != NULL) {
		actx->iterating = iterating;
		imapc_storage_client_register_untagged(
			client, "METADATA", imapc_storage_attribute_get_cb);
	}
	mbox->storage->cur_attribute_context = actx;
	imapc_command_send(cmd, line);
	imapc_simple_run(&sctx, &cmd);
	mbox->storage->cur_attribute_context = NULL;

	if (actx != NULL)
		imapc_storage_client_unregister_untagged(client, "METADATA");

	if (actx == NULL || actx->error == NULL)
		return sctx.ret < 0 ? -1 : 0;

	mail_storage_set_error(mbox->box.storage, MAIL_ERROR_INVALIDDATA,
		t_strdup_printf("Server sent invalid METADATA response: %s",
				actx->error));
	return -1;
}

static int
imapc_storage_attribute_cmd(struct mailbox *box,
			    enum imapc_attribute_command_enum command,
			    enum mail_attribute_type type_flags,
			    int depth, const char *key, const char *value,
			    struct imapc_storage_attribute_context *actx)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(box);
	const char *line = imapc_storage_attribute_build_cmd(
		mbox, command, depth, type_flags, key, value);
	return imapc_storage_attribute_run_cmd(
		mbox, line, command == GETMETADATA && depth != 0, actx);
}

enum handling {
	HANDLE_ERROR 	   = -1, /* the call should fail */
	HANDLE_UNAVAILABLE = -2, /* backend doesn't support METADATA */
	HANDLE_IMAPC 	   =  0, /* execute using backend */
	HANDLE_INDEX 	   =  1, /* execute using local (pvt) index */
};

static enum handling
imapc_storage_attribute_handling(struct mailbox *box,
				 enum mail_attribute_type type_flags,
				 const char *key)
{
	/* this prefix has special handling, fall back on index_attribute */
	if (str_begins_with(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT))
		return HANDLE_INDEX;

	/* private attributes for other users will be handled by index_attribute */
	struct mail_namespace *ns = mailbox_get_namespace(box);
	if (type_flags == MAIL_ATTRIBUTE_TYPE_PRIVATE &&
	    strcmp(ns->user->username, ns->owner->username) != 0)
		return HANDLE_INDEX;

	/* If we got here then we want to access metadata in the imapc backend.
	   Check if that is possible. */
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(box);
	enum imapc_capability capabilities = 0;

	if (!IMAPC_HAS_FEATURE(mbox->storage, IMAPC_FEATURE_NO_METADATA)) {
		if (mbox->capabilities == 0 &&
		    imapc_client_get_capabilities(mbox->storage->client->client,
					 	  &mbox->capabilities) < 0)
			return HANDLE_ERROR;
		capabilities = mbox->capabilities;
	}

	if (!HAS_ALL_BITS(capabilities, IMAPC_CAPABILITY_METADATA)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_UNAVAILABLE,
				       "Can't access metadata on imapc backend");
		return HANDLE_UNAVAILABLE;
	}

	return HANDLE_IMAPC;
}

int imapc_storage_attribute_set(struct mailbox_transaction_context *t,
				enum mail_attribute_type type_flags,
				const char *key,
				const struct mail_attribute_value *value)
{
	switch (imapc_storage_attribute_handling(t->box, type_flags, key)) {
	case HANDLE_INDEX:
		return index_storage_attribute_set(t, type_flags, key, value);
	case HANDLE_IMAPC:
		break;
	default:
		return -1;
	}

	const char *value_str;
	if (mailbox_attribute_value_to_string(t->box->storage, value, &value_str) < 0)
		return -1;

	return imapc_storage_attribute_cmd(t->box, SETMETADATA, type_flags,
					   DEPTH_NONE, key, value_str, NULL);
}

int imapc_storage_attribute_get(struct mailbox *box,
				enum mail_attribute_type type_flags,
				const char *key,
				struct mail_attribute_value *value_r)
{
	switch (imapc_storage_attribute_handling(box, type_flags, key)) {
	case HANDLE_INDEX:
		return index_storage_attribute_get(box, type_flags, key, value_r);
	case HANDLE_IMAPC:
		break;
	default:
		return -1;
	}

	struct imapc_storage_attribute_context *actx =
		imapc_storage_attribute_context_create();
	int ret = imapc_storage_attribute_cmd(box, GETMETADATA, type_flags,
					      DEPTH_NONE, key, NULL, actx);
	value_r->value = ret < 0 ? NULL : t_strdup(actx->value);
	imapc_storage_attribute_context_destroy(&actx);
	return ret;
}

struct mailbox_attribute_iter *
imapc_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type_flags,
				  const char *prefix)
{
	struct imapc_storage_attribute_iter *iter =
		imapc_storage_attribute_iter_create();

	switch (imapc_storage_attribute_handling(box, type_flags, prefix)) {
	case HANDLE_INDEX:
		iter->ictx = index_storage_attribute_iter_init(box, type_flags,
							       prefix);
		break;
	case HANDLE_IMAPC:
		if (imapc_storage_attribute_cmd(box, GETMETADATA, type_flags,
					        DEPTH_INFINITY, prefix, NULL,
						iter->actx) < 0) {
			mail_storage_last_error_push(box->storage);
			iter->failed = TRUE;
		}
		break;
	case HANDLE_UNAVAILABLE:
		break;
	default:
		mail_storage_last_error_push(box->storage);
		iter->failed = TRUE;
		break;
	}

	iter->iter.box = box;
	return &iter->iter;
}

const char *
imapc_storage_attribute_iter_next(struct mailbox_attribute_iter *_iter)
{
	struct imapc_storage_attribute_iter *iter = ITER_CONTAINER(_iter);

	if (iter->ictx != NULL)
		return index_storage_attribute_iter_next(iter->ictx);

	if (iter->failed || iter->actx == NULL || iter->actx->keys == NULL)
		return NULL;

	const char *key = *(iter->actx->keys);
	if (key == NULL)
		return NULL;

	iter->actx->keys++;

	/* skip the leading "/private/" or "/shared/" part */
	i_assert(*key == '/');
	key = strchr(++key, '/');
	if (key != NULL)
		key++;

	return key;
}

int imapc_storage_attribute_iter_deinit(struct mailbox_attribute_iter *_iter)
{
	struct imapc_storage_attribute_iter *iter = ITER_CONTAINER(_iter);

	int ret;
	if (iter->ictx != NULL)
		ret = index_storage_attribute_iter_deinit(iter->ictx);
	else if (!iter->failed)
		ret = 0;
	else {
		mail_storage_last_error_pop(iter->iter.box->storage);
		ret = -1;
	}

	imapc_storage_attribute_iter_destroy(&iter);
	return ret;
}
