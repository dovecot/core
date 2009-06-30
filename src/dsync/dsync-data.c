/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsync-data.h"

struct dsync_mailbox *
dsync_mailbox_dup(pool_t pool, const struct dsync_mailbox *box)
{
	struct dsync_mailbox *dest;

	dest = p_new(pool, struct dsync_mailbox, 1);
	*dest = *box;
	dest->name = p_strdup(pool, box->name);
	return dest;
}

struct dsync_message *
dsync_message_dup(pool_t pool, const struct dsync_message *msg)
{
	struct dsync_message *dest;
	const char **keywords;
	unsigned int i, count;

	dest = p_new(pool, struct dsync_message, 1);
	*dest = *msg;
	dest->guid = p_strdup(pool, msg->guid);
	if (msg->keywords != NULL) {
		count = str_array_length(msg->keywords);
		keywords = p_new(pool, const char *, count+1);
		for (i = 0; i < count; i++)
			keywords[i] = p_strdup(pool, msg->keywords[i]);
		dest->keywords = keywords;
	}
	return dest;
}

int dsync_mailbox_guid_cmp(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2)
{
	int ret;

	ret = memcmp(box1->guid.guid, box2->guid.guid,
		     sizeof(box1->guid.guid));
	if (ret != 0)
		return ret;

	if (box1->uid_validity != 0)
		return ret;

	/* \noselect mailboxes */
	i_assert(box2->uid_validity == 0);
	return strcmp(box1->name, box2->name);
}

int dsync_mailbox_p_guid_cmp(struct dsync_mailbox *const *box1,
			     struct dsync_mailbox *const *box2)
{
	return dsync_mailbox_guid_cmp(*box1, *box2);
}

bool dsync_keyword_list_equals(const char *const *k1, const char *const *k2)
{
	unsigned int i;

	if (k1 == NULL)
		return k2 == NULL || k2[0] == NULL;
	if (k2 == NULL)
		return k1[0] == NULL;

	for (i = 0;; i++) {
		if (k1[i] == NULL)
			return k2[i] == NULL;
		if (k2[i] == NULL)
			return FALSE;

		if (strcasecmp(k1[i], k2[i]) != 0)
			return FALSE;
	}
}
