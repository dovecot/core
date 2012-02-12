/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "sha1.h"
#include "dsync-data.h"
#include "test-dsync-common.h"

const guid_128_t test_mailbox_guid1 = {
	0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x21, 0x43, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
};

const guid_128_t test_mailbox_guid2 = {
	0xa3, 0xbd, 0x78, 0x24, 0xde, 0xfe, 0x08, 0xf7,
	0xac, 0xc7, 0xca, 0x8c, 0xe7, 0x39, 0xdb, 0xca
};

bool dsync_messages_equal(const struct dsync_message *m1,
			  const struct dsync_message *m2)
{
	unsigned int i;

	if (strcmp(m1->guid, m2->guid) != 0 ||
	    m1->uid != m2->uid || m1->flags != m2->flags ||
	    m1->modseq != m2->modseq || m1->save_date != m2->save_date)
		return FALSE;

	if (m1->keywords == m2->keywords)
		return TRUE;
	if (m1->keywords == NULL)
		return m2->keywords == NULL || m2->keywords[0] == NULL;
	if (m2->keywords == NULL)
		return m1->keywords[0] == NULL;

	for (i = 0; m1->keywords[i] != NULL && m2->keywords[i] != NULL; i++) {
		if (strcasecmp(m1->keywords[i], m2->keywords[i]) != 0)
			return FALSE;
	}
	return m1->keywords[i] == NULL && m2->keywords[i] == NULL;
}

bool dsync_mailboxes_equal(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2)
{
	const struct mailbox_cache_field *f1 = NULL, *f2 = NULL;
	unsigned int i, f1_count = 0, f2_count = 0;

	if (strcmp(box1->name, box2->name) != 0 ||
	    box1->name_sep != box2->name_sep ||
	    memcmp(box1->mailbox_guid.guid, box2->mailbox_guid.guid,
		   sizeof(box1->mailbox_guid.guid)) != 0 ||
	    box1->uid_validity != box2->uid_validity ||
	    box1->uid_next != box2->uid_next ||
	    box1->highest_modseq != box2->highest_modseq)
		return FALSE;

	if (array_is_created(&box1->cache_fields))
		f1 = array_get(&box1->cache_fields, &f1_count);
	if (array_is_created(&box2->cache_fields))
		f2 = array_get(&box2->cache_fields, &f2_count);
	if (f1_count != f2_count)
		return FALSE;
	for (i = 0; i < f1_count; i++) {
		if (strcmp(f1[i].name, f2[i].name) != 0 ||
		    f1[i].decision != f2[i].decision ||
		    f1[i].last_used != f2[i].last_used)
			return FALSE;
	}
	return TRUE;
}

void mail_generate_guid_128_hash(const char *guid, guid_128_t guid_128_r)
{
	unsigned char sha1_sum[SHA1_RESULTLEN];

	sha1_get_digest(guid, strlen(guid), sha1_sum);
	memcpy(guid_128_r, sha1_sum, GUID_128_SIZE);
}
