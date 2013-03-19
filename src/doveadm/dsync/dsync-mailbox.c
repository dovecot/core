/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "dsync-mailbox.h"

void dsync_mailbox_attribute_dup(pool_t pool,
				 const struct dsync_mailbox_attribute *src,
				 struct dsync_mailbox_attribute *dest_r)
{
	dest_r->type = src->type;
	dest_r->key = p_strdup(pool, src->key);
	dest_r->value = p_strdup(pool, src->value);
	if (src->value_stream != NULL) {
		dest_r->value_stream = src->value_stream;
		i_stream_ref(dest_r->value_stream);
	}

	dest_r->deleted = src->deleted;
	dest_r->last_change = src->last_change;
	dest_r->modseq = src->modseq;
}
