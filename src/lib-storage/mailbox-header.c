/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sort.h"
#include "mail-cache.h"
#include "mail-storage-private.h"


static struct mailbox_header_lookup_ctx *
mailbox_header_lookup_init_real(struct mailbox *box,
				const char *const headers[])
{
	struct mail_cache_field *fields, header_field = {
		.type = MAIL_CACHE_FIELD_HEADER,
		.decision = MAIL_CACHE_DECISION_TEMP
	};
	struct mailbox_header_lookup_ctx *ctx;
	const char *const *name;
	const char **sorted_headers, **dest_name;
	pool_t pool;
	unsigned int i, j, count;

	i_assert(*headers != NULL);

	for (count = 0, name = headers; *name != NULL; name++)
		count++;

	/* @UNSAFE: headers need to be sorted for filter stream. */
	sorted_headers = t_new(const char *, count);
	memcpy(sorted_headers, headers, count * sizeof(*sorted_headers));
	i_qsort(sorted_headers, count, sizeof(*sorted_headers), i_strcasecmp_p);
	headers = sorted_headers;

	/* @UNSAFE */
	fields = t_new(struct mail_cache_field, count);
	for (i = j = 0; i < count; i++) {
		if (i > 0 && strcasecmp(headers[i-1], headers[i]) == 0)
			continue;
		header_field.name = t_strconcat("hdr.", headers[i], NULL);
		fields[j++] = header_field;
	}
	count = j;
	mail_cache_register_fields(box->cache, fields, count);

	pool = pool_alloconly_create("mailbox_header_lookup_ctx", 1024);
	ctx = p_new(pool, struct mailbox_header_lookup_ctx, 1);
	ctx->box = box;
	ctx->refcount = 1;
	ctx->pool = pool;
	ctx->count = count;

	ctx->idx = p_new(pool, unsigned int, count);

	/* @UNSAFE */
	dest_name = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++) {
		ctx->idx[i] = fields[i].idx;
		dest_name[i] = p_strdup(pool, fields[i].name + strlen("hdr."));
	}
	ctx->name = dest_name;
	return ctx;
}

struct mailbox_header_lookup_ctx *
mailbox_header_lookup_init(struct mailbox *box, const char *const headers[])
{
	struct mailbox_header_lookup_ctx *ctx;

	T_BEGIN {
		ctx = mailbox_header_lookup_init_real(box, headers);
	} T_END;
	return ctx;
}

void mailbox_header_lookup_ref(struct mailbox_header_lookup_ctx *ctx)
{
	i_assert(ctx->refcount > 0);
	ctx->refcount++;
}

void mailbox_header_lookup_unref(struct mailbox_header_lookup_ctx **_ctx)
{
	struct mailbox_header_lookup_ctx *ctx = *_ctx;

	if (ctx == NULL)
		return;

	*_ctx = NULL;

	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	pool_unref(&ctx->pool);
}
