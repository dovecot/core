/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

static const char *const *
keywords_get_from_header(const struct mail_transaction_keyword_update *rec,
			 size_t size, const uint32_t **uid_r)
{
	buffer_t *buf;
	const unsigned char *p, *end;
	const char *name;
	uint32_t i, diff;

	if (size / sizeof(rec->name_size) < rec->keywords_count) {
		/* keyword_count is badly broken */
		return NULL;
	}

	buf = buffer_create_static_hard(pool_datastack_create(),
					(rec->keywords_count + 1) *
					sizeof(const char *));
	p = (const unsigned char *)(rec->name_size + rec->keywords_count);
	end = CONST_PTR_OFFSET(rec, size);

	if (p >= end)
		return NULL;

	for (i = 0; i < rec->keywords_count; i++) {
		if (p + rec->name_size[i] >= end)
			return NULL;

		name = t_strndup(p, rec->name_size[i]);
		buffer_append(buf, &name, sizeof(name));
		p += rec->name_size[i];
	}

	diff = (p - (const unsigned char *)rec) % 4;
	if (diff != 0)
		p += 4 - diff;

	*uid_r = (const uint32_t *)p;

	name = NULL;
	buffer_append(buf, &name, sizeof(name));
	return buf->data;
}

static int keywords_get_missing(struct mail_index_sync_map_ctx *ctx,
				const char *const *keywords,
                                const char *const **missing_r)
{
	struct mail_index_map *map = ctx->view->index->map;
	const char *name;
	buffer_t *missing_buf;
	unsigned int i;

	if (!ctx->keywords_read) {
		if (mail_index_map_read_keywords(ctx->view->index, map) < 0)
			return -1;
		ctx->keywords_read = TRUE;
	}

        missing_buf = buffer_create_dynamic(pool_datastack_create(), 64);
	for (; *keywords != NULL; keywords++) {
		for (i = 0; i < map->keywords_count; i++) {
			if (strcmp(map->keywords[i], *keywords) == 0)
				break;
		}
		if (i == map->keywords_count)
			buffer_append(missing_buf, keywords, sizeof(*keywords));
	}

	if (missing_buf->used == 0)
		*missing_r = NULL;
	else {
		name = NULL;
		buffer_append(missing_buf, &name, sizeof(name));
		*missing_r = missing_buf->data;
	}
	return 0;
}

static buffer_t *
keywords_get_header_buf(struct mail_index_map *map,
			const struct mail_index_ext *ext,
			unsigned int new_count, unsigned int *keywords_count_r,
			size_t *rec_offset_r, size_t *name_offset_root_r,
			size_t *name_offset_r)
{
	buffer_t *buf;
	const struct mail_index_keyword_header *kw_hdr;
	const struct mail_index_keyword_header_rec *kw_rec;
	const char *name;
	struct mail_index_keyword_header new_kw_hdr;
	uint32_t offset;

	kw_hdr = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	kw_rec = (const void *)(kw_hdr + 1);
	name = (const char *)(kw_rec + kw_hdr->keywords_count);

	if (kw_hdr->keywords_count == 0)
		return NULL;

	new_kw_hdr = *kw_hdr;
	new_kw_hdr.keywords_count += new_count;
	*keywords_count_r = new_kw_hdr.keywords_count;

	offset = kw_rec[kw_hdr->keywords_count-1].name_offset;
	offset += strlen(name + offset) + 1;

	buf = buffer_create_dynamic(pool_datastack_create(), 512);
	buffer_append(buf, &new_kw_hdr, sizeof(new_kw_hdr));
	buffer_append(buf, kw_rec, sizeof(*kw_rec) * kw_hdr->keywords_count);
	*rec_offset_r = buf->used;
	buffer_write(buf, buf->used + sizeof(*kw_rec) * new_count,
		     name, offset);
	*name_offset_root_r = buf->used;
	*name_offset_r = offset;
	return buf;
}

static int keywords_ext_register(struct mail_index_sync_map_ctx *ctx,
				 uint32_t ext_id, uint32_t reset_id,
				 uint32_t hdr_size, uint32_t keywords_count)
{
	buffer_t *ext_intro_buf;
	struct mail_transaction_ext_intro *u;

	ext_intro_buf =
		buffer_create_static_hard(pool_datastack_create(),
					  sizeof(*u) + sizeof("keywords")-1);

	u = buffer_append_space_unsafe(ext_intro_buf, sizeof(*u));
	u->ext_id = ext_id;
	u->reset_id = reset_id;
	u->hdr_size = hdr_size;
	u->record_size = (keywords_count + CHAR_BIT - 1) / CHAR_BIT;
	if ((u->record_size % 4) != 0) {
		/* since we aren't properly aligned anyway,
		   reserve one extra byte for future */
		u->record_size++;
	}
	u->record_align = 1;

	if (ext_id == (uint32_t)-1) {
		u->name_size = strlen("keywords");
		buffer_append(ext_intro_buf, "keywords", u->name_size);
	}

	return mail_index_sync_ext_intro(ctx, u);
}

static int
keywords_update_header(struct mail_index_sync_map_ctx *ctx,
		       const char *const *keywords)
{
	struct mail_index_map *map = ctx->view->map;
        const struct mail_index_ext *ext = NULL;
	struct mail_index_keyword_header *kw_hdr;
	struct mail_index_keyword_header_rec kw_rec;
	uint32_t ext_id;
	const char *const *missing = keywords;
	buffer_t *buf = NULL;
	size_t rec_offset, name_offset, name_offset_root;
	unsigned int keywords_count;
	int ret = 0;

	ext_id = mail_index_map_lookup_ext(map, "keywords");
	if (ext_id != (uint32_t)-1) {
		/* make sure all keywords exist in the header */
		ext = map->extensions->data;
		ext += ext_id;

		ret = keywords_get_missing(ctx, keywords, &missing);
		if (ret == 0 && missing != NULL) {
			/* update existing header */
			buf = keywords_get_header_buf(map, ext,
						      strarray_length(missing),
						      &keywords_count,
						      &rec_offset,
						      &name_offset_root,
						      &name_offset);
		}
	}

	if (buf == NULL) {
		/* create new / replace broken header */
		buf = buffer_create_dynamic(pool_datastack_create(), 512);
		kw_hdr = buffer_append_space_unsafe(buf, sizeof(*kw_hdr));
		kw_hdr->keywords_count = strarray_length(missing);

                keywords_count = kw_hdr->keywords_count;
		rec_offset = buf->used;
		name_offset_root = rec_offset +
			kw_hdr->keywords_count * sizeof(kw_rec);
		name_offset = 0;
	}

	if (missing == NULL)
		return 1;

	/* missing some keywords - add them */
	memset(&kw_rec, 0, sizeof(kw_rec));
	kw_rec.name_offset = name_offset;

	for (; *missing != NULL; missing++) {
		size_t len = strlen(*missing) + 1;

		buffer_write(buf, rec_offset, &kw_rec, sizeof(kw_rec));
		buffer_write(buf, name_offset_root, *missing, len);

		rec_offset += sizeof(kw_rec);
		kw_rec.name_offset += len;
		name_offset_root += len;
	}

	if ((buf->used % 4) != 0)
		buffer_append_zero(buf, 4 - (buf->used % 4));

	if (ext == NULL || buf->used > ext->hdr_size ||
	    (uint32_t)ext->record_size * CHAR_BIT < keywords_count) {
		/* if we need to grow the buffer, add some padding */
		buffer_append_zero(buf, 128);

		ret = keywords_ext_register(ctx, ext_id,
					    ext == NULL ? 0 : ext->reset_id,
					    buf->used, keywords_count);
		if (ret <= 0)
			return ret;

		/* map may have changed */
		map = ctx->view->map;

		if (ext == NULL) {
			ext_id = mail_index_map_lookup_ext(map, "keywords");
			i_assert(ext_id != (uint32_t)-1);
		}
		ext = map->extensions->data;
		ext += ext_id;

		i_assert(ext->hdr_size == buf->used);
	}

	buffer_copy(map->hdr_copy_buf, ext->hdr_offset,
		    buf, 0, buf->used);
	map->hdr_base = map->hdr_copy_buf->data;

        ctx->keywords_read = FALSE;
	return 1;
}

static const unsigned char *
keywords_make_mask(struct mail_index_map *map, const struct mail_index_ext *ext,
		   const char *const *keywords)
{
	const char *const *n;
	unsigned char *mask;
	unsigned int i;

	mask = t_malloc0(ext->record_size);

	for (i = 0; i < map->keywords_count; i++) {
		for (n = keywords; *n != NULL; n++) {
			if (strcmp(map->keywords[i], *n) == 0) {
				mask[i / CHAR_BIT] |= 1 << (i % CHAR_BIT);
				break;
			}
		}
	}

	return mask;
}

static int
keywords_update_records(struct mail_index_view *view,
			const struct mail_index_ext *ext,
			const unsigned char *mask,
			enum modify_type type,
			uint32_t uid1, uint32_t uid2)
{
	struct mail_index_record *rec;
	unsigned char *data;
	uint32_t seq1, seq2;
	unsigned int i;

	if (mail_index_lookup_uid_range(view, uid1, uid2, &seq1, &seq2) < 0)
		return -1;

	if (seq1 == 0)
		return 1;

	for (; seq1 <= seq2; seq1++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, seq1-1);
		data = PTR_OFFSET(rec, ext->record_offset);

		switch (type) {
		case MODIFY_ADD:
			for (i = 0; i < ext->record_size; i++)
				data[i] |= mask[i];
			break;
		case MODIFY_REMOVE:
		for (i = 0; i < ext->record_size; i++)
			data[i] &= ~mask[i];
		break;
		case MODIFY_REPLACE:
			memcpy(data, mask, ext->record_size);
			break;
		default:
			i_unreached();
		}
	}
	return 1;
}

int mail_index_sync_keywords(struct mail_index_sync_map_ctx *ctx,
			     const struct mail_transaction_header *hdr,
			     const struct mail_transaction_keyword_update *rec)
{
	const uint32_t *uid, *end;
	const char *const *keywords;
	const struct mail_index_ext *ext;
	const unsigned char *mask;
	uint32_t ext_id;
	int ret;

	keywords = keywords_get_from_header(rec, hdr->size, &uid);
	if (keywords == NULL) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Keyword header ended unexpectedly");
		return -1;
	}
	end = CONST_PTR_OFFSET(rec, hdr->size);

	if (*keywords == NULL && rec->modify_type != MODIFY_REPLACE) {
		/* adding/removing empty keywords list - do nothing */
		return 1;
	}

	if (rec->modify_type != MODIFY_REMOVE) {
		ret = keywords_update_header(ctx, keywords);
		if (ret <= 0)
			return ret;
	}

	ext_id = mail_index_map_lookup_ext(ctx->view->map, "keywords");
	if (ext_id == (uint32_t)-1) {
		/* nothing to do */
		i_assert(rec->modify_type == MODIFY_REMOVE);
		return 1;
	}

	ext = ctx->view->map->extensions->data;
	ext += ext_id;

	if (ext->record_size == 0) {
		/* nothing to do */
		i_assert(*keywords == NULL);
		i_assert(rec->modify_type == MODIFY_REPLACE);
		return 1;
	}

	if (!ctx->keywords_read) {
		if (mail_index_map_read_keywords(ctx->view->index,
						 ctx->view->map) < 0)
			return -1;
		ctx->keywords_read = TRUE;
	}

	mask = keywords_make_mask(ctx->view->map, ext, keywords);

	while (uid+2 <= end) {
		if (uid[0] > uid[1] || uid[0] == 0) {
			mail_transaction_log_view_set_corrupted(
					ctx->view->log_view,
					"Keyword record UIDs are broken");
			return -1;
		}

		ret = keywords_update_records(ctx->view, ext, mask,
					      rec->modify_type,
					      uid[0], uid[1]);
		if (ret <= 0)
			return ret;

		uid += 2;
	}

	return 1;
}
