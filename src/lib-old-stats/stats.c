/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "stats.h"

struct stats_item {
	struct stats_vfuncs v;
	size_t pos;
};

static ARRAY(struct stats_item *) stats_items = ARRAY_INIT;
static unsigned int stats_total_size = 0;
static bool stats_allocated = FALSE;

struct stats_item *stats_register(const struct stats_vfuncs *vfuncs)
{
	struct stats_item *item;

	if (stats_allocated)
		i_panic("stats_register() called after stats_alloc_size() was already called - this will break existing allocations");

	if (!array_is_created(&stats_items))
		i_array_init(&stats_items, 8);

	item = i_new(struct stats_item, 1);
	item->v = *vfuncs;
	item->pos = stats_total_size;
	array_push_back(&stats_items, &item);

	stats_total_size += vfuncs->alloc_size();
	return item;
}

static bool stats_item_find(struct stats_item *item, unsigned int *idx_r)
{
	struct stats_item *const *itemp;

	array_foreach(&stats_items, itemp) {
		if (*itemp == item) {
			*idx_r = array_foreach_idx(&stats_items, itemp);
			return TRUE;
		}
	}
	return FALSE;
}

static struct stats_item *stats_item_find_by_name(const char *name)
{
	struct stats_item *item;

	array_foreach_elem(&stats_items, item) {
		if (strcmp(item->v.short_name, name) == 0)
			return item;
	}
	return NULL;
}

void stats_unregister(struct stats_item **_item)
{
	struct stats_item *item = *_item;
	unsigned int idx;

	*_item = NULL;

	if (!stats_item_find(item, &idx))
		i_unreached();
	array_delete(&stats_items, idx, 1);

	i_free(item);
	if (array_count(&stats_items) == 0) {
		array_free(&stats_items);
		/* all stats should have been freed by now. allow
		   re-registering and using stats. */
		stats_allocated = FALSE;
	}
}

struct stats *stats_alloc(pool_t pool)
{
	return p_malloc(pool, stats_alloc_size());
}

size_t stats_alloc_size(void)
{
	stats_allocated = TRUE;
	return stats_total_size;
}

void stats_copy(struct stats *dest, const struct stats *src)
{
	memcpy(dest, src, stats_total_size);
}

unsigned int stats_field_count(void)
{
	struct stats_item *item;
	unsigned int count = 0;

	array_foreach_elem(&stats_items, item)
		count += item->v.field_count();
	return count;
}

const char *stats_field_name(unsigned int n)
{
	struct stats_item *item;
	unsigned int i = 0, count;

	array_foreach_elem(&stats_items, item) {
		count = item->v.field_count();
		if (i + count > n)
			return item->v.field_name(n - i);
		i += count;
	}
	i_unreached();
}

void stats_field_value(string_t *str, const struct stats *stats,
		       unsigned int n)
{
	struct stats_item *item;
	unsigned int i = 0, count;

	array_foreach_elem(&stats_items, item) {
		count = item->v.field_count();
		if (i + count > n) {
			const void *item_stats =
				CONST_PTR_OFFSET(stats, item->pos);
			item->v.field_value(str, item_stats, n - i);
			return;
		}
		i += count;
	}
	i_unreached();
}

bool stats_diff(const struct stats *stats1, const struct stats *stats2,
		struct stats *diff_stats_r, const char **error_r)
{
	struct stats_item *item;
	bool ret = TRUE;

	array_foreach_elem(&stats_items, item) {
		if (!item->v.diff(CONST_PTR_OFFSET(stats1, item->pos),
				  CONST_PTR_OFFSET(stats2, item->pos),
				  PTR_OFFSET(diff_stats_r, item->pos),
				  error_r))
			ret = FALSE;
	}
	return ret;
}

void stats_add(struct stats *dest, const struct stats *src)
{
	struct stats_item *item;

	array_foreach_elem(&stats_items, item) {
		item->v.add(PTR_OFFSET(dest, item->pos),
			    CONST_PTR_OFFSET(src, item->pos));
	}
}

bool stats_have_changed(const struct stats *prev, const struct stats *cur)
{
	struct stats_item *item;

	array_foreach_elem(&stats_items, item) {
		if (item->v.have_changed(CONST_PTR_OFFSET(prev, item->pos),
					 CONST_PTR_OFFSET(cur, item->pos)))
			return TRUE;
	}
	return FALSE;
}

void stats_export(buffer_t *buf, const struct stats *stats)
{
	struct stats_item *item;

	array_foreach_elem(&stats_items, item) {
		buffer_append(buf, item->v.short_name,
			      strlen(item->v.short_name)+1);
		item->v.export(buf, CONST_PTR_OFFSET(stats, item->pos));
	}
}

bool stats_import(const unsigned char *data, size_t size,
		  const struct stats *old_stats, struct stats *stats,
		  const char **error_r)
{
	struct stats_item *item;
	const unsigned char *p;
	size_t pos;

	memcpy(stats, old_stats, stats_total_size);
	while (size > 0) {
		const char *next_name = (const void *)data;

		p = memchr(data, '\0', size);
		if (p == NULL) {
			*error_r = "Expected name, but NUL is missing";
			return FALSE;
		}
		item = stats_item_find_by_name(next_name);
		if (item == NULL) {
			*error_r = t_strdup_printf("Unknown stats name: '%s'", next_name);
			return FALSE;
		}
		size -= (p+1) - data;
		data = p+1;
		if (!item->v.import(data, size, &pos,
				    PTR_OFFSET(stats, item->pos), error_r))
			return FALSE;
		i_assert(pos <= size);
		data += pos;
		size -= pos;
	}
	return TRUE;
}

void *stats_fill_ptr(struct stats *stats, struct stats_item *item)
{
	return PTR_OFFSET(stats, item->pos);
}

void stats_reset(struct stats *stats)
{
	memset(stats, 0, stats_total_size);
}
