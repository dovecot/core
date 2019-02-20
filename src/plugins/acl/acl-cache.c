/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "acl-cache.h"
#include "acl-api-private.h"

/* Give more than enough so that the arrays should never have to be grown.
   IMAP ACLs define only 10 standard rights and 10 user-defined rights. */
#define DEFAULT_ACL_RIGHTS_COUNT 64

#define ACL_GLOBAL_COUNT 2

struct acl_object_cache {
	char *name;

	struct acl_mask *my_rights, *my_neg_rights;
	struct acl_mask *my_current_rights;
};

struct acl_cache {
	struct acl_backend *backend;
	/* name => object */
	HASH_TABLE(char *, struct acl_object_cache *) objects;

	size_t validity_rec_size;

	/* Right names mapping is used for faster rights checking. Note that
	   acl_mask bitmask relies on the order to never change, so only new
	   rights can be added to the mapping. */
	pool_t right_names_pool;
	/* idx => right name. */
	ARRAY(const char *) right_idx_name_map;
	/* name => idx+1 */
	HASH_TABLE(char *, void *) right_name_idx_map;
};

static struct acl_mask negative_cache_entry;

struct acl_cache *acl_cache_init(struct acl_backend *backend,
				 size_t validity_rec_size)
{
	struct acl_cache *cache;

	cache = i_new(struct acl_cache, 1);
	cache->backend = backend;
	cache->validity_rec_size = validity_rec_size;
	cache->right_names_pool =
		pool_alloconly_create("ACL right names", 1024);
	hash_table_create(&cache->objects, default_pool, 0, str_hash, strcmp);
	hash_table_create(&cache->right_name_idx_map,
			  cache->right_names_pool, 0, str_hash, strcmp);
	i_array_init(&cache->right_idx_name_map, DEFAULT_ACL_RIGHTS_COUNT);
	return cache;
}

void acl_cache_deinit(struct acl_cache **_cache)
{
	struct acl_cache *cache = *_cache;

	*_cache = NULL;

	acl_cache_flush_all(cache);
	array_free(&cache->right_idx_name_map);
	hash_table_destroy(&cache->right_name_idx_map);
	hash_table_destroy(&cache->objects);
	pool_unref(&cache->right_names_pool);
	i_free(cache);
}

static void acl_cache_free_object_cache(struct acl_object_cache *obj_cache)
{
	if (obj_cache->my_current_rights != NULL &&
	    obj_cache->my_current_rights != &negative_cache_entry)
		acl_cache_mask_deinit(&obj_cache->my_current_rights);
	if (obj_cache->my_rights != NULL)
		acl_cache_mask_deinit(&obj_cache->my_rights);
	if (obj_cache->my_neg_rights != NULL)
		acl_cache_mask_deinit(&obj_cache->my_neg_rights);
	i_free(obj_cache->name);
	i_free(obj_cache);
}

static struct acl_mask *
acl_cache_mask_init_real(struct acl_cache *cache, pool_t pool,
			 const char *const *rights)
{
	struct acl_mask *mask;
	unsigned int rights_count, i, idx;
	unsigned char *p;
	buffer_t *bitmask;

	rights_count = str_array_length(rights);
	bitmask = t_buffer_create(DEFAULT_ACL_RIGHTS_COUNT / CHAR_BIT);
	for (i = 0; i < rights_count; i++) {
		idx = acl_cache_right_lookup(cache, rights[i]);
		p = buffer_get_space_unsafe(bitmask, idx / CHAR_BIT, 1);
		*p |= 1 << (idx % CHAR_BIT);
	}

	/* @UNSAFE */
	mask = p_malloc(pool, SIZEOF_ACL_MASK(bitmask->used));
	memcpy(mask->mask, bitmask->data, bitmask->used);
	mask->pool = pool;
	mask->size = bitmask->used;
	return mask;
}

struct acl_mask *acl_cache_mask_init(struct acl_cache *cache, pool_t pool,
				     const char *const *rights)
{
	struct acl_mask *mask;

	T_BEGIN {
		mask = acl_cache_mask_init_real(cache, pool, rights);
	} T_END;
	return mask;
}

static struct acl_mask *
acl_cache_mask_dup(pool_t pool, const struct acl_mask *src)
{
	struct acl_mask *mask;

	mask = p_malloc(pool, SIZEOF_ACL_MASK(src->size));
	memcpy(mask->mask, src->mask, src->size);
	mask->pool = pool;
	mask->size = src->size;
	return mask;
}

void acl_cache_mask_deinit(struct acl_mask **_mask)
{
	struct acl_mask *mask = *_mask;

	*_mask = NULL;
	p_free(mask->pool, mask);
}

unsigned int acl_cache_right_lookup(struct acl_cache *cache, const char *right)
{
	unsigned int idx;
	void *idx_p;
	char *name;
	const char *const_name;

	/* use +1 for right_name_idx_map values because we can't add NULL
	   values. */
	idx_p = hash_table_lookup(cache->right_name_idx_map, right);
	if (idx_p == NULL) {
		/* new right name, add it */
		const_name = name = p_strdup(cache->right_names_pool, right);

		idx = array_count(&cache->right_idx_name_map);
		array_push_back(&cache->right_idx_name_map, &const_name);
		hash_table_insert(cache->right_name_idx_map, name,
				  POINTER_CAST(idx + 1));
	} else {
		idx = POINTER_CAST_TO(idx_p, unsigned int)-1;
	}
	return idx;
}

void acl_cache_flush(struct acl_cache *cache, const char *objname)
{
	struct acl_object_cache *obj_cache;

	obj_cache = hash_table_lookup(cache->objects, objname);
	if (obj_cache != NULL) {
		hash_table_remove(cache->objects, objname);
		acl_cache_free_object_cache(obj_cache);
	}
}

void acl_cache_flush_all(struct acl_cache *cache)
{
	struct hash_iterate_context *iter;
	char *key;
	struct acl_object_cache *obj_cache;

	iter = hash_table_iterate_init(cache->objects);
	while (hash_table_iterate(iter, cache->objects, &key, &obj_cache))
		acl_cache_free_object_cache(obj_cache);
	hash_table_iterate_deinit(&iter);

	hash_table_clear(cache->objects, FALSE);
}

static void
acl_cache_update_rights_mask(struct acl_cache *cache,
			     struct acl_object_cache *obj_cache,
			     enum acl_modify_mode modify_mode,
			     const char *const *rights,
			     struct acl_mask **mask_p)
{
	struct acl_mask *change_mask, *old_mask, *new_mask;
	unsigned int i, size;
	bool changed = TRUE;

	change_mask = rights == NULL ? NULL :
		acl_cache_mask_init(cache, default_pool, rights);
	old_mask = *mask_p;
	new_mask = old_mask;

	switch (modify_mode) {
	case ACL_MODIFY_MODE_ADD:
		if (old_mask == NULL) {
			new_mask = change_mask;
			break;
		}

		if (change_mask == NULL) {
			/* no changes */
			changed = FALSE;
			break;
		}

		/* merge the masks */
		if (old_mask->size >= change_mask->size) {
			/* keep using the old mask */
			for (i = 0; i < change_mask->size; i++)
				old_mask->mask[i] |= change_mask->mask[i];
		} else {
			/* use the new mask, put old changes into it */
			for (i = 0; i < old_mask->size; i++)
				change_mask->mask[i] |= old_mask->mask[i];
			new_mask = change_mask;
		}
		break;
	case ACL_MODIFY_MODE_REMOVE:
		if (old_mask == NULL || change_mask == NULL) {
			changed = FALSE;
			break;
		}

		/* remove changed bits from old mask */
		size = I_MIN(old_mask->size, change_mask->size);
		for (i = 0; i < size; i++)
			old_mask->mask[i] &= ~change_mask->mask[i];
		break;
	case ACL_MODIFY_MODE_REPLACE:
		if (old_mask == NULL && change_mask == NULL)
			changed = FALSE;
		new_mask = change_mask;
		break;
	case ACL_MODIFY_MODE_CLEAR:
		i_unreached();
	}

	if (new_mask != old_mask) {
		*mask_p = new_mask;
		if (old_mask != NULL)
			acl_cache_mask_deinit(&old_mask);
	}
	if (new_mask != change_mask && change_mask != NULL)
		acl_cache_mask_deinit(&change_mask);

	if (changed && obj_cache->my_current_rights != NULL) {
		/* current rights need to be recalculated */
		if (obj_cache->my_current_rights == &negative_cache_entry)
			obj_cache->my_current_rights = NULL;
		else
			acl_cache_mask_deinit(&obj_cache->my_current_rights);
	}
}

static struct acl_object_cache *
acl_cache_object_get(struct acl_cache *cache, const char *objname,
		     bool *created_r)
{
	struct acl_object_cache *obj_cache;

	obj_cache = hash_table_lookup(cache->objects, objname);
	if (obj_cache == NULL) {
		obj_cache = i_malloc(MALLOC_ADD(sizeof(struct acl_object_cache),
						cache->validity_rec_size));
		obj_cache->name = i_strdup(objname);
		hash_table_insert(cache->objects, obj_cache->name, obj_cache);
		*created_r = TRUE;
	} else {
		*created_r = FALSE;
	}
	return obj_cache;
}

void acl_cache_update(struct acl_cache *cache, const char *objname,
		      const struct acl_rights_update *update)
{
	struct acl_object_cache *obj_cache;
	bool created;

	obj_cache = acl_cache_object_get(cache, objname, &created);
	i_assert(obj_cache->my_current_rights != &negative_cache_entry);

	if (created && update->modify_mode != ACL_MODIFY_MODE_REPLACE) {
		/* since the rights aren't being replaced, start with our
		   default rights */
		obj_cache->my_rights =
			acl_cache_mask_dup(default_pool,
					   cache->backend->default_aclmask);
	}

	acl_cache_update_rights_mask(cache, obj_cache, update->modify_mode,
				     update->rights.rights,
				     &obj_cache->my_rights);
	acl_cache_update_rights_mask(cache, obj_cache, update->neg_modify_mode,
				     update->rights.neg_rights,
				     &obj_cache->my_neg_rights);
}

void acl_cache_set_validity(struct acl_cache *cache, const char *objname,
			    const void *validity)
{
	struct acl_object_cache *obj_cache;
	bool created;

	obj_cache = acl_cache_object_get(cache, objname, &created);

	/* @UNSAFE: validity is stored after the cache record */
	memcpy(obj_cache + 1, validity, cache->validity_rec_size);

	if (created) {
		/* negative cache entry */
		obj_cache->my_current_rights = &negative_cache_entry;
	} 
}

void *acl_cache_get_validity(struct acl_cache *cache, const char *objname)
{
	struct acl_object_cache *obj_cache;

	obj_cache = hash_table_lookup(cache->objects, objname);
	return obj_cache == NULL ? NULL : (obj_cache + 1);
}

const char *const *acl_cache_get_names(struct acl_cache *cache,
				       unsigned int *count_r)
{
	*count_r = array_count(&cache->right_idx_name_map);
	return array_front(&cache->right_idx_name_map);
}

static void
acl_cache_my_current_rights_recalculate(struct acl_object_cache *obj_cache)
{
	struct acl_mask *mask;
	unsigned int i, size;

	/* @UNSAFE */
	size = obj_cache->my_rights == NULL ? 0 :
		obj_cache->my_rights->size;
	mask = i_malloc(SIZEOF_ACL_MASK(size));
	mask->pool = default_pool;
	mask->size = size;

	/* apply the positive rights */
	if (obj_cache->my_rights != NULL)
		memcpy(mask->mask, obj_cache->my_rights->mask, mask->size);
	if (obj_cache->my_neg_rights != NULL) {
		/* apply the negative rights. they override positive rights. */
		size = I_MIN(mask->size, obj_cache->my_neg_rights->size);
		for (i = 0; i < size; i++)
			mask->mask[i] &= ~obj_cache->my_neg_rights->mask[i];
	}

	obj_cache->my_current_rights = mask;
}

const struct acl_mask *
acl_cache_get_my_rights(struct acl_cache *cache, const char *objname)
{
	struct acl_object_cache *obj_cache;

	obj_cache = hash_table_lookup(cache->objects, objname);
	if (obj_cache == NULL ||
	    obj_cache->my_current_rights == &negative_cache_entry)
		return NULL;

	if (obj_cache->my_current_rights == NULL) {
		T_BEGIN {
			acl_cache_my_current_rights_recalculate(obj_cache);
		} T_END;
	}
	return obj_cache->my_current_rights;
}

bool acl_cache_mask_isset(const struct acl_mask *mask, unsigned int right_idx)
{
	unsigned int mask_idx;

	mask_idx = right_idx / CHAR_BIT;
	return mask_idx < mask->size &&
		(mask->mask[mask_idx] & (1 << (right_idx % CHAR_BIT))) != 0;
}
