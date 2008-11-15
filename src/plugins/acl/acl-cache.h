#ifndef ACL_CACHE_H
#define ACL_CACHE_H

struct acl_backend;
struct acl_rights_update;

struct acl_mask {
	pool_t pool;

	/* mask[] size as bytes */
	unsigned int size;

	/* variable length bitmask */
	unsigned char mask[1];
};
#define SIZEOF_ACL_MASK(bitmask_size) \
	(sizeof(pool_t) + sizeof(unsigned int) + (bitmask_size))

struct acl_cache *acl_cache_init(struct acl_backend *backend,
				 size_t validity_rec_size);
void acl_cache_deinit(struct acl_cache **cache);

struct acl_mask *acl_cache_mask_init(struct acl_cache *cache, pool_t pool,
				     const char *const *rights);
void acl_cache_mask_deinit(struct acl_mask **mask);
unsigned int acl_cache_right_lookup(struct acl_cache *cache,
				    const char *right);

/* Flush cache for given object name */
void acl_cache_flush(struct acl_cache *cache, const char *objname);
/* Flush cache for all objects */
void acl_cache_flush_all(struct acl_cache *cache);

/* Update object ACLs. The new rights are always applied on top of the
   existing rights. The ordering by acl_id_type must be done by the caller. */
void acl_cache_update(struct acl_cache *cache, const char *objname,
		      const struct acl_rights_update *update);
/* Return ACL object validity, or NULL if object doesn't exit. */
void *acl_cache_get_validity(struct acl_cache *cache, const char *objname);
/* Update ACL object validity, creating the object if needed. */
void acl_cache_set_validity(struct acl_cache *cache, const char *objname,
			    const void *validity);

/* Returns all the right names currently created. The returned pointer may
   change after calling acl_cache_update(). */
const char *const *acl_cache_get_names(struct acl_cache *cache,
				       unsigned int *count_r);

/* Returns user's current rights, or NULL if no rights have been specified
   for this object. */
const struct acl_mask *
acl_cache_get_my_rights(struct acl_cache *cache, const char *objname);

/* Returns TRUE if given right index is set in mask. */
bool acl_cache_mask_isset(const struct acl_mask *mask, unsigned int right_idx);

#endif
