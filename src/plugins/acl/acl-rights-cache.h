#ifndef ACL_RIGHTS_CACHE_H
#define ACL_RIGHTS_CACHE_H

#include "acl-api.h"

#define ACL_RIGHTS_CACHE "acl-rights.cache"

struct acl_backend_vfile;
struct acl_rights_cache_file;

struct acl_rights_cache_file *
acl_rights_cache_file_init(struct acl_backend *backend);
void acl_rights_cache_file_deinit(struct acl_rights_cache_file **_file);

/* Read the ACL rights cache into memory. Returns 1 if the cache was loaded,
   0 if there is no cache file (the entries loaded earlier are forgotten)
   and -1 on error. */
int acl_rights_cache_file_refresh(struct acl_rights_cache_file *file);

/* Refresh the cache, throttled by the backend's cache_secs. If
   rebuild_if_missing is TRUE, the cache is rebuilt from the mailboxes' ACL
   files when the cache file is missing or unreadable, or when an earlier
   version's dovecot-acl-list has appeared next to it. */
void acl_rights_cache_refresh(struct acl_backend_vfile *backend,
			      bool rebuild_if_missing);

/* Rebuild the cache file from all mailboxes' ACL files. */
int acl_rights_cache_rebuild(struct acl_backend_vfile *backend);

/* Make sure the cached rights for the mailbox are up-to-date with the
   mailbox's ACL file. The count rights must be only the rights read from
   the ACL file (no configuration-provided rights) and mtime the ACL file's
   mtime. Called after the ACL file has been read successfully. */
void acl_rights_cache_verify(struct acl_object *aclobj,
			     const struct acl_rights *rights,
			     unsigned int count, const struct timeval *mtime);

/* Returns TRUE and the mtime stored for the mailbox's cache entry, FALSE if
   the mailbox has no entry. */
bool acl_rights_cache_file_get_mtime(struct acl_rights_cache_file *file,
				     const char *name, struct timeval *mtime_r);

enum acl_rights_cache_evict_flags {
	/* The configured ACLs give a nonowner the lookup right, so the
	   mailbox's marker is kept. */
	ACL_RIGHTS_CACHE_EVICT_KEEP_MARKER = BIT(0),
	/* The mailbox itself no longer exists, so a storage with cached files
	   doesn't keep its line either. */
	ACL_RIGHTS_CACHE_EVICT_MAILBOX_GONE = BIT(1),
};

/* Remove the mailbox's cached rights, e.g. after the mailbox or its ACL
   file was deleted. With a storage that has cached files the line stays without
   rights, so an old local copy of the ACL file isn't used again, unless
   ACL_RIGHTS_CACHE_EVICT_MAILBOX_GONE is set. Rebuilds the ACL lookup dict
   when the evicted entry contained nonowner lookup rights. Does nothing
   for backends without a rights cache. */
void acl_rights_cache_evict(struct acl_backend *backend, const char *name,
			    enum acl_rights_cache_evict_flags flags);

/* Apply given update to the existing cached ACL of the mailbox.
   Returns 1 if the cache was updated, 0 if there is no cache file to
   update (a full rebuild has to create it) or updating isn't possible
   here, -1 on error. */
int acl_rights_cache_file_update(struct acl_rights_cache_file *file,
				 const struct acl_rights_update *update,
				 const char *name, bool marker,
				 const struct timeval *mtime);

/* Replace the cached rights of the mailbox with the given rights. With
   marker the mailbox's line also gets the marker flag. An empty rights
   array without it removes the mailbox from the cache, unless its line has
   flags this version doesn't know, or the storage has cached files
   and mtime isn't 0.
   Return values are the same as for acl_rights_cache_file_update(). */
int acl_rights_cache_file_set(struct acl_rights_cache_file *file,
			      const char *name,
			      ARRAY_TYPE(acl_rights) *rights,
			      bool marker, const struct timeval *mtime);

/* Append the cached ACL rights of the mailbox to rights_r, allocated from
   pool. The cache must already have been refreshed. */
void acl_rights_cache_file_get(struct acl_rights_cache_file *file,
			       const char *name, pool_t pool,
			       ARRAY_TYPE(acl_rights) *rights_r);

/* Returns TRUE if there are any cached ACLs for the mailbox name and
   identifier. If identifier is NULL it is ignored. */
bool acl_rights_cache_file_have_any(struct acl_rights_cache_file *file,
				    const char *name,
				    const char *identifier);

/* Returns 1 if the cache file exists, 0 if it doesn't and -1 on error. */
int acl_rights_cache_file_exists(struct acl_rights_cache_file *file);

#endif
