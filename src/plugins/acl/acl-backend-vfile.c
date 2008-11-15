/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "nfs-workarounds.h"
#include "mail-storage-private.h"
#include "acl-cache.h"
#include "acl-backend-vfile.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ACL_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
#define ACL_VFILE_DEFAULT_CACHE_SECS (60*5)

#define VALIDITY_MTIME_NOTFOUND 0
#define VALIDITY_MTIME_NOACCESS -1

struct acl_vfile_validity {
	time_t last_check;

	time_t last_read_time;
	time_t last_mtime;
	off_t last_size;
};

struct acl_backend_vfile_validity {
	struct acl_vfile_validity global_validity, local_validity;
	struct acl_vfile_validity mailbox_validity;
};

struct acl_letter_map {
	char letter;
	const char *name;
};

static const struct acl_letter_map acl_letter_map[] = {
	{ 'l', MAIL_ACL_LOOKUP },
	{ 'r', MAIL_ACL_READ },
	{ 'w', MAIL_ACL_WRITE },
	{ 's', MAIL_ACL_WRITE_SEEN },
	{ 't', MAIL_ACL_WRITE_DELETED },
	{ 'i', MAIL_ACL_INSERT },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

static struct acl_backend *acl_backend_vfile_alloc(void)
{
	struct acl_backend_vfile *backend;
	pool_t pool;

	pool = pool_alloconly_create("ACL backend", 512);
	backend = p_new(pool, struct acl_backend_vfile, 1);
	backend->backend.pool = pool;
	return &backend->backend;
}

static int
acl_backend_vfile_init(struct acl_backend *_backend, const char *data)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	const char *const *tmp;

	tmp = t_strsplit(data, ":");
	backend->global_dir = p_strdup_empty(_backend->pool, *tmp);
	backend->cache_secs = ACL_VFILE_DEFAULT_CACHE_SECS;

	if (*tmp != NULL)
		tmp++;
	for (; *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "cache_secs=", 11) == 0)
			backend->cache_secs = atoi(*tmp + 11);
		else {
			i_error("acl vfile: Unknown parameter: %s", *tmp);
			return -1;
		}
	}
	if (_backend->debug) {
		i_info("acl vfile: Global ACL directory: %s",
		       backend->global_dir);
	}

	_backend->cache =
		acl_cache_init(_backend,
			       sizeof(struct acl_backend_vfile_validity));
	return 0;
}

static void acl_backend_vfile_deinit(struct acl_backend *_backend)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;

	if (backend->acllist_pool != NULL) {
		array_free(&backend->acllist);
		pool_unref(&backend->acllist_pool);
	}
	pool_unref(&backend->backend.pool);
}

static const char *
acl_backend_vfile_get_local_dir(struct mail_storage *storage, const char *name)
{
	const char *dir;
	bool is_file;

	dir = mail_storage_get_mailbox_path(storage, name, &is_file);
	if (is_file) {
		dir = mailbox_list_get_path(storage->list, name,
					    MAILBOX_LIST_PATH_TYPE_CONTROL);
	}
	return dir;
}

static struct acl_object *
acl_backend_vfile_object_init(struct acl_backend *_backend,
			      struct mail_storage *storage, const char *name)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	struct acl_object_vfile *aclobj;
	const char *dir;

	aclobj = i_new(struct acl_object_vfile, 1);
	aclobj->aclobj.backend = _backend;
	aclobj->aclobj.name = i_strdup(name);
	aclobj->global_path = backend->global_dir == NULL ? NULL :
		i_strconcat(backend->global_dir, "/", name, NULL);

	if (storage == NULL) {
		/* the default ACL for mailbox list */
		dir = mailbox_list_get_path(_backend->list, NULL,
					    MAILBOX_LIST_PATH_TYPE_DIR);
	} else {
		dir = acl_backend_vfile_get_local_dir(storage, name);
	}
	aclobj->local_path = dir == NULL ? NULL :
		i_strconcat(dir, "/"ACL_FILENAME, NULL);
	return &aclobj->aclobj;
}

static const char *
get_parent_mailbox(struct mail_storage *storage, const char *name)
{
	const char *p;
	char sep;

	sep = mailbox_list_get_hierarchy_sep(storage->list);
	p = strrchr(name, sep);
	return p == NULL ? NULL : t_strdup_until(name, p);
}

static int
acl_backend_vfile_exists(struct acl_backend_vfile *backend, const char *path,
			 struct acl_vfile_validity *validity)
{
	struct stat st;

	if (validity->last_check + (time_t)backend->cache_secs > ioloop_time) {
		/* use the cached value */
		return validity->last_mtime != VALIDITY_MTIME_NOTFOUND;
	}

	validity->last_check = ioloop_time;
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			validity->last_mtime = VALIDITY_MTIME_NOTFOUND;
			return 0;
		}
		if (errno == EACCES) {
			validity->last_mtime = VALIDITY_MTIME_NOACCESS;
			return 1;
		}
		i_error("stat(%s) failed: %m", path);
		return -1;
	}
	validity->last_mtime = st.st_mtime;
	validity->last_size = st.st_size;
	return 1;
}

static bool
acl_backend_vfile_has_acl(struct acl_backend *_backend,
			  struct mail_storage *storage, const char *name)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	struct acl_backend_vfile_validity *old_validity, new_validity;
	const char *path, *local_path, *global_path, *dir;
	int ret;

	old_validity = acl_cache_get_validity(_backend->cache, name);
	if (old_validity != NULL)
		new_validity = *old_validity;
	else
		memset(&new_validity, 0, sizeof(new_validity));

	/* See if the mailbox exists. If we wanted recursive lookups we could
	   skip this, but at least for now we assume that if an existing
	   mailbox has no ACL it's equivalent to default ACLs. */
	path = mailbox_list_get_path(storage->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	ret = path == NULL ? 0 :
		acl_backend_vfile_exists(backend, path,
					 &new_validity.mailbox_validity);
	if (ret == 0) {
		dir = acl_backend_vfile_get_local_dir(storage, name);
		local_path = t_strconcat(dir, "/", name, NULL);
		ret = acl_backend_vfile_exists(backend, local_path,
					       &new_validity.local_validity);
	}
	if (ret == 0 && backend->global_dir != NULL) {
		global_path = t_strconcat(backend->global_dir, "/", name, NULL);
		ret = acl_backend_vfile_exists(backend, global_path,
					       &new_validity.global_validity);
	}
	acl_cache_set_validity(_backend->cache, name, &new_validity);
	return ret > 0;
}

static struct acl_object *
acl_backend_vfile_object_init_parent(struct acl_backend *backend,
				     struct mail_storage *storage,
				     const char *child_name)
{
	const char *parent;

	/* stop at the first parent that
	   a) has global ACL file
	   b) has local ACL file
	   c) exists */
	while ((parent = get_parent_mailbox(storage, child_name)) != NULL) {
		if (acl_backend_vfile_has_acl(backend, storage, parent))
			break;
		child_name = parent;
	}
	if (parent == NULL) {
		/* use the root */
		parent = "";
	}
	return acl_backend_vfile_object_init(backend, storage, parent);
}

static void acl_backend_vfile_object_deinit(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;

	if (array_is_created(&aclobj->rights))
		array_free(&aclobj->rights);
	if (aclobj->rights_pool != NULL)
		pool_unref(&aclobj->rights_pool);

	i_free(aclobj->local_path);
	i_free(aclobj->global_path);
	i_free(aclobj->aclobj.name);
	i_free(aclobj);
}

static const char *const *
acl_rights_alloc(pool_t pool, ARRAY_TYPE(const_string) *rights_arr)
{
	const char **ret, **rights;
	unsigned int i, dest, count;

	/* sort the rights first so we can easily drop duplicates */
	rights = array_get_modifiable(rights_arr, &count);
	qsort(rights, count, sizeof(*rights), i_strcmp_p);

	/* @UNSAFE */
	ret = p_new(pool, const char *, count + 1);
	if (count > 0) {
		ret[0] = rights[0];
		for (i = dest = 1; i < count; i++) {
			if (strcmp(rights[i-1], rights[i]) != 0)
				ret[dest++] = rights[i];
		}
	}
	return ret;
}

static const char *const *
acl_parse_rights(pool_t pool, const char *acl, const char **error_r)
{
	ARRAY_TYPE(const_string) rights;
	const char *const *names;
	unsigned int i;

	/* parse IMAP ACL list */
	while (*acl == ' ' || *acl == '\t')
		acl++;

	t_array_init(&rights, 64);
	while (*acl != '\0' && *acl != ' ' && *acl != '\t' && *acl != ':') {
		for (i = 0; acl_letter_map[i].letter != '\0'; i++) {
			if (acl_letter_map[i].letter == *acl)
				break;
		}

		if (acl_letter_map[i].letter == '\0') {
			*error_r = t_strdup_printf("Unknown ACL '%c'", *acl);
			return NULL;
		}

		array_append(&rights, &acl_letter_map[i].name, 1);
		acl++;
	}
	while (*acl == ' ' || *acl == '\t') acl++;

	if (*acl != '\0') {
		/* parse our own extended ACLs */
		i_assert(*acl == ':');

		names = t_strsplit_spaces(acl, ", ");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_append(&rights, &name, 1);
		}
	}

	return acl_rights_alloc(pool, &rights);
}

static int
acl_object_vfile_parse_line(struct acl_object_vfile *aclobj, bool global,
			    const char *path, const char *line,
			    unsigned int linenum)
{
	struct acl_rights rights;
	const char *p, *const *right_names, *error = NULL;

	if (*line == '\0' || *line == '#')
		return 0;

	/* <id> [<imap acls>] [:<named acls>] */
	p = strchr(line, ' ');
	if (p == NULL)
		p = "";
	else {
		line = t_strdup_until(line, p);
		p++;
	}

	memset(&rights, 0, sizeof(rights));
	rights.global = global;

	right_names = acl_parse_rights(aclobj->rights_pool, p, &error);
	if (*line != '-') {
		rights.rights = right_names;
	} else {
		line++;
		rights.neg_rights = right_names;
	}

	switch (*line) {
	case 'u':
		if (strncmp(line, "user=", 5) == 0) {
			rights.id_type = ACL_ID_USER;
			rights.identifier = line + 5;
			break;
		}
	case 'o':
		if (strcmp(line, "owner") == 0) {
			rights.id_type = ACL_ID_OWNER;
			break;
		}
	case 'g':
		if (strncmp(line, "group=", 6) == 0) {
			rights.id_type = ACL_ID_GROUP;
			rights.identifier = line + 6;
			break;
		} else if (strncmp(line, "group-override=", 15) == 0) {
			rights.id_type = ACL_ID_GROUP_OVERRIDE;
			rights.identifier = line + 15;
			break;
		}
	case 'a':
		if (strcmp(line, "authenticated") == 0) {
			rights.id_type = ACL_ID_AUTHENTICATED;
			break;
		} else if (strcmp(line, "anyone") == 0 ||
			   strcmp(line, "anonymous") == 0) {
			rights.id_type = ACL_ID_ANYONE;
			break;
		}
	default:
		error = t_strdup_printf("Unknown ID '%s'", line);
		break;
	}

	if (error != NULL) {
		i_error("ACL file %s line %u: %s", path, linenum, error);
		return -1;
	}

	rights.identifier = p_strdup(aclobj->rights_pool, rights.identifier);
	array_append(&aclobj->rights, &rights, 1);
	return 0;
}

static void acl_backend_remove_all_access(struct acl_object *aclobj)
{
	struct acl_rights_update rights;

	memset(&rights, 0, sizeof(rights));
	rights.rights.id_type = ACL_ID_ANYONE;
	rights.modify_mode = ACL_MODIFY_MODE_REPLACE;
	acl_cache_update(aclobj->backend->cache, aclobj->name, &rights);
}

static int
acl_backend_vfile_read(struct acl_object_vfile *aclobj,
		       bool global, const char *path,
		       struct acl_vfile_validity *validity, bool try_retry,
		       bool *is_dir_r)
{
	struct istream *input;
	struct stat st;
	const char *line;
	unsigned int linenum;
	int fd, ret = 0;

	*is_dir_r = FALSE;

	fd = nfs_safe_open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			if (aclobj->aclobj.backend->debug)
				i_info("acl vfile: file %s not found", path);
			validity->last_mtime = VALIDITY_MTIME_NOTFOUND;
		} else if (errno == EACCES) {
			if (aclobj->aclobj.backend->debug)
				i_info("acl vfile: no access to file %s", path);

			acl_backend_remove_all_access(&aclobj->aclobj);
			validity->last_mtime = VALIDITY_MTIME_NOACCESS;
		} else {
			i_error("open(%s) failed: %m", path);
			return -1;
		}

		validity->last_size = 0;
		validity->last_read_time = ioloop_time;
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		if (errno == ESTALE && try_retry) {
			(void)close(fd);
			return 0;
		}

		i_error("fstat(%s) failed: %m", path);
		(void)close(fd);
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		/* we opened a directory. */
		*is_dir_r = TRUE;
		(void)close(fd);
		return 0;
	}

	if (aclobj->aclobj.backend->debug)
		i_info("acl vfile: reading file %s", path);

	input = i_stream_create_fd(fd, 4096, FALSE);
	linenum = 1;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		T_BEGIN {
			ret = acl_object_vfile_parse_line(aclobj, global,
							  path, line,
							  linenum++);
		} T_END;
		if (ret < 0)
			break;
	}

	if (ret < 0) {
		/* parsing failure */
	} else if (input->stream_errno != 0) {
		if (input->stream_errno == ESTALE && try_retry)
			ret = 0;
		else {
			ret = -1;
			i_error("read(%s) failed: %m", path);
		}
	} else {
		if (fstat(fd, &st) < 0) {
			if (errno == ESTALE && try_retry)
				ret = 0;
			else {
				ret = -1;
				i_error("fstat(%s) failed: %m", path);
			}
		} else {
			ret = 1;
			validity->last_read_time = ioloop_time;
			validity->last_mtime = st.st_mtime;
			validity->last_size = st.st_size;
		}
	}

	i_stream_unref(&input);
	if (close(fd) < 0) {
		if (errno == ESTALE && try_retry)
			return 0;

		i_error("close(%s) failed: %m", path);
		return -1;
	}
	return ret;
}

static int
acl_backend_vfile_read_with_retry(struct acl_object_vfile *aclobj,
				  bool global, const char *path,
				  struct acl_vfile_validity *validity)
{
	unsigned int i;
	int ret;
	bool is_dir;

	if (path == NULL)
		return 0;

	for (i = 0;; i++) {
		ret = acl_backend_vfile_read(aclobj, global, path, validity,
					     i < ACL_ESTALE_RETRY_COUNT,
					     &is_dir);
		if (ret != 0)
			break;

		if (is_dir) {
			/* opened a directory. use dir/.DEFAULT instead */
			path = t_strconcat(path, "/.DEFAULT", NULL);
		} else {
			/* ESTALE - try again */
		}
	}

	return ret <= 0 ? -1 : 0;
}

static int
acl_backend_vfile_refresh(struct acl_object *aclobj, const char *path,
			  struct acl_vfile_validity *validity)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)aclobj->backend;
	struct stat st;

	if (validity == NULL)
		return 1;
	if (path == NULL ||
	    validity->last_check + (time_t)backend->cache_secs > ioloop_time)
		return 0;

	validity->last_check = ioloop_time;
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* if the file used to exist, we have to re-read it */
			return validity->last_mtime != VALIDITY_MTIME_NOTFOUND;
		} 
		if (errno == EACCES)
			return validity->last_mtime != VALIDITY_MTIME_NOACCESS;
		i_error("stat(%s) failed: %m", path);
		return -1;
	}

	if (st.st_mtime == validity->last_mtime &&
	    st.st_size == validity->last_size) {
		/* same timestamp, but if it was modified within the
		   same second we want to refresh it again later (but
		   do it only after a couple of seconds so we don't
		   keep re-reading it all the time within those
		   seconds) */
		time_t cache_secs = backend->cache_secs;

		if (validity->last_read_time != 0 &&
		    (st.st_mtime < validity->last_read_time - cache_secs ||
		     ioloop_time - validity->last_read_time <= cache_secs))
			return 0;
	}

	return 1;
}

int acl_backend_vfile_object_get_mtime(struct acl_object *aclobj,
				       time_t *mtime_r)
{
	struct acl_backend_vfile_validity *validity;

	validity = acl_cache_get_validity(aclobj->backend->cache, aclobj->name);
	if (validity == NULL)
		return -1;

	if (validity->local_validity.last_mtime != 0)
		*mtime_r = validity->local_validity.last_mtime;
	else if (validity->global_validity.last_mtime != 0)
		*mtime_r = validity->global_validity.last_mtime;
	else
		*mtime_r = 0;
	return 0;
}

static int acl_rights_cmp(const void *p1, const void *p2)
{
	const struct acl_rights *r1 = p1, *r2 = p2;

	if (r1->global != r2->global) {
		/* globals have higher priority than locals */
		return r1->global ? 1 : -1;
	}

	return r1->id_type - r2->id_type;
}

static void
acl_rights_merge(pool_t pool, const char *const **destp, const char *const *src)
{
	const char *const *dest = *destp;
	ARRAY_TYPE(const_string) rights;
	unsigned int i;

	t_array_init(&rights, 64);
	for (i = 0; dest[i] != NULL; i++)
		array_append(&rights, &dest[i], 1);
	for (i = 0; src[i] != NULL; i++)
		array_append(&rights, &src[i], 1);

	*destp = acl_rights_alloc(pool, &rights);
}

static void acl_backend_vfile_rights_sort(struct acl_object_vfile *aclobj)
{
	struct acl_rights *rights;
	unsigned int i, dest, count;

	if (!array_is_created(&aclobj->rights))
		return;

	rights = array_get_modifiable(&aclobj->rights, &count);
	qsort(rights, count, sizeof(*rights), acl_rights_cmp);

	/* merge identical identifiers */
	for (dest = 0, i = 1; i < count; i++) {
		if (rights[i].global == rights[dest].global &&
		    rights[i].id_type == rights[dest].id_type &&
		    null_strcmp(rights[i].identifier,
				rights[dest].identifier) == 0) {
			/* add i's rights to dest and delete i */
			acl_rights_merge(aclobj->rights_pool,
					 &rights[dest].rights,
					 rights[i].rights);
			acl_rights_merge(aclobj->rights_pool,
					 &rights[dest].neg_rights,
					 rights[i].neg_rights);
		} else {
			if (++dest != i)
				rights[dest] = rights[i];
		}
	}
	if (++dest != count)
		array_delete(&aclobj->rights, dest, count - dest);
}

static void acl_backend_vfile_cache_rebuild(struct acl_object_vfile *aclobj)
{
	struct acl_object *_aclobj = &aclobj->aclobj;
	struct acl_rights_update ru;
	const struct acl_rights *rights;
	unsigned int i, count;

	acl_cache_flush(_aclobj->backend->cache, _aclobj->name);

	if (!array_is_created(&aclobj->rights))
		return;

	memset(&ru, 0, sizeof(ru));
	rights = array_get(&aclobj->rights, &count);
	for (i = 0; i < count; i++) {
		ru.modify_mode = ACL_MODIFY_MODE_REPLACE;
		ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
		ru.rights = rights[i];
		acl_cache_update(_aclobj->backend->cache, _aclobj->name, &ru);
	}
}

static int acl_backend_vfile_object_refresh_cache(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_aclobj->backend;
	struct acl_backend_vfile_validity *old_validity;
	struct acl_backend_vfile_validity validity;
	time_t mtime;
	int ret;

	old_validity = acl_cache_get_validity(_aclobj->backend->cache,
					      _aclobj->name);
	ret = acl_backend_vfile_refresh(_aclobj, aclobj->global_path,
					old_validity == NULL ? NULL :
					&old_validity->global_validity);
	if (ret == 0) {
		ret = acl_backend_vfile_refresh(_aclobj, aclobj->local_path,
						old_validity == NULL ? NULL :
						&old_validity->local_validity);
	}
	if (ret <= 0)
		return ret;

	/* either global or local ACLs changed, need to re-read both */
	if (!array_is_created(&aclobj->rights)) {
		aclobj->rights_pool =
			pool_alloconly_create("acl rights", 256);
		i_array_init(&aclobj->rights, 16);
	} else {
		array_clear(&aclobj->rights);
		p_clear(aclobj->rights_pool);
	}

	memset(&validity, 0, sizeof(validity));
	if (acl_backend_vfile_read_with_retry(aclobj, TRUE, aclobj->global_path,
					      &validity.global_validity) < 0)
		return -1;
	if (acl_backend_vfile_read_with_retry(aclobj, FALSE, aclobj->local_path,
					      &validity.local_validity) < 0)
		return -1;

	acl_backend_vfile_rights_sort(aclobj);
	/* update cache only after we've successfully read everything */
	acl_backend_vfile_cache_rebuild(aclobj);
	acl_cache_set_validity(_aclobj->backend->cache,
			       _aclobj->name, &validity);

	if (acl_backend_vfile_object_get_mtime(_aclobj, &mtime) == 0)
		acl_backend_vfile_acllist_verify(backend, _aclobj->name, mtime);
	return 0;
}

static int
acl_backend_vfile_object_update(struct acl_object *aclobj ATTR_UNUSED,
				const struct acl_rights_update *rights
					ATTR_UNUSED)
{
	/* FIXME */
	return -1;
}

static struct acl_object_list_iter *
acl_backend_vfile_object_list_init(struct acl_object *aclobj)
{
	struct acl_object_list_iter *iter;

	iter = i_new(struct acl_object_list_iter, 1);
	iter->aclobj = aclobj;

	if (aclobj->backend->v.object_refresh_cache(aclobj) < 0)
		iter->failed = TRUE;
	return iter;
}

static int
acl_backend_vfile_object_list_next(struct acl_object_list_iter *iter,
				   struct acl_rights *rights_r)
{
	struct acl_object_vfile *aclobj =
		(struct acl_object_vfile *)iter->aclobj;
	const struct acl_rights *rights;

	if (!array_is_created(&aclobj->rights) ||
	    iter->idx == array_count(&aclobj->rights))
		return 0;

	rights = array_idx(&aclobj->rights, iter->idx++);
	*rights_r = *rights;
	return 1;
}

static void
acl_backend_vfile_object_list_deinit(struct acl_object_list_iter *iter)
{
	i_free(iter);
}

struct acl_backend_vfuncs acl_backend_vfile = {
	acl_backend_vfile_alloc,
	acl_backend_vfile_init,
	acl_backend_vfile_deinit,
	acl_backend_vfile_nonowner_iter_init,
	acl_backend_vfile_nonowner_iter_next,
	acl_backend_vfile_nonowner_iter_deinit,
	acl_backend_vfile_object_init,
	acl_backend_vfile_object_init_parent,
	acl_backend_vfile_object_deinit,
	acl_backend_vfile_object_refresh_cache,
	acl_backend_vfile_object_update,
	acl_backend_vfile_object_list_init,
	acl_backend_vfile_object_list_next,
	acl_backend_vfile_object_list_deinit
};
