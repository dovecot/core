/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "ostream.h"
#include "file-dotlock.h"
#include "nfs-workarounds.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "acl-cache.h"
#include "acl-backend-vfile.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ACL_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
#define ACL_VFILE_DEFAULT_CACHE_SECS 30

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
	{ 'p', MAIL_ACL_POST },
	{ 'e', MAIL_ACL_EXPUNGE },
	{ 'k', MAIL_ACL_CREATE },
	{ 'x', MAIL_ACL_DELETE },
	{ 'a', MAIL_ACL_ADMIN },
	{ '\0', NULL }
};

static struct dotlock_settings dotlock_set = {
	.timeout = 30,
	.stale_timeout = 120
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
		if (strncmp(*tmp, "cache_secs=", 11) == 0) {
			if (str_to_uint(*tmp + 11, &backend->cache_secs) < 0) {
				i_error("acl vfile: Invalid cache_secs value: %s",
					*tmp + 11);
				return -1;
			}
		} else {
			i_error("acl vfile: Unknown parameter: %s", *tmp);
			return -1;
		}
	}
	if (_backend->debug) {
		i_debug("acl vfile: Global ACL directory: %s",
			backend->global_dir == NULL ? "(none)" :
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
acl_backend_vfile_get_local_dir(struct acl_backend *backend, const char *name)
{
	struct mail_namespace *ns;
	const char *dir, *inbox;

	if (*name == '\0')
		name = NULL;

	ns = mailbox_list_get_namespace(backend->list);
	if (mail_storage_is_mailbox_file(ns->storage)) {
		dir = mailbox_list_get_path(ns->list, name,
					    MAILBOX_LIST_PATH_TYPE_CONTROL);
	} else {
		dir = mailbox_list_get_path(ns->list, name,
					    MAILBOX_LIST_PATH_TYPE_MAILBOX);
	}
	if (name == NULL && dir != NULL) {
		/* verify that the directory isn't same as INBOX's directory.
		   this is mainly for Maildir. */
		inbox = mailbox_list_get_path(ns->list, "INBOX",
					      MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(inbox, dir) == 0) {
			/* can't have default ACLs with this setup */
			return NULL;
		}
	}
	return dir;
}

static struct acl_object *
acl_backend_vfile_object_init(struct acl_backend *_backend,
			      const char *name)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	struct acl_object_vfile *aclobj;
	const char *dir;

	aclobj = i_new(struct acl_object_vfile, 1);
	aclobj->aclobj.backend = _backend;
	aclobj->aclobj.name = i_strdup(name);

	if (backend->global_dir != NULL) T_BEGIN {
		struct mail_namespace *ns =
			mailbox_list_get_namespace(_backend->list);
		string_t *vname;

		vname = t_str_new(128);
		mail_namespace_get_vname(ns, vname, name);
		aclobj->global_path = i_strconcat(backend->global_dir, "/",
						  str_c(vname), NULL);
	} T_END;

	dir = acl_backend_vfile_get_local_dir(_backend, name);
	aclobj->local_path = dir == NULL ? NULL :
		i_strconcat(dir, "/"ACL_FILENAME, NULL);
	return &aclobj->aclobj;
}

static const char *
get_parent_mailbox(struct acl_backend *backend, const char *name)
{
	struct mail_namespace *ns = mailbox_list_get_namespace(backend->list);
	const char *p;

	p = strrchr(name, ns->real_sep);
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
		if (errno == ENOENT || errno == ENOTDIR) {
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
acl_backend_vfile_has_acl(struct acl_backend *_backend, const char *name)
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
	path = mailbox_list_get_path(_backend->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	ret = path == NULL ? 0 :
		acl_backend_vfile_exists(backend, path,
					 &new_validity.mailbox_validity);
	if (ret == 0 &&
	    (dir = acl_backend_vfile_get_local_dir(_backend, name)) != NULL) {
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
				     const char *child_name)
{
	const char *parent;

	/* stop at the first parent that
	   a) has global ACL file
	   b) has local ACL file
	   c) exists */
	while ((parent = get_parent_mailbox(backend, child_name)) != NULL) {
		if (acl_backend_vfile_has_acl(backend, parent))
			break;
		child_name = parent;
	}
	if (parent == NULL) {
		/* use the root */
		parent = "";
	}
	return acl_backend_vfile_object_init(backend, parent);
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
acl_rights_alloc(pool_t pool, ARRAY_TYPE(const_string) *rights_arr,
		 bool dup_strings)
{
	const char **ret, *const *rights;
	unsigned int i, dest, count;

	/* sort the rights first so we can easily drop duplicates */
	array_sort(rights_arr, i_strcmp_p);

	/* @UNSAFE */
	rights = array_get(rights_arr, &count);
	ret = p_new(pool, const char *, count + 1);
	if (count > 0) {
		ret[0] = rights[0];
		for (i = dest = 1; i < count; i++) {
			if (strcmp(rights[i-1], rights[i]) != 0)
				ret[dest++] = rights[i];
		}
		ret[dest] = NULL;
		if (dup_strings) {
			for (i = 0; i < dest; i++)
				ret[i] = p_strdup(pool, ret[i]);
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
		if (*acl != ':') {
			*error_r = "Missing ':' prefix in ACL extensions";
			return NULL;
		}

		names = t_strsplit_spaces(acl + 1, ", \t");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_append(&rights, &name, 1);
		}
	}

	return acl_rights_alloc(pool, &rights, FALSE);
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
	if (*line == '"') {
		for (p = line + 1; *p != '\0'; p++) {
			if (*p == '\\' && p[1] != '\0')
				p++;
			else if (*p == '"')
				break;
		}
		if (p[0] != '"' || (p[1] != ' ' && p[1] != '\0')) {
			i_error("ACL file %s line %u: Invalid quoted ID",
				path, linenum);
			return -1;
		}
		line = t_strdup_until(line + 1, p);
		line = str_unescape(t_strdup_noconst(line));
		p++;
	} else {
		p = strchr(line, ' ');
		if (p == NULL)
			p = "";
		else {
			line = t_strdup_until(line, p);
			p++;
		}
	}

	memset(&rights, 0, sizeof(rights));
	rights.global = global;

	right_names = acl_parse_rights(aclobj->rights_pool, p, &error);
	if (*line != '-')
		rights.rights = right_names;
	else {
		line++;
		rights.neg_rights = right_names;
	}

	if (acl_identifier_parse(line, &rights) < 0)
		error = t_strdup_printf("Unknown ID '%s'", line);

	if (error != NULL) {
		i_error("ACL file %s line %u: %s", path, linenum, error);
		return -1;
	}

	rights.identifier = p_strdup(aclobj->rights_pool, rights.identifier);
	array_append(&aclobj->rights, &rights, 1);
	return 0;
}

static void acl_backend_remove_all_access(struct acl_object_vfile *aclobj)
{
	static const char *null = NULL;
	struct acl_rights rights;

	memset(&rights, 0, sizeof(rights));
	rights.id_type = ACL_ID_ANYONE;
	rights.rights = &null;
	array_append(&aclobj->rights, &rights, 1);

	rights.id_type = ACL_ID_OWNER;
	rights.rights = &null;
	array_append(&aclobj->rights, &rights, 1);
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
		if (errno == ENOENT || errno == ENOTDIR) {
			if (aclobj->aclobj.backend->debug)
				i_debug("acl vfile: file %s not found", path);
			validity->last_mtime = VALIDITY_MTIME_NOTFOUND;
		} else if (errno == EACCES) {
			if (aclobj->aclobj.backend->debug)
				i_debug("acl vfile: no access to file %s",
					path);

			acl_backend_remove_all_access(aclobj);
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
		i_debug("acl vfile: reading file %s", path);

	input = i_stream_create_fd(fd, 4096, FALSE);
	i_stream_set_return_partial_line(input, TRUE);
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
	int ret;

	if (validity == NULL)
		return 1;
	if (path == NULL ||
	    validity->last_check + (time_t)backend->cache_secs > ioloop_time)
		return 0;

	validity->last_check = ioloop_time;
	ret = stat(path, &st);
	if (ret == 0 && S_ISDIR(st.st_mode)) {
		/* it's a directory. use dir/.DEFAULT instead */
		path = t_strconcat(path, "/.DEFAULT", NULL);
		ret = stat(path, &st);
	}

	if (ret < 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
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

static int acl_rights_cmp(const struct acl_rights *r1,
			  const struct acl_rights *r2)
{
	int ret;

	if (r1->global != r2->global) {
		/* globals have higher priority than locals */
		return r1->global ? 1 : -1;
	}

	ret = r1->id_type - r2->id_type;
	if (ret != 0)
		return ret;

	return null_strcmp(r1->identifier, r2->identifier);
}

static void
acl_rights_merge(pool_t pool, const char *const **destp, const char *const *src,
		 bool dup_strings)
{
	const char *const *dest = *destp;
	ARRAY_TYPE(const_string) rights;
	unsigned int i;

	t_array_init(&rights, 64);
	if (dest != NULL) {
		for (i = 0; dest[i] != NULL; i++)
			array_append(&rights, &dest[i], 1);
	}
	if (src != NULL) {
		for (i = 0; src[i] != NULL; i++)
			array_append(&rights, &src[i], 1);
	}

	*destp = acl_rights_alloc(pool, &rights, dup_strings);
}

static void acl_backend_vfile_rights_sort(struct acl_object_vfile *aclobj)
{
	struct acl_rights *rights;
	unsigned int i, dest, count;

	if (!array_is_created(&aclobj->rights))
		return;

	array_sort(&aclobj->rights, acl_rights_cmp);

	/* merge identical identifiers */
	rights = array_get_modifiable(&aclobj->rights, &count);
	for (dest = 0, i = 1; i < count; i++) {
		if (acl_rights_cmp(&rights[i], &rights[dest]) == 0) {
			/* add i's rights to dest and delete i */
			acl_rights_merge(aclobj->rights_pool,
					 &rights[dest].rights,
					 rights[i].rights, FALSE);
			acl_rights_merge(aclobj->rights_pool,
					 &rights[dest].neg_rights,
					 rights[i].neg_rights, FALSE);
		} else {
			if (++dest != i)
				rights[dest] = rights[i];
		}
	}
	if (++dest != count)
		array_delete(&aclobj->rights, dest, count - dest);
}

static void apply_owner_default_rights(struct acl_object *_aclobj)
{
	struct acl_rights_update ru;
	const char *null = NULL;

	memset(&ru, 0, sizeof(ru));
	ru.modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
	ru.rights.id_type = ACL_ID_OWNER;
	ru.rights.rights = _aclobj->backend->default_rights;
	ru.rights.neg_rights = &null;
	acl_cache_update(_aclobj->backend->cache, _aclobj->name, &ru);
}

static void acl_backend_vfile_cache_rebuild(struct acl_object_vfile *aclobj)
{
	struct acl_object *_aclobj = &aclobj->aclobj;
	struct acl_rights_update ru;
	enum acl_modify_mode add_mode;
	const struct acl_rights *rights, *prev_match = NULL;
	unsigned int i, count;
	bool first_global = TRUE;

	acl_cache_flush(_aclobj->backend->cache, _aclobj->name);

	if (!array_is_created(&aclobj->rights))
		return;

	/* Rights are sorted by their 1) locals first, globals next,
	   2) acl_id_type. We'll apply only the rights matching ourself.

	   Every time acl_id_type or local/global changes, the new ACLs will
	   replace all of the existing ACLs. Basically this means that if
	   user belongs to multiple matching groups or group-overrides, their
	   ACLs are merged. In all other situations the ACLs are replaced
	   (because there aren't duplicate rights entries and a user can't
	   match multiple usernames). */
	memset(&ru, 0, sizeof(ru));
	rights = array_get(&aclobj->rights, &count);
	if (!acl_backend_user_is_owner(_aclobj->backend))
		i = 0;
	else {
		/* we're the owner. skip over all rights entries until we
		   reach ACL_ID_OWNER or higher, or alternatively when we
		   reach a global ACL (even ACL_ID_ANYONE overrides owner's
		   rights if it's global) */
		for (i = 0; i < count; i++) {
			if (rights[i].id_type >= ACL_ID_OWNER ||
			    rights[i].global)
				break;
		}
		apply_owner_default_rights(_aclobj);
		/* now continue applying the rest of the rights,
		   if there are any */
	}
	for (; i < count; i++) {
		if (!acl_backend_rights_match_me(_aclobj->backend, &rights[i]))
			continue;

		if (prev_match == NULL ||
		    prev_match->id_type != rights[i].id_type ||
		    prev_match->global != rights[i].global) {
			/* replace old ACLs */
			add_mode = ACL_MODIFY_MODE_REPLACE;
		} else {
			/* merging to existing ACLs */
			i_assert(rights[i].id_type == ACL_ID_GROUP ||
				 rights[i].id_type == ACL_ID_GROUP_OVERRIDE);
			add_mode = ACL_MODIFY_MODE_ADD;
		}
		prev_match = &rights[i];

		/* If [neg_]rights is NULL it needs to be ignored.
		   The easiest way to do that is to just mark it with
		   REMOVE mode */
		ru.modify_mode = rights[i].rights == NULL ?
			ACL_MODIFY_MODE_REMOVE : add_mode;
		ru.neg_modify_mode = rights[i].neg_rights == NULL ?
			ACL_MODIFY_MODE_REMOVE : add_mode;
		ru.rights = rights[i];
		if (rights[i].global && first_global) {
			/* first global: reset negative ACLs so local ACLs
			   can't mess things up via them */
			first_global = FALSE;
			ru.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
		}
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

static int acl_backend_vfile_update_begin(struct acl_object_vfile *aclobj,
					  struct dotlock **dotlock_r)
{
	struct acl_object *_aclobj = &aclobj->aclobj;
	const char *gid_origin;
	mode_t mode;
	gid_t gid;
	int fd;

	if (aclobj->local_path == NULL) {
		i_error("Can't update acl object '%s': No local acl file path",
			aclobj->aclobj.name);
		return -1;
	}

	/* first lock the ACL file */
	mailbox_list_get_permissions(_aclobj->backend->list, _aclobj->name,
				     &mode, &gid, &gid_origin);
	fd = file_dotlock_open_group(&dotlock_set, aclobj->local_path, 0,
				     mode, gid, gid_origin, dotlock_r);
	if (fd == -1) {
		i_error("file_dotlock_open(%s) failed: %m", aclobj->local_path);
		return -1;
	}

	/* locked successfully, re-read the existing file to make sure we
	   don't lose any changes. */
	acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
	if (acl_backend_vfile_object_refresh_cache(_aclobj) < 0) {
		file_dotlock_delete(dotlock_r);
		return -1;
	}
	return fd;
}

static bool modify_right_list(pool_t pool,
			      const char *const **rightsp,
			      const char *const *modify_rights,
			      enum acl_modify_mode modify_mode)
{
	const char *const *old_rights = *rightsp;
	const char *const *new_rights = NULL;
	const char *null = NULL;
	ARRAY_TYPE(const_string) rights;
	unsigned int i, j;

	if (modify_rights == NULL && modify_mode != ACL_MODIFY_MODE_CLEAR) {
		/* nothing to do here */
		return FALSE;
	}

	switch (modify_mode) {
	case ACL_MODIFY_MODE_REMOVE:
		if (old_rights == NULL || *old_rights == NULL) {
			/* nothing to do */
			return FALSE;
		}
		t_array_init(&rights, 64);
		for (i = 0; old_rights[i] != NULL; i++) {
			for (j = 0; modify_rights[j] != NULL; j++) {
				if (strcmp(old_rights[i], modify_rights[j]) == 0)
					break;
			}
			if (modify_rights[j] == NULL)
				array_append(&rights, &old_rights[i], 1);
		}
		new_rights = &null;
		modify_rights = array_count(&rights) == 0 ? NULL :
			array_idx(&rights, 0);
		acl_rights_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_ADD:
		new_rights = old_rights;
		acl_rights_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_REPLACE:
		new_rights = &null;
		acl_rights_merge(pool, &new_rights, modify_rights, TRUE);
		break;
	case ACL_MODIFY_MODE_CLEAR:
		if (*rightsp == NULL) {
			/* ACL didn't exist before either */
			return FALSE;
		}
		*rightsp = NULL;
		return TRUE;
	}
	i_assert(new_rights != NULL);
	*rightsp = new_rights;

	if (old_rights == NULL)
		return new_rights[0] != NULL;

	/* see if anything changed */
	for (i = 0; old_rights[i] != NULL && new_rights[i] != NULL; i++) {
		if (strcmp(old_rights[i], new_rights[i]) != 0)
			return TRUE;
	}
	return old_rights[i] != NULL || new_rights[i] != NULL;
}

static bool
vfile_object_modify_right(struct acl_object_vfile *aclobj, unsigned int idx,
			  const struct acl_rights_update *update)
{
	struct acl_rights *right;
	bool c1, c2;

	right = array_idx_modifiable(&aclobj->rights, idx);
	c1 = modify_right_list(aclobj->rights_pool, &right->rights,
			       update->rights.rights, update->modify_mode);
	c2 = modify_right_list(aclobj->rights_pool, &right->neg_rights,
			       update->rights.neg_rights,
			       update->neg_modify_mode);

	if (right->rights == NULL && right->neg_rights == NULL) {
		/* this identifier no longer exists */
		array_delete(&aclobj->rights, idx, 1);
		c1 = TRUE;
	}
	return c1 || c2;
}

static bool
vfile_object_add_right(struct acl_object_vfile *aclobj, unsigned int idx,
		       const struct acl_rights_update *update)
{
	struct acl_rights right;

	if (update->modify_mode == ACL_MODIFY_MODE_REMOVE &&
	    update->neg_modify_mode == ACL_MODIFY_MODE_REMOVE) {
		/* nothing to do */
		return FALSE;
	}

	memset(&right, 0, sizeof(right));
	right.id_type = update->rights.id_type;
	right.identifier = p_strdup(aclobj->rights_pool,
				    update->rights.identifier);
	array_insert(&aclobj->rights, idx, &right, 1);
	return vfile_object_modify_right(aclobj, idx, update);
}

static void vfile_write_rights_list(string_t *dest, const char *const *rights)
{
	char c2[2];
	unsigned int i, j, pos;

	c2[1] = '\0';
	pos = str_len(dest);
	for (i = 0; rights[i] != NULL; i++) {
		/* use letters if possible */
		for (j = 0; acl_letter_map[j].name != NULL; j++) {
			if (strcmp(rights[i], acl_letter_map[j].name) == 0) {
				c2[0] = acl_letter_map[j].letter;
				str_insert(dest, pos, c2);
				pos++;
				break;
			}
		}
		if (acl_letter_map[j].name == NULL) {
			/* fallback to full name */
			str_append_c(dest, ' ');
			str_append(dest, rights[i]);
		}
	}
	if (pos + 1 < str_len(dest)) {
		c2[0] = ':';
		str_insert(dest, pos + 1, c2);
	}
}

static void
vfile_write_right(string_t *dest, const struct acl_rights *right,
		  bool neg)
{
	const char *const *rights = neg ? right->neg_rights : right->rights;

	if (neg) str_append_c(dest,'-');
	acl_rights_write_id(dest, right);

	if (strchr(str_c(dest), ' ') != NULL) T_BEGIN {
		/* need to escape it */
		const char *escaped = t_strdup(str_escape(str_c(dest)));
		str_truncate(dest, 0);
		str_printfa(dest, "\"%s\"", escaped);
	} T_END;

	str_append_c(dest, ' ');
	vfile_write_rights_list(dest, rights);
	str_append_c(dest, '\n');
}

static int
acl_backend_vfile_update_write(struct acl_object_vfile *aclobj,
			       int fd, const char *path)
{
	struct ostream *output;
	string_t *str;
	const struct acl_rights *rights;
	unsigned int i, count;
	int ret = 0;

	output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(output);

	str = str_new(default_pool, 256);
	/* rights are sorted with globals at the end, so we can stop at the
	   first global */
	rights = array_get(&aclobj->rights, &count);
	for (i = 0; i < count && !rights[i].global; i++) {
		if (rights[i].rights != NULL) {
			vfile_write_right(str, &rights[i], FALSE);
			o_stream_send(output, str_data(str), str_len(str));
			str_truncate(str, 0);
		}
		if (rights[i].neg_rights != NULL) {
			vfile_write_right(str, &rights[i], TRUE);
			o_stream_send(output, str_data(str), str_len(str));
			str_truncate(str, 0);
		}
	}
	str_free(&str);
	if (o_stream_flush(output) < 0) {
		i_error("write(%s) failed: %m", path);
		ret = -1;
	}
	o_stream_destroy(&output);
	/* we really don't want to lose ACL files' contents, so fsync() always
	   before renaming */
	if (fsync(fd) < 0) {
		i_error("fsync(%s) failed: %m", path);
		ret = -1;
	}
	return ret;
}

static void acl_backend_vfile_update_cache(struct acl_object *_aclobj, int fd)
{
	struct acl_backend_vfile_validity *validity;
	struct stat st;

	if (fstat(fd, &st) < 0) {
		/* we'll just recalculate or fail it later */
		acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
		return;
	}

	validity = acl_cache_get_validity(_aclobj->backend->cache,
					  _aclobj->name);
	validity->local_validity.last_read_time = ioloop_time;
	validity->local_validity.last_mtime = st.st_mtime;
	validity->local_validity.last_size = st.st_size;
}

static int
acl_backend_vfile_object_update(struct acl_object *_aclobj,
				const struct acl_rights_update *update)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_aclobj->backend;
	struct dotlock *dotlock;
	const char *path;
	unsigned int i;
	int fd;
	bool changed;

	/* global ACLs can't be updated here */
	i_assert(!update->rights.global);

	fd = acl_backend_vfile_update_begin(aclobj, &dotlock);
	if (fd == -1)
		return -1;

	if (!array_bsearch_insert_pos(&aclobj->rights, &update->rights,
				      acl_rights_cmp, &i))
		changed = vfile_object_add_right(aclobj, i, update);
	else
		changed = vfile_object_modify_right(aclobj, i, update);
	if (!changed) {
		file_dotlock_delete(&dotlock);
		return 0;
	}

	/* ACLs were really changed, write the new ones */
	path = file_dotlock_get_lock_path(dotlock);
	if (acl_backend_vfile_update_write(aclobj, fd, path) < 0) {
		file_dotlock_delete(&dotlock);
		acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
		return -1;
	}
	acl_backend_vfile_update_cache(_aclobj, fd);
	if (file_dotlock_replace(&dotlock, 0) < 0) {
		acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
		return -1;
	}
	/* make sure dovecot-acl-list gets updated if we changed any
	   lookup rights. */
	if (acl_rights_has_nonowner_lookup_changes(&update->rights) ||
	    update->modify_mode == ACL_MODIFY_MODE_REPLACE ||
	    update->modify_mode == ACL_MODIFY_MODE_CLEAR)
		(void)acl_backend_vfile_acllist_rebuild(backend);
	return 0;
}

static struct acl_object_list_iter *
acl_backend_vfile_object_list_init(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj =
		(struct acl_object_vfile *)_aclobj;
	struct acl_object_list_iter *iter;

	iter = i_new(struct acl_object_list_iter, 1);
	iter->aclobj = _aclobj;

	if (!array_is_created(&aclobj->rights)) {
		/* we may have the object cached, but we don't have all the
		   rights read into memory */
		acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
	}

	if (_aclobj->backend->v.object_refresh_cache(_aclobj) < 0)
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

	if (iter->idx == array_count(&aclobj->rights))
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
	acl_backend_vfile_nonowner_lookups_rebuild,
	acl_backend_vfile_object_init,
	acl_backend_vfile_object_init_parent,
	acl_backend_vfile_object_deinit,
	acl_backend_vfile_object_refresh_cache,
	acl_backend_vfile_object_update,
	acl_backend_vfile_object_list_init,
	acl_backend_vfile_object_list_next,
	acl_backend_vfile_object_list_deinit
};
