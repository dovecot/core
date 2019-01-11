/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "nfs-workarounds.h"
#include "mail-storage-private.h"
#include "acl-global-file.h"
#include "acl-cache.h"
#include "acl-backend-vfile.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ACL_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT
#define ACL_VFILE_DEFAULT_CACHE_SECS 30

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
	struct stat st;
	const char *const *tmp;

	tmp = t_strsplit(data, ":");
	backend->global_path = p_strdup_empty(_backend->pool, *tmp);
	backend->cache_secs = ACL_VFILE_DEFAULT_CACHE_SECS;

	if (*tmp != NULL)
		tmp++;
	for (; *tmp != NULL; tmp++) {
		if (str_begins(*tmp, "cache_secs=")) {
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
	if (backend->global_path != NULL) {
		if (stat(backend->global_path, &st) < 0) {
			if (errno != ENOENT) {
				i_error("acl vfile: stat(%s) failed: %m",
					backend->global_path);
				return -1;
			}
		} else if (!S_ISDIR(st.st_mode)) {
			_backend->global_file =
				acl_global_file_init(backend->global_path, backend->cache_secs,
						     _backend->debug);
		}
	}
	if (_backend->debug) {
		if (backend->global_path == NULL)
			i_debug("acl vfile: Global ACLs disabled");
		else if (_backend->global_file != NULL) {
			i_debug("acl vfile: Global ACL file: %s",
				backend->global_path);
		} else {
			i_debug("acl vfile: Global ACL legacy directory: %s",
				backend->global_path);
		}
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
	if (_backend->global_file != NULL)
		acl_global_file_deinit(&_backend->global_file);
	pool_unref(&backend->backend.pool);
}

static const char *
acl_backend_vfile_get_local_dir(struct acl_backend *backend,
				const char *name, const char *vname)
{
	struct mail_namespace *ns = mailbox_list_get_namespace(backend->list);
	struct mailbox_list *list = ns->list;
	struct mail_storage *storage;
	enum mailbox_list_path_type type;
	const char *dir, *inbox;

	if (*name == '\0')
		name = NULL;

	if (backend->globals_only)
		return NULL;

	/* ACL files are very important. try to keep them among the main
	   mail files. that's not possible though with a) if the mailbox is
	   a file or b) if the mailbox path doesn't point to filesystem. */
	if (mailbox_list_get_storage(&list, vname, &storage) < 0)
		return NULL;
	i_assert(list == ns->list);

	type = mail_storage_is_mailbox_file(storage) ||
		(storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) != 0 ?
		MAILBOX_LIST_PATH_TYPE_CONTROL : MAILBOX_LIST_PATH_TYPE_MAILBOX;
	if (name == NULL) {
		if (!mailbox_list_get_root_path(list, type, &dir))
			return NULL;
	} else {
		if (mailbox_list_get_path(list, name, type, &dir) <= 0)
			return NULL;
	}

	/* verify that the directory isn't same as INBOX's directory.
	   this is mainly for Maildir. */
	if (name == NULL &&
	    mailbox_list_get_path(list, "INBOX",
				  MAILBOX_LIST_PATH_TYPE_MAILBOX, &inbox) > 0 &&
	    strcmp(inbox, dir) == 0) {
		/* can't have default ACLs with this setup */
		return NULL;
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
	const char *dir, *vname, *error;

	aclobj = i_new(struct acl_object_vfile, 1);
	aclobj->aclobj.backend = _backend;
	aclobj->aclobj.name = i_strdup(name);

	T_BEGIN {
		if (*name == '\0' ||
		    mailbox_list_is_valid_name(_backend->list, name, &error)) {
			vname = *name == '\0' ? "" :
				mailbox_list_get_vname(_backend->list, name);

			dir = acl_backend_vfile_get_local_dir(_backend, name, vname);
			aclobj->local_path = dir == NULL ? NULL :
				i_strconcat(dir, "/"ACL_FILENAME, NULL);
			if (backend->global_path != NULL &&
			    _backend->global_file == NULL) {
				aclobj->global_path =
					i_strconcat(backend->global_path, "/", vname, NULL);
			}
		} else {
			/* Invalid mailbox name, just use the default
			   global ACL files */
		}
	} T_END;
	return &aclobj->aclobj;
}

static const char *
get_parent_mailbox(struct acl_backend *backend, const char *name)
{
	const char *p;

	p = strrchr(name, mailbox_list_get_hierarchy_sep(backend->list));
	return p == NULL ? NULL : t_strdup_until(name, p);
}

static int
acl_backend_vfile_exists(struct acl_backend_vfile *backend, const char *path,
			 struct acl_vfile_validity *validity)
{
	struct stat st;

	if (validity->last_check + (time_t)backend->cache_secs > ioloop_time) {
		/* use the cached value */
		return validity->last_mtime != ACL_VFILE_VALIDITY_MTIME_NOTFOUND ? 1 : 0;
	}

	validity->last_check = ioloop_time;
	if (stat(path, &st) < 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
			validity->last_mtime = ACL_VFILE_VALIDITY_MTIME_NOTFOUND;
			return 0;
		}
		if (errno == EACCES) {
			validity->last_mtime = ACL_VFILE_VALIDITY_MTIME_NOACCESS;
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
	const char *path, *local_path, *global_path, *dir, *vname = "";
	const char *error;
	int ret;

	old_validity = acl_cache_get_validity(_backend->cache, name);
	if (old_validity != NULL)
		new_validity = *old_validity;
	else
		i_zero(&new_validity);

	/* See if the mailbox exists. If we wanted recursive lookups we could
	   skip this, but at least for now we assume that if an existing
	   mailbox has no ACL it's equivalent to default ACLs. */
	if (mailbox_list_get_path(_backend->list, name,
				  MAILBOX_LIST_PATH_TYPE_MAILBOX, &path) <= 0)
		ret = -1;
	else {
		ret = acl_backend_vfile_exists(backend, path,
					       &new_validity.mailbox_validity);
	}

	if (ret == 0 &&
	    (*name == '\0' ||
	     mailbox_list_is_valid_name(_backend->list, name, &error))) {
		vname = *name == '\0' ? "" :
			mailbox_list_get_vname(_backend->list, name);
		dir = acl_backend_vfile_get_local_dir(_backend, name, vname);
		if (dir != NULL) {
			local_path = t_strconcat(dir, "/", name, NULL);
			ret = acl_backend_vfile_exists(backend, local_path,
						       &new_validity.local_validity);
		}
	}

	if (ret == 0 && backend->global_path != NULL) {
		if (_backend->global_file != NULL) {
			ret = acl_global_file_refresh(_backend->global_file);
			if (ret == 0 && acl_global_file_have_any(_backend->global_file, vname))
				ret = 1;
		} else {
			global_path = t_strconcat(backend->global_path, "/", name, NULL);
			ret = acl_backend_vfile_exists(backend, global_path,
						       &new_validity.global_validity);
		}
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
		parent = acl_backend_get_default_object(backend)->name;
	}
	return acl_backend_vfile_object_init(backend, parent);
}

static void acl_backend_vfile_object_deinit(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;

	i_free(aclobj->local_path);
	i_free(aclobj->global_path);

	if (array_is_created(&aclobj->aclobj.rights))
		array_free(&aclobj->aclobj.rights);
	pool_unref(&aclobj->aclobj.rights_pool);
	i_free(aclobj->aclobj.name);
	i_free(aclobj);
}

static int
acl_backend_vfile_read(struct acl_object *aclobj, bool global, const char *path,
		       struct acl_vfile_validity *validity, bool try_retry,
		       bool *is_dir_r)
{
	struct istream *input;
	struct stat st;
	struct acl_rights rights;
	const char *line, *error;
	unsigned int linenum;
	int fd, ret = 0;

	*is_dir_r = FALSE;

	fd = nfs_safe_open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT || errno == ENOTDIR) {
			if (aclobj->backend->debug)
				i_debug("acl vfile: file %s not found", path);
			validity->last_mtime = ACL_VFILE_VALIDITY_MTIME_NOTFOUND;
		} else if (errno == EACCES) {
			if (aclobj->backend->debug)
				i_debug("acl vfile: no access to file %s",
					path);

			acl_object_remove_all_access(aclobj);
			validity->last_mtime = ACL_VFILE_VALIDITY_MTIME_NOACCESS;
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
			i_close_fd(&fd);
			return 0;
		}

		i_error("fstat(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		/* we opened a directory. */
		*is_dir_r = TRUE;
		i_close_fd(&fd);
		return 0;
	}

	if (aclobj->backend->debug)
		i_debug("acl vfile: reading file %s", path);

	input = i_stream_create_fd(fd, (size_t)-1);
	i_stream_set_return_partial_line(input, TRUE);
	linenum = 0;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		linenum++;
		if (line[0] == '\0' || line[0] == '#')
			continue;
		T_BEGIN {
			ret = acl_rights_parse_line(line, aclobj->rights_pool,
						    &rights, &error);
			rights.global = global;
			if (ret < 0) {
				i_error("ACL file %s line %u: %s",
					path, linenum, error);
			} else {
				array_push_back(&aclobj->rights, &rights);
			}
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
			i_error("read(%s) failed: %s", path,
				i_stream_get_error(input));
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
acl_backend_vfile_read_with_retry(struct acl_object *aclobj,
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

static bool
acl_vfile_validity_has_changed(struct acl_backend_vfile *backend,
			       const struct acl_vfile_validity *validity,
			       const struct stat *st)
{
	if (st->st_mtime == validity->last_mtime &&
	    st->st_size == validity->last_size) {
		/* same timestamp, but if it was modified within the
		   same second we want to refresh it again later (but
		   do it only after a couple of seconds so we don't
		   keep re-reading it all the time within those
		   seconds) */
		time_t cache_secs = backend->cache_secs;

		if (validity->last_read_time != 0 &&
		    (st->st_mtime < validity->last_read_time - cache_secs ||
		     ioloop_time - validity->last_read_time <= cache_secs))
			return FALSE;
	}
	return TRUE;
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
			return validity->last_mtime != ACL_VFILE_VALIDITY_MTIME_NOTFOUND ? 1 : 0;
		} 
		if (errno == EACCES)
			return validity->last_mtime != ACL_VFILE_VALIDITY_MTIME_NOACCESS ? 1 : 0;
		i_error("stat(%s) failed: %m", path);
		return -1;
	}
	return acl_vfile_validity_has_changed(backend, validity, &st) ? 1 : 0;
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

static int
acl_backend_global_file_refresh(struct acl_object *_aclobj,
				struct acl_vfile_validity *validity)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_aclobj->backend;
	struct stat st;

	if (acl_global_file_refresh(_aclobj->backend->global_file) < 0)
		return -1;

	acl_global_file_last_stat(_aclobj->backend->global_file, &st);
	if (validity == NULL)
		return 1;
	return acl_vfile_validity_has_changed(backend, validity, &st) ? 1 : 0;
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
	ret = _aclobj->backend->global_file != NULL ?
		acl_backend_global_file_refresh(_aclobj, old_validity == NULL ? NULL :
						&old_validity->global_validity) :
		acl_backend_vfile_refresh(_aclobj, aclobj->global_path,
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
	if (!array_is_created(&_aclobj->rights)) {
		_aclobj->rights_pool =
			pool_alloconly_create("acl rights", 256);
		i_array_init(&_aclobj->rights, 16);
	} else {
		array_clear(&_aclobj->rights);
		p_clear(_aclobj->rights_pool);
	}

	i_zero(&validity);
	if (_aclobj->backend->global_file != NULL) {
		struct stat st;

		acl_object_add_global_acls(_aclobj);
		acl_global_file_last_stat(_aclobj->backend->global_file, &st);
		validity.global_validity.last_read_time = ioloop_time;
		validity.global_validity.last_mtime = st.st_mtime;
		validity.global_validity.last_size = st.st_size;
	} else {
		if (acl_backend_vfile_read_with_retry(_aclobj, TRUE, aclobj->global_path,
						      &validity.global_validity) < 0)
			return -1;
	}
	if (acl_backend_vfile_read_with_retry(_aclobj, FALSE, aclobj->local_path,
					      &validity.local_validity) < 0)
		return -1;

	acl_rights_sort(_aclobj);
	/* update cache only after we've successfully read everything */
	acl_object_rebuild_cache(_aclobj);
	acl_cache_set_validity(_aclobj->backend->cache,
			       _aclobj->name, &validity);

	if (acl_backend_vfile_object_get_mtime(_aclobj, &mtime) == 0)
		acl_backend_vfile_acllist_verify(backend, _aclobj->name, mtime);
	return 0;
}

static int acl_backend_vfile_object_last_changed(struct acl_object *_aclobj,
						 time_t *last_changed_r)
{
	struct acl_backend_vfile_validity *old_validity;

	*last_changed_r = 0;

	old_validity = acl_cache_get_validity(_aclobj->backend->cache,
					      _aclobj->name);
	if (old_validity == NULL) {
		if (acl_backend_vfile_object_refresh_cache(_aclobj) < 0)
			return -1;
		old_validity = acl_cache_get_validity(_aclobj->backend->cache,
						      _aclobj->name);
		if (old_validity == NULL)
			return 0;
	}
	*last_changed_r = old_validity->local_validity.last_mtime;
	return 0;
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
	acl_backend_vfile_object_last_changed,
	acl_default_object_list_init,
	acl_default_object_list_next,
	acl_default_object_list_deinit
};
