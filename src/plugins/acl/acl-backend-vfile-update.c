/* Copyright (c) 2006-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "file-dotlock.h"
#include "ostream.h"
#include "mail-storage.h"
#include "acl-cache.h"
#include "acl-backend-vfile.h"

#include <utime.h>
#include <sys/stat.h>

static struct dotlock_settings dotlock_set = {
	.timeout = 30,
	.stale_timeout = 120
};

static int acl_backend_vfile_update_begin(struct acl_object_vfile *aclobj,
					  struct dotlock **dotlock_r)
{
	struct acl_object *_aclobj = &aclobj->aclobj;
	struct mailbox_permissions perm;
	int fd;

	if (aclobj->local_path == NULL) {
		i_error("Can't update acl object '%s': No local acl file path",
			aclobj->aclobj.name);
		return -1;
	}

	/* first lock the ACL file */
	mailbox_list_get_permissions(_aclobj->backend->list,
				     _aclobj->name, &perm);
	fd = file_dotlock_open_group(&dotlock_set, aclobj->local_path, 0,
				     perm.file_create_mode,
				     perm.file_create_gid,
				     perm.file_create_gid_origin, dotlock_r);
	if (fd == -1) {
		i_error("file_dotlock_open(%s) failed: %m", aclobj->local_path);
		return -1;
	}

	/* locked successfully, re-read the existing file to make sure we
	   don't lose any changes. */
	acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
	if (_aclobj->backend->v.object_refresh_cache(_aclobj) < 0) {
		file_dotlock_delete(dotlock_r);
		return -1;
	}
	return fd;
}

static bool
vfile_object_modify_right(struct acl_object *aclobj, unsigned int idx,
			  const struct acl_rights_update *update)
{
	struct acl_rights *right;
	bool c1, c2;

	right = array_idx_modifiable(&aclobj->rights, idx);
	c1 = acl_right_names_modify(aclobj->rights_pool, &right->rights,
				    update->rights.rights, update->modify_mode);
	c2 = acl_right_names_modify(aclobj->rights_pool, &right->neg_rights,
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
vfile_object_add_right(struct acl_object *aclobj, unsigned int idx,
		       const struct acl_rights_update *update)
{
	struct acl_rights right;
	bool c1, c2;

	if (update->modify_mode == ACL_MODIFY_MODE_REMOVE &&
	    update->neg_modify_mode == ACL_MODIFY_MODE_REMOVE) {
		/* nothing to do */
		return FALSE;
	}

	i_zero(&right);
	right.id_type = update->rights.id_type;
	right.identifier = p_strdup(aclobj->rights_pool,
				    update->rights.identifier);

	c1 = acl_right_names_modify(aclobj->rights_pool, &right.rights,
				    update->rights.rights, update->modify_mode);
	c2 = acl_right_names_modify(aclobj->rights_pool, &right.neg_rights,
				    update->rights.neg_rights,
				    update->neg_modify_mode);
	if (c1 || c2) {
		array_insert(&aclobj->rights, idx, &right, 1);
		return TRUE;
	}
	return FALSE;
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
	acl_right_names_write(dest, rights);
	str_append_c(dest, '\n');
}

static int
acl_backend_vfile_update_write(struct acl_object *aclobj,
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
			o_stream_nsend(output, str_data(str), str_len(str));
			str_truncate(str, 0);
		}
		if (rights[i].neg_rights != NULL) {
			vfile_write_right(str, &rights[i], TRUE);
			o_stream_nsend(output, str_data(str), str_len(str));
			str_truncate(str, 0);
		}
	}
	str_free(&str);
	if (o_stream_nfinish(output) < 0) {
		i_error("write(%s) failed: %s", path,
			o_stream_get_error(output));
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

int acl_backend_vfile_object_update(struct acl_object *_aclobj,
				    const struct acl_rights_update *update)
{
	struct acl_object_vfile *aclobj =
		(struct acl_object_vfile *)_aclobj;
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_aclobj->backend;
	struct acl_backend_vfile_validity *validity;
	struct dotlock *dotlock;
	struct utimbuf ut;
	time_t orig_mtime;
	const char *path;
	unsigned int i;
	int fd;
	bool changed;

	/* global ACLs can't be updated here */
	i_assert(!update->rights.global);

	fd = acl_backend_vfile_update_begin(aclobj, &dotlock);
	if (fd == -1)
		return -1;

	if (!array_bsearch_insert_pos(&_aclobj->rights, &update->rights,
				      acl_rights_cmp, &i))
		changed = vfile_object_add_right(_aclobj, i, update);
	else
		changed = vfile_object_modify_right(_aclobj, i, update);
	if (!changed) {
		file_dotlock_delete(&dotlock);
		return 0;
	}

	validity = acl_cache_get_validity(_aclobj->backend->cache,
					  _aclobj->name);
	orig_mtime = validity->local_validity.last_mtime;

	/* ACLs were really changed, write the new ones */
	path = file_dotlock_get_lock_path(dotlock);
	if (acl_backend_vfile_update_write(_aclobj, fd, path) < 0) {
		file_dotlock_delete(&dotlock);
		acl_cache_flush(_aclobj->backend->cache, _aclobj->name);
		return -1;
	}
	if (orig_mtime < update->last_change && update->last_change != 0) {
		/* set mtime to last_change, if it's higher than the file's
		   original mtime. if original mtime is higher, then we're
		   merging some changes and it's better for the mtime to get
		   updated. */
		ut.actime = ioloop_time;
		ut.modtime = update->last_change;
		if (utime(path, &ut) < 0)
			i_error("utime(%s) failed: %m", path);
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
