/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

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

	t_push();
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
			t_pop();
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
	t_pop();
	return 0;
}

static void acl_backend_vfile_deinit(struct acl_backend *backend)
{
	pool_unref(&backend->pool);
}

static struct acl_object *
acl_backend_vfile_object_init(struct acl_backend *_backend,
			      struct mail_storage *storage, const char *name)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	struct acl_object_vfile *aclobj;
	const char *dir;
	bool is_file;

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
		dir = mail_storage_get_mailbox_path(storage, name, &is_file);
		if (is_file) {
			dir = mailbox_list_get_path(_backend->list, name,
					MAILBOX_LIST_PATH_TYPE_CONTROL);
		}
	}
	aclobj->local_path = i_strconcat(dir, "/"ACL_FILENAME, NULL);
	return &aclobj->aclobj;
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
acl_parse_rights(pool_t pool, const char *acl, const char **error_r)
{
	ARRAY_DEFINE(rights, const char *);
	const char *const *names, **ret_rights;
	unsigned int i, count;

	/* parse IMAP ACL list */
	while (*acl == ' ' || *acl == '\t')
		acl++;

	t_array_init(&rights, 64);
	for (; *acl != '\0' && *acl != ':'; acl++) {
		for (i = 0; acl_letter_map[i].letter != '\0'; i++) {
			if (acl_letter_map[i].letter == *acl)
				break;
		}

		if (acl_letter_map[i].letter == '\0') {
			*error_r = t_strdup_printf("Unknown ACL '%c'", *acl);
			return NULL;
		}

		array_append(&rights, &acl_letter_map[i].name, 1);
	}

	if (*acl != '\0') {
		/* parse our own extended ACLs */
		i_assert(*acl == ':');

		names = t_strsplit_spaces(acl, ", ");
		for (; *names != NULL; names++) {
			const char *name = p_strdup(pool, *names);
			array_append(&rights, &name, 1);
		}
	}

	/* @UNSAFE */
	count = array_count(&rights);
	ret_rights = p_new(pool, const char *, count + 1);
	if (count > 0) {
		memcpy(ret_rights, array_idx(&rights, 0),
		       sizeof(const char *) * count);
	}
	return ret_rights;
}

static int
acl_object_vfile_parse_line(struct acl_object_vfile *aclobj, const char *path,
			    const char *line, unsigned int linenum)
{
	struct acl_rights_update rights;
	const char *p, *const *right_names, *error = NULL;

	if (*line == '\0' || *line == '#')
		return 0;

	/* <id> [<imap acls>] [:<named acls>] */
	t_push();
	p = strchr(line, ' ');
	if (p == NULL)
		p = "";
	else {
		line = t_strdup_until(line, p);
		p++;
	}

	memset(&rights, 0, sizeof(rights));

	right_names = acl_parse_rights(aclobj->rights_pool, p, &error);
	if (*line != '-') {
		rights.modify_mode = ACL_MODIFY_MODE_REPLACE;
		rights.rights.rights = right_names;
	} else {
		line++;
		rights.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
		rights.rights.neg_rights = right_names;
	}

	switch (*line) {
	case 'u':
		if (strncmp(line, "user=", 5) == 0) {
			rights.rights.id_type = ACL_ID_USER;
			rights.rights.identifier = line + 5;
			break;
		}
	case 'o':
		if (strcmp(line, "owner") == 0) {
			rights.rights.id_type = ACL_ID_OWNER;
			break;
		}
	case 'g':
		if (strncmp(line, "group=", 6) == 0) {
			rights.rights.id_type = ACL_ID_GROUP;
			rights.rights.identifier = line + 6;
			break;
		} else if (strncmp(line, "group-override=", 15) == 0) {
			rights.rights.id_type = ACL_ID_GROUP_OVERRIDE;
			rights.rights.identifier = line + 15;
			break;
		}
	case 'a':
		if (strcmp(line, "authenticated") == 0) {
			rights.rights.id_type = ACL_ID_AUTHENTICATED;
			break;
		} else if (strcmp(line, "anyone") == 0 ||
			   strcmp(line, "anonymous") == 0) {
			rights.rights.id_type = ACL_ID_ANYONE;
			break;
		}
	default:
		error = t_strdup_printf("Unknown ID '%s'", line);
		break;
	}

	if (error != NULL) {
		i_error("ACL file %s line %u: %s", path, linenum, error);
		t_pop();
		return -1;
	}

	rights.rights.identifier =
		p_strdup(aclobj->rights_pool, rights.rights.identifier);
	array_append(&aclobj->rights, &rights.rights, 1);

	acl_cache_update(aclobj->aclobj.backend->cache,
			 aclobj->aclobj.name, &rights);

	t_pop();
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
acl_backend_vfile_read(struct acl_object_vfile *aclobj, const char *path,
		       struct acl_vfile_validity *validity, bool try_retry,
		       bool *is_dir_r)
{
	struct istream *input;
	struct stat st;
	const char *line;
	unsigned int linenum;
	int fd, ret = 1;

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

	if (!array_is_created(&aclobj->rights)) {
		aclobj->rights_pool =
			pool_alloconly_create("acl rights",
					      I_MAX(256, st.st_size / 2));
		i_array_init(&aclobj->rights, I_MAX(16, st.st_size / 40));
	} else {
		array_clear(&aclobj->rights);
		p_clear(aclobj->rights_pool);
	}

	linenum = 1;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (acl_object_vfile_parse_line(aclobj, path, line,
						linenum++) < 0) {
			ret = -1;
			break;
		}
	}

	if (input->stream_errno != 0) {
		if (input->stream_errno == ESTALE && try_retry)
			ret = 0;
		else {
			ret = -1;
			i_error("read(%s) failed: %m", path);
		}
	}

	if (ret > 0) {
		if (fstat(fd, &st) < 0) {
			if (errno == ESTALE && try_retry)
				ret = 0;
			else {
				ret = -1;
				i_error("read(%s) failed: %m", path);
			}
		} else {
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
				  const char *path,
				  struct acl_vfile_validity *validity)
{
	unsigned int i;
	int ret;
	bool is_dir;

	if (path == NULL)
		return 0;

	for (i = 0;; i++) {
		ret = acl_backend_vfile_read(aclobj, path, validity,
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

		if (st.st_mtime < validity->last_read_time - cache_secs ||
		    ioloop_time - validity->last_read_time <= cache_secs)
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
	acl_cache_flush(_aclobj->backend->cache, _aclobj->name);

	memset(&validity, 0, sizeof(validity));
	if (acl_backend_vfile_read_with_retry(aclobj, aclobj->global_path,
					      &validity.global_validity) < 0)
		return -1;
	if (acl_backend_vfile_read_with_retry(aclobj, aclobj->local_path,
					      &validity.local_validity) < 0)
		return -1;

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
	acl_backend_vfile_object_deinit,
	acl_backend_vfile_object_refresh_cache,
	acl_backend_vfile_object_update,
	acl_backend_vfile_object_list_init,
	acl_backend_vfile_object_list_next,
	acl_backend_vfile_object_list_deinit
};
