/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "istream.h"
#include "nfs-workarounds.h"
#include "mail-storage-private.h"
#include "acl-cache.h"
#include "acl-api-private.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ACL_FILENAME "dovecot-acl"

/* Minimum time between stat()ing the ACL file to see if its timestamp has
   changed. */
#define ACL_VALIDITY_SECS 1
/* Time difference to allow between this system's time and file server's time */
#define ACL_SYNC_SECS 1

#define ACL_ESTALE_RETRY_COUNT NFS_ESTALE_RETRY_COUNT

struct acl_vfile_validity {
	time_t last_check;

	time_t last_read_time;
	time_t last_mtime;
	off_t last_size;
};

struct acl_backend_vfile_validity {
	struct acl_vfile_validity global_validity, local_validity;
};

struct acl_backend_vfile {
	struct acl_backend backend;
	const char *global_dir;
};

struct acl_object_vfile {
	struct acl_object aclobj;

	char *global_path, *local_path;
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

	if (_backend->debug)
		i_info("acl vfile: Global ACL directory: %s", data);

	backend->global_dir = p_strdup(_backend->pool, data);
	_backend->cache =
		acl_cache_init(_backend,
			       sizeof(struct acl_backend_vfile_validity));
	return 0;
}

static void acl_backend_vfile_deinit(struct acl_backend *backend)
{
	pool_unref(backend->pool);
}

static struct acl_object *
acl_backend_vfile_object_init(struct acl_backend *_backend, const char *name)
{
	struct acl_backend_vfile *backend =
		(struct acl_backend_vfile *)_backend;
	struct acl_object_vfile *aclobj;
	const char *control_dir, *dir;
	bool is_file;

	aclobj = i_new(struct acl_object_vfile, 1);
	aclobj->aclobj.backend = _backend;
	aclobj->aclobj.name = i_strdup(name);
	aclobj->global_path = *backend->global_dir == '\0' ? NULL :
		i_strconcat(backend->global_dir, "/", name, NULL);

	control_dir =
		mail_storage_get_mailbox_control_dir(_backend->storage, name);
	dir = mail_storage_get_mailbox_path(_backend->storage, name, &is_file);
	if (is_file) {
		/* use control directory with mboxes */
		dir = control_dir;
	} else {
		/* FIXME: this is only for making sure people won't upgrade
		   improperly. remove this check some day. */
		const char *path;
		struct stat st;

		path = t_strconcat(control_dir, "/"ACL_FILENAME, NULL);
		if (stat(path, &st) == 0) {
			i_fatal("%s is no longer kept in control directory, "
				"move it to the actual maildir (%s)",
				path, dir);
		}
	}
	aclobj->local_path = i_strconcat(dir, "/"ACL_FILENAME, NULL);
	return &aclobj->aclobj;
}

static void acl_backend_vfile_object_deinit(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;

	i_free(aclobj->local_path);
	i_free(aclobj->global_path);
	i_free(aclobj->aclobj.name);
	i_free(aclobj);
}

static const char *const *
acl_parse_rights(const char *acl, const char **error_r)
{
	ARRAY_DEFINE(rights, const char *);
	const char *const *names;
	unsigned int i;

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

	if (*acl == '\0') {
		(void)array_append_space(&rights);
		return array_idx(&rights, 0);
	}

	/* parse our own extended ACLs */
	i_assert(*acl == ':');

	names = t_strsplit_spaces(acl, ", ");
	if (array_count(&rights) == 0)
		return names;
	
	for (; *names != NULL; names++)
		array_append(&rights, names, 1);
	(void)array_append_space(&rights);
	return array_idx(&rights, 0);
}

static int
acl_object_vfile_parse_line(struct acl_object *aclobj, const char *path,
			    const char *line, unsigned int linenum)
{
	struct acl_rights rights;
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

	right_names = acl_parse_rights(p, &error);
	if (*line != '-') {
		rights.modify_mode = ACL_MODIFY_MODE_REPLACE;
		rights.rights = right_names;
	} else {
		line++;
		rights.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;
		rights.neg_rights = right_names;
	}

	if (strncmp(line, "user=", 5) == 0) {
		rights.id_type = ACL_ID_USER;
		rights.identifier = line + 5;
	} else if (strncmp(line, "group=", 6) == 0) {
		rights.id_type = ACL_ID_GROUP;
		rights.identifier = line + 6;
	} else if (strncmp(line, "group-override=", 15) == 0) {
		rights.id_type = ACL_ID_GROUP_OVERRIDE;
		rights.identifier = line + 15;
	} else if (strcmp(line, "owner") == 0) {
		rights.id_type = ACL_ID_USER;
		rights.identifier = aclobj->backend->owner_username;
	} else if (strcmp(line, "authenticated") == 0) {
		rights.id_type = ACL_ID_AUTHENTICATED;
	} else if (strcmp(line, "anyone") == 0 ||
		   strcmp(line, "anonymous") == 0) {
		rights.id_type = ACL_ID_ANYONE;
	} else {
		error = t_strdup_printf("Unknown ID '%s'", line);
	}

	if (error != NULL) {
		mail_storage_set_critical(aclobj->backend->storage,
					  "ACL file %s line %u: %s",
					  path, linenum, error);
		t_pop();
		return -1;
	}

	acl_cache_update(aclobj->backend->cache, aclobj->name, &rights);

	t_pop();
	return 0;
}

static int
acl_backend_vfile_read(struct acl_object *aclobj, const char *path,
		       struct acl_vfile_validity *validity, bool try_retry,
		       bool *is_dir_r)
{
	struct mail_storage *storage = aclobj->backend->storage;
	struct istream *input;
	struct stat st;
	const char *line;
	unsigned int linenum;
	int fd, ret = 1;

	*is_dir_r = FALSE;

	fd = nfs_safe_open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT) {
			if (aclobj->backend->debug)
				i_info("acl vfile: file %s not found", path);

			validity->last_size = 0;
			validity->last_mtime = 0;
			validity->last_read_time = ioloop_time;
			return 1;
		}
		mail_storage_set_critical(storage, "open(%s) failed: %m", path);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		if (errno == ESTALE && try_retry) {
			(void)close(fd);
			return 0;
		}

		mail_storage_set_critical(storage,
					  "fstat(%s) failed: %m", path);
		(void)close(fd);
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		/* we opened a directory. */
		*is_dir_r = TRUE;
		(void)close(fd);
		return 0;
	}

	if (aclobj->backend->debug)
		i_info("acl vfile: reading file %s", path);

	input = i_stream_create_file(fd, default_pool, 4096, FALSE);

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
			mail_storage_set_critical(storage,
						  "read(%s) failed: %m", path);
		}
	}

	if (ret > 0) {
		if (fstat(fd, &st) < 0) {
			if (errno == ESTALE && try_retry)
				ret = 0;
			else {
				ret = -1;
				mail_storage_set_critical(storage,
					"read(%s) failed: %m", path);
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

		mail_storage_set_critical(storage, "close(%s) failed: %m",
					  path);
		return -1;
	}
	return ret;
}

static int
acl_backend_vfile_read_with_retry(struct acl_object *aclobj, const char *path,
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
	struct stat st;

	if (validity == NULL)
		return 1;
	if (path == NULL ||
	    validity->last_check + ACL_VALIDITY_SECS > ioloop_time)
		return 0;

	validity->last_check = ioloop_time;
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* if the file used to exist, we have to re-read it */
			return validity->last_mtime != 0;
		} 
		mail_storage_set_critical(aclobj->backend->storage,
					  "stat(%s) failed: %m", path);
		return -1;
	}

	if (st.st_mtime == validity->last_mtime &&
	    st.st_size == validity->last_size) {
		/* same timestamp, but if it was modified within the
		   same second we want to refresh it again later (but
		   do it only after a couple of seconds so we don't
		   keep re-reading it all the time within those
		   seconds) */
		if (st.st_mtime < validity->last_read_time - ACL_SYNC_SECS ||
		    ioloop_time - validity->last_read_time <= ACL_SYNC_SECS)
			return 0;
	}

	return 1;
}

static int acl_backend_vfile_object_refresh_cache(struct acl_object *_aclobj)
{
	struct acl_object_vfile *aclobj = (struct acl_object_vfile *)_aclobj;
	struct acl_backend_vfile_validity *old_validity;
	struct acl_backend_vfile_validity validity;
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
	if (acl_backend_vfile_read_with_retry(_aclobj, aclobj->global_path,
					      &validity.global_validity) < 0)
		return -1;
	if (acl_backend_vfile_read_with_retry(_aclobj, aclobj->local_path,
					      &validity.local_validity) < 0)
		return -1;

	acl_cache_set_validity(_aclobj->backend->cache,
			       _aclobj->name, &validity);
	return 0;
}

static int
acl_backend_vfile_object_update(struct acl_object *aclobj __attr_unused__,
				const struct acl_rights *rights __attr_unused__)
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
	return iter;
}

static int
acl_backend_vfile_object_list_next(struct acl_object_list_iter *iter
				   	__attr_unused__,
				   struct acl_rights *rights_r __attr_unused__)
{
	return -1;
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
	acl_backend_vfile_object_init,
	acl_backend_vfile_object_deinit,
	acl_backend_vfile_object_refresh_cache,
	acl_backend_vfile_object_update,
	acl_backend_vfile_object_list_init,
	acl_backend_vfile_object_list_next,
	acl_backend_vfile_object_list_deinit
};
