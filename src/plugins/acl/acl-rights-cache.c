/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "sort.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "time-util.h"
#include "ostream.h"
#include "eacces-error.h"
#include "file-create-locked.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "acl-plugin.h"
#include "acl-lookup-dict.h"
#include "acl-backend-vfile.h"
#include "acl-api-private.h"
#include "acl-rights-cache.h"
#include "acl-storage.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct acl_rights_cache_entry {
	const char *name;
	/* mtime of the mailbox's ACL file when the entry was written */
	struct timeval mtime;
	/* The configured ACLs give the mailbox nonowner lookup rights. It
	   is stored as a flag of the mailbox's line. */
	bool marker;
	/* flags this version doesn't know, written back unchanged */
	const char *unknown_flags;
	/* the ACL file's rights */
	ARRAY_TYPE(acl_rights) rights;
};
ARRAY_DEFINE_TYPE(acl_rights_cache_entry, struct acl_rights_cache_entry);

/* The file starts with a version line. Each mailbox has one line:

   <mtime> TAB <flags> TAB <storage name> [TAB [-]<id> TAB <rights>]...

   <mtime> is <secs>.<usecs>, the usecs with 6 digits. Not nanoseconds:
   obox restores the mtime of the files it unpacks with utimes().
   All fields are tab-escaped. */
#define ACL_RIGHTS_CACHE_VERSION_LINE "V1"
#define ACL_RIGHTS_CACHE_FLAG_NONE '-'
#define ACL_RIGHTS_CACHE_FLAG_MARKER 'm'

struct acl_rights_cache_file {
	struct acl_backend *backend;
	struct event *event;
	char *path;
	/* stat() of the cache file when it was last loaded */
	struct stat prev_st;
	time_t last_refresh_time;
	time_t last_check;

	/* sorted by name, one entry per mailbox */
	ARRAY_TYPE(acl_rights_cache_entry) entries;

	struct file_lock *lock;
	int tmp_fd;

	pool_t rights_pool;

	bool has_path:1;
	/* the .tmp file was rename()d over the cache file */
	bool tmp_renamed:1;
	/* reading an existing cache file failed (e.g. corrupt content) -
	   the in-memory copy is empty, but must not be treated as an
	   authoritative empty result */
	bool read_failed:1;
	/* when a rebuild last failed to leave a usable cache behind */
	time_t last_failed_rebuild;
};

#define ACL_LEGACY_LIST_FILENAME "dovecot-acl-list"

struct acl_rights_cache_list_context_vfile {
	struct acl_mailbox_list_context ctx;

	unsigned int idx;
};

static bool
acl_rights_cache_legacy_list_exists(struct acl_rights_cache_file *file);

static bool acl_rights_cache_get_path(struct acl_backend *backend,
				      const char **path_r)
{
	enum mailbox_list_path_type type;
	const char *root_dir;

	if (!acl_backend_get_root_dir(backend, &root_dir, &type))
		return FALSE;
	*path_r = t_strconcat(root_dir, "/", ACL_RIGHTS_CACHE, NULL);
	return TRUE;
}

static bool acl_rights_cache_resolve_path(struct acl_rights_cache_file *file)
{
	const char *full_path;

	if (file->has_path)
		return TRUE;
	/* The path can't be resolved at backend init time: the backend is
	   initialized from the mailbox_list_created hook, before the
	   namespace's storage exists. Resolve it lazily on first use and
	   keep retrying until the storage is there. For backends without a
	   root dir (e.g. acl_globals_only) this keeps failing and the cache
	   stays unused. */
	T_BEGIN {
		if (acl_rights_cache_get_path(file->backend, &full_path)) {
			i_free(file->path);
			file->path = i_strdup(full_path);
			file->has_path = TRUE;
		}
	} T_END;
	return file->has_path;
}

struct acl_rights_cache_file *
acl_rights_cache_file_init(struct acl_backend *backend)
{
	struct acl_rights_cache_file *file;

	file = i_new(struct acl_rights_cache_file, 1);
	file->backend = backend;
	file->tmp_fd = -1;
	file->event = event_create(mailbox_list_get_user(backend->list)->event);
	file->path = i_strdup(ACL_RIGHTS_CACHE);
	i_array_init(&file->entries, 32);
	file->rights_pool = pool_alloconly_create("acl rights cache", 1024);

	return file;
}

void acl_rights_cache_file_deinit(struct acl_rights_cache_file **_file)
{
	struct acl_rights_cache_file *file = *_file;

	if (file == NULL)
		return;
	*_file = NULL;

	array_free(&file->entries);
	pool_unref(&file->rights_pool);
	event_unref(&file->event);
	i_free(file->path);
	i_free(file);
}

int acl_rights_cache_file_exists(struct acl_rights_cache_file *file)
{
	struct stat st;

	if (!acl_rights_cache_resolve_path(file))
		return 0;
	if (stat(file->path, &st) < 0) {
		if (ENOTFOUND(errno))
			return 0;
		e_error(file->event, "stat(%s) failed: %m",
			file->path);
		return -1;
	}
	return 1;
}

/* The files in the ACL root are never supposed to be symlinks. */
static struct istream *acl_rights_cache_open_stream(const char *path)
{
	struct istream *input;
	int fd;

	fd = open(path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		int open_errno = errno;

		return i_stream_create_error_str(open_errno,
						 "open(%s) failed: %s", path,
						 strerror(open_errno));
	}
	input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	i_stream_set_name(input, path);
	return input;
}

static int
acl_rights_cache_entry_cmp(const struct acl_rights_cache_entry *e1,
			   const struct acl_rights_cache_entry *e2)
{
	return strcmp(e1->name, e2->name);
}

static int
acl_rights_cache_parse_line(struct acl_rights_cache_file *file,
			    const char *line, const char **error_r)
{
	struct acl_rights_cache_entry *entry;
	struct acl_rights *right;
	const char *const *fields, *p;
	string_t *unknown_flags;
	struct timeval mtime;
	unsigned int i, field_count;

	fields = t_strsplit_tabescaped(line);
	field_count = str_array_length(fields);
	if (field_count < 3 || field_count % 2 == 0) {
		*error_r = "Invalid number of fields";
		return -1;
	}
	if (str_to_timeval(fields[0], &mtime) < 0) {
		*error_r = "Invalid mtime";
		return -1;
	}
	if (fields[1][0] == '\0') {
		*error_r = "Empty flags";
		return -1;
	}
	if (fields[2][0] == '\0') {
		*error_r = "Empty mailbox name";
		return -1;
	}

	entry = array_append_space(&file->entries);
	entry->name = p_strdup(file->rights_pool, fields[2]);
	entry->mtime = mtime;
	p_array_init(&entry->rights, file->rights_pool, 4);

	unknown_flags = t_str_new(8);
	for (p = fields[1]; *p != '\0'; p++) {
		if (*p == ACL_RIGHTS_CACHE_FLAG_MARKER)
			entry->marker = TRUE;
		else if (*p != ACL_RIGHTS_CACHE_FLAG_NONE)
			str_append_c(unknown_flags, *p);
	}
	if (str_len(unknown_flags) > 0) {
		entry->unknown_flags =
			p_strdup(file->rights_pool, str_c(unknown_flags));
	}

	for (i = 3; i < field_count; i += 2) {
		right = array_append_space(&entry->rights);
		if (acl_rights_parse_fields(fields[i], fields[i + 1],
					    file->rights_pool, right,
					    error_r) < 0)
			return -1;
	}
	return 0;
}

static int acl_rights_cache_file_parse(struct acl_rights_cache_file *file)
{
	const struct acl_rights_cache_entry *entry, *prev_entry = NULL;
	struct istream *input;
	const char *line, *error;
	unsigned int linenum = 0;
	int ret = 0;

	array_clear(&file->entries);
	p_clear(file->rights_pool);

	input = acl_rights_cache_open_stream(file->path);
	i_stream_set_return_partial_line(input, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		linenum++;
		if (linenum == 1) {
			if (strcmp(line, ACL_RIGHTS_CACHE_VERSION_LINE) == 0)
				continue;
			e_error(file->event, "ACL rights cache %s: Unsupported version line", file->path);
			ret = -1;
			break;
		}
		if (line[0] == '\0')
			continue;
		T_BEGIN {
			ret = acl_rights_cache_parse_line(file, line, &error);
			if (ret < 0) {
				e_error(file->event,
					"ACL rights cache %s line %u: %s",
					file->path, linenum, error);
			}
		} T_END;
		if (ret < 0)
			break;
	}
	if (ret == 0 && input->stream_errno != 0) {
		e_error(file->event, "Couldn't read ACL rights cache %s: %s",
			file->path, i_stream_get_error(input));
		ret = -1;
	}
	if (ret == 0 && linenum == 0) {
		e_error(file->event, "ACL rights cache %s: Missing version line", file->path);
		ret = -1;
	}
	if (ret == 0) {
		const struct stat *st;

		if (i_stream_stat(input, TRUE, &st) < 0) {
			e_error(file->event,
				"Couldn't stat ACL rights cache %s: %s",
				file->path, i_stream_get_error(input));
			ret = -1;
		} else {
			file->prev_st = *st;
		}
	}
	i_stream_destroy(&input);

	if (ret == 0) {
		/* The lookups need the entries sorted by name. A mailbox
		   has a single line. */
		array_sort(&file->entries, acl_rights_cache_entry_cmp);
		array_foreach(&file->entries, entry) {
			if (prev_entry != NULL &&
			    strcmp(prev_entry->name, entry->name) == 0) {
				e_error(file->event, "ACL rights cache %s: Duplicate mailbox %s",
					file->path,
					str_sanitize(entry->name, 128));
				ret = -1;
				break;
			}
			prev_entry = entry;
		}
	}

	if (ret < 0) {
		/* Don't install a partially parsed file, and forget the last
		   good one: the next file written may have its inode, size
		   and mtime, and must not be taken as unchanged. */
		array_clear(&file->entries);
		i_zero(&file->prev_st);
		file->last_refresh_time = 0;
	}
	return ret;
}

/* Load the cache file into memory, unless the already loaded copy is still
   the same file. */
static int acl_rights_cache_file_load(struct acl_rights_cache_file *file)
{
	struct stat st;

	if (file->last_refresh_time != 0) {
		if (stat(file->path, &st) < 0) {
			e_error(file->event, "stat(%s) failed: %m", file->path);
			return -1;
		}
		if (st.st_ino == file->prev_st.st_ino &&
		    st.st_size == file->prev_st.st_size &&
		    CMP_ST_MTIME(&st, &file->prev_st)) {
			/* no change to the file */
			file->last_refresh_time = ioloop_time;
			return 0;
		}
	}
	if (acl_rights_cache_file_parse(file) < 0)
		return -1;
	file->last_refresh_time = ioloop_time;
	return 0;
}

static int acl_rights_cache_file_read(struct acl_rights_cache_file *file)
{
	if (acl_rights_cache_file_load(file) < 0) {
		file->read_failed = TRUE;
		return -1;
	}
	file->read_failed = FALSE;
	return 0;
}

int acl_rights_cache_file_refresh(struct acl_rights_cache_file *file)
{
	int ret;

	if ((ret = acl_rights_cache_file_exists(file)) < 0)
		return -1;
	if (ret == 0) {
		/* The cache file was deleted. Don't keep serving the entries
		   loaded earlier: a session that doesn't rebuild the cache
		   (e.g. a shared namespace's) would use them until the file
		   is recreated. */
		array_clear(&file->entries);
		i_zero(&file->prev_st);
		file->last_refresh_time = 0;
		return 0;
	}
	if (acl_rights_cache_file_read(file) < 0)
		return -1;
	return 1;
}

/* Rebuild a missing or unreadable cache. A rebuild lists every mailbox, so
   when it doesn't leave a usable cache behind (it failed, or the ACL root
   can't be written) it isn't tried again by every ACL read, only once per
   acl_cache_ttl. */
static void acl_rights_cache_try_rebuild(struct acl_backend_vfile *backend)
{
	struct acl_rights_cache_file *file = backend->backend.rights_cache_file;

	(void)acl_rights_cache_rebuild(backend);
	if (acl_rights_cache_file_exists(file) > 0 && !file->read_failed)
		file->last_failed_rebuild = 0;
	else
		file->last_failed_rebuild = ioloop_time;
}

void acl_rights_cache_refresh(struct acl_backend_vfile *backend,
			      bool rebuild_if_missing)
{
	struct acl_rights_cache_file *file = backend->backend.rights_cache_file;

	if (backend->rebuilding_aclcache || backend->iterating_aclcache)
		return;
	if (!acl_rights_cache_resolve_path(file))
		return;
	if (file->last_failed_rebuild != 0 &&
	    file->last_failed_rebuild + (time_t)backend->cache_secs >
	    ioloop_time) {
		/* there is no usable cache, and a rebuild was just tried */
		return;
	}
	if (rebuild_if_missing &&
	    acl_rights_cache_file_exists(file) == 0) {
		/* Only a full rebuild creates the cache file. The check
		   isn't throttled by last_check - the missing state
		   persists until a rebuild succeeds. */
		acl_rights_cache_try_rebuild(backend);
		return;
	}
	if (file->last_check + (time_t)backend->cache_secs > ioloop_time)
		return;
	if (acl_rights_cache_file_refresh(file) > 0) {
		file->last_check = ioloop_time;
		if (rebuild_if_missing &&
		    acl_rights_cache_legacy_list_exists(file)) {
			/* A rebuild removes dovecot-acl-list, so a version
			   without the rights cache has been used since, and
			   it may have changed ACLs without updating the
			   cache. Rebuild the cache and remove the list
			   again. A failed rebuild leaves both in place and
			   is tried again after acl_cache_ttl. */
			e_debug(file->event, "%s found next to %s",
				ACL_LEGACY_LIST_FILENAME, file->path);
			(void)acl_rights_cache_rebuild(backend);
		}
	} else if (file->read_failed && rebuild_if_missing) {
		/* the cache file exists but can't be read (e.g. corrupt
		   content) - recover by rebuilding it */
		acl_rights_cache_try_rebuild(backend);
	}
}

static int
acl_rights_cache_entry_name_cmp(const char *name,
				const struct acl_rights_cache_entry *entry)
{
	return strcmp(name, entry->name);
}

static const struct acl_rights_cache_entry *
acl_rights_cache_find(struct acl_rights_cache_file *file, const char *name)
{
	return array_bsearch(&file->entries, name,
			     acl_rights_cache_entry_name_cmp);
}

void acl_rights_cache_file_get(struct acl_rights_cache_file *file,
			       const char *name, pool_t pool,
			       ARRAY_TYPE(acl_rights) *rights_r)
{
	const struct acl_rights_cache_entry *entry;
	const struct acl_rights *right;
	struct acl_rights *new_right;

	/* Cache entries are literal mailbox names - match exactly. */
	entry = acl_rights_cache_find(file, name);
	if (entry == NULL)
		return;
	array_foreach(&entry->rights, right) {
		new_right = array_append_space(rights_r);
		acl_rights_dup(right, pool, new_right);
		new_right->global = FALSE;
	}
}

bool acl_rights_cache_file_have_any(struct acl_rights_cache_file *file,
				    const char *name, const char *identifier)
{
	const struct acl_rights_cache_entry *entry;
	const struct acl_rights *right;

	if (file->last_refresh_time == 0) {
		/* cache was never loaded */
		return FALSE;
	}
	if (*name == '\0') {
		/* the namespace root is never cached */
		return FALSE;
	}

	entry = acl_rights_cache_find(file, name);
	if (entry == NULL || array_count(&entry->rights) == 0) {
		/* no entry, or an entry that has only flags - there are
		   no cached rights that could be served */
		return FALSE;
	}
	if (identifier == NULL)
		return TRUE;
	array_foreach(&entry->rights, right) {
		if (acl_backend_rights_match_me(file->backend, right))
			return TRUE;
		if (null_strcmp(right->identifier, identifier) == 0)
			return TRUE;
	}
	return FALSE;
}

bool acl_rights_cache_file_get_mtime(struct acl_rights_cache_file *file,
				     const char *name, struct timeval *mtime_r)
{
	const struct acl_rights_cache_entry *entry;

	if (file->last_refresh_time == 0) {
		/* cache was never loaded */
		return FALSE;
	}
	entry = acl_rights_cache_find(file, name);
	if (entry == NULL)
		return FALSE;
	*mtime_r = entry->mtime;
	return TRUE;
}

static bool
acl_rights_cache_modify_right(struct acl_rights *old_rights,
			      pool_t pool,
			      const struct acl_rights_update *update)
{
	bool c1, c2;

	c1 = acl_right_names_modify(pool, &old_rights->rights,
				    update->rights.rights, update->modify_mode);
	c2 = acl_right_names_modify(pool, &old_rights->neg_rights,
				    update->rights.neg_rights,
				    update->neg_modify_mode);

	return c1 || c2;
}

static bool
acl_rights_cache_add_right(ARRAY_TYPE(acl_rights) *rights, pool_t pool,
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
	right.identifier = p_strdup(pool, update->rights.identifier);

	c1 = acl_right_names_modify(pool, &right.rights,
				    update->rights.rights, update->modify_mode);
	c2 = acl_right_names_modify(pool, &right.neg_rights,
				    update->rights.neg_rights,
				    update->neg_modify_mode);
	if (c1 || c2) {
		array_push_back(rights, &right);
		return TRUE;
	}
	return FALSE;
}

static void acl_rights_cache_write_header(struct ostream *output)
{
	o_stream_nsend_str(output, ACL_RIGHTS_CACHE_VERSION_LINE"\n");
}

static void
acl_rights_cache_append_right(string_t *dest, const struct acl_rights *right,
			      bool neg)
{
	string_t *field = t_str_new(64);

	if (neg)
		str_append_c(field, '-');
	acl_rights_write_id(field, right);
	str_append_c(dest, '\t');
	str_append_tabescaped(dest, str_c(field));

	str_truncate(field, 0);
	acl_right_names_write(field, neg ? right->neg_rights : right->rights);
	str_append_c(dest, '\t');
	str_append_tabescaped(dest, str_c(field));
}

/* Write the mailbox's line. Nothing is written for a mailbox that has
   neither rights nor flags - unless the storage has the mailboxes' files
   only in a local cache: there the line of a mailbox whose rights were all
   removed stays, because its mtime tells that an older local copy of the
   ACL file is out of date. Such a line with mtime 0 tells nothing and isn't
   kept. */
static void
acl_rights_cache_write_line(struct acl_rights_cache_file *file,
			    struct ostream *output, string_t *str,
			    const char *name, const struct timeval *mtime,
			    bool marker, const char *unknown_flags,
			    const ARRAY_TYPE(acl_rights) *rights)
{
	const struct acl_rights *right;
	size_t rights_pos;
	bool keep_empty = rights != NULL && mtime->tv_sec != 0 &&
		acl_backend_storage_has_cached_files(file->backend);

	str_truncate(str, 0);
	str_printfa(str, "%"PRIdTIME_T".%06u\t", mtime->tv_sec,
		    (unsigned int)mtime->tv_usec);
	if (marker)
		str_append_c(str, ACL_RIGHTS_CACHE_FLAG_MARKER);
	if (unknown_flags != NULL)
		str_append_tabescaped(str, unknown_flags);
	else if (!marker)
		str_append_c(str, ACL_RIGHTS_CACHE_FLAG_NONE);
	str_append_c(str, '\t');
	str_append_tabescaped(str, name);
	rights_pos = str_len(str);
	if (rights != NULL) {
		array_foreach(rights, right) T_BEGIN {
			if (right->rights != NULL)
				acl_rights_cache_append_right(str, right, FALSE);
			if (right->neg_rights != NULL)
				acl_rights_cache_append_right(str, right, TRUE);
		} T_END;
	}
	if (str_len(str) == rights_pos && !marker && unknown_flags == NULL &&
	    !keep_empty)
		return;
	str_append_c(str, '\n');
	o_stream_nsend(output, str_data(str), str_len(str));
}

static int acl_rights_cache_file_flush(struct acl_rights_cache_file *file,
				       ARRAY_TYPE(acl_rights) *add_rights,
				       bool add_marker,
				       const char *storage_name,
				       const struct timeval *add_rights_mtime)
{
	const struct acl_rights_cache_entry *entry;
	const char *unknown_flags = NULL;
	struct ostream *output;
	string_t *str;
	int ret = 0;

	const char *tmp_path = t_strdup_printf("%s.tmp", file->path);

	output = o_stream_create_fd_file(file->tmp_fd, 0, FALSE);
	o_stream_cork(output);
	acl_rights_cache_write_header(output);

	str = str_new(default_pool, 256);
	array_foreach(&file->entries, entry) {
		if (null_strcmp(entry->name, storage_name) == 0) {
			/* replaced below, only its unknown flags are kept */
			unknown_flags = entry->unknown_flags;
			continue;
		}
		/* Rewrite the other mailboxes' entries unmodified */
		acl_rights_cache_write_line(file, output, str, entry->name,
					    &entry->mtime, entry->marker,
					    entry->unknown_flags,
					    &entry->rights);
	}
	if (add_rights != NULL) {
		i_assert(storage_name != NULL);
		/* New rights for storage_name */
		acl_rights_cache_write_line(file, output, str, storage_name,
					    add_rights_mtime, add_marker,
					    unknown_flags, add_rights);
	}
	str_free(&str);

	if (o_stream_finish(output) < 0) {
		e_error(file->event, "write(%s) failed: %s", tmp_path,
			o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);

	if (ret == 0) {
		if (rename(tmp_path, file->path) < 0) {
			e_error(file->event, "rename(%s, %s) failed: %m",
				tmp_path, file->path);
			ret = -1;
		} else {
			file->tmp_renamed = TRUE;
		}
	}
	return ret;
}

static void acl_rights_cache_file_update_end(struct acl_rights_cache_file *file)
{
	if (!file->tmp_renamed) {
		/* Nothing was written - remove the .tmp file while the lock
		   is still held. */
		const char *tmp_path =
			t_strdup_printf("%s.tmp", file->path);
		i_unlink_if_exists(tmp_path);
	}
	i_close_fd(&file->tmp_fd);
	file_lock_free(&file->lock);
}

static bool acl_rights_cache_ns_is_shared(struct acl_rights_cache_file *file)
{
	return mailbox_list_get_namespace(file->backend->list)->type ==
		MAIL_NAMESPACE_TYPE_SHARED;
}

static bool acl_rights_cache_ns_is_private(struct acl_rights_cache_file *file)
{
	return mailbox_list_get_namespace(file->backend->list)->type ==
		MAIL_NAMESPACE_TYPE_PRIVATE;
}

/* The empty name is the namespace root, also when the prefix itself is
   accessed as a mailbox ("Public" for "Public/", or "shared/$user" with
   mail_shared_explicit_inbox=yes). Its ACL file is the one in the ACL root,
   the namespace default ACL. It is always read from the file and never gets
   a cache entry. */
static bool acl_rights_cache_name_is_cacheable(const char *name)
{
	return *name != '\0';
}

/* Lock the cache file for rewriting and re-read it. The lock is a separate
   <path>.lock file, created like the mail storage's other lock files, so
   every lock_method works. The .tmp file that gets rename()d over the cache
   is written under that lock. Only a full rebuild may create the cache file
   (allow_create), so an incrementally updated cache is always known to be
   complete. Returns 1 if locked, 0 if the cache can't be updated here
   (skipped silently), -1 on error. */
static int
acl_rights_cache_file_update_begin(struct acl_rights_cache_file *file,
				   bool allow_create)
{
	struct acl_backend_vfile *backend =
		container_of(file->backend, struct acl_backend_vfile, backend);
	const struct mail_storage_settings *mail_set =
		mailbox_list_get_mail_set(file->backend->list);
	struct mailbox_permissions perm;
	const char *lock_path, *tmp_path, *error;
	mode_t old_mask;
	int fd, ret;

	if (!acl_rights_cache_resolve_path(file))
		return -1;
	mailbox_list_get_root_permissions(file->backend->list, &perm);
	const struct file_create_settings lock_set = {
		.lock_timeout_secs = backend->rights_cache_lock_timeout_secs,
		.lock_settings = {
			.lock_method = mail_set->parsed_lock_method,
		},
		.mode = (int)perm.file_create_mode,
		.gid = perm.file_create_gid == (gid_t)-1 ? 0 :
			perm.file_create_gid,
		.gid_origin = perm.file_create_gid_origin,
	};
	lock_path = t_strdup_printf("%s.lock", file->path);
	ret = mail_storage_lock_create(lock_path, &lock_set, mail_set,
				       &file->lock, &error);
	if (ret < 0 && errno == ENOENT) {
		/* home or ACL root directory doesn't exist yet */
		enum mailbox_list_path_type type;
		const char *root_dir;

		struct mail_user *user =
			mailbox_list_get_user(file->backend->list);

		if (mail_user_home_mkdir(user) < 0)
			return -1;
		if (acl_backend_get_root_dir(file->backend, &root_dir, &type) &&
		    mailbox_list_mkdir_root(file->backend->list, root_dir,
					    type) < 0)
			return -1;
		ret = mail_storage_lock_create(lock_path, &lock_set, mail_set,
					       &file->lock, &error);
	}
	if (ret <= 0) {
		if (ret < 0 && ENOACCESS(errno)) {
			/* We're not allowed to write here (e.g. a public
			   namespace's ACL root) - skip silently like the
			   old acllist rebuild did. */
			e_debug(file->event, "%s", error);
			return 0;
		}
		/* an error, or the lock timeout was reached */
		e_error(file->event, "%s", error);
		return -1;
	}

	/* O_TRUNC: the .tmp may be a leftover from a crashed writer. It is
	   never supposed to be a symlink. */
	tmp_path = t_strdup_printf("%s.tmp", file->path);
	old_mask = umask(0);
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
		  perm.file_create_mode);
	umask(old_mask);
	if (fd == -1) {
		e_error(file->event, "open(%s, O_CREAT) failed: %m", tmp_path);
		file_lock_free(&file->lock);
		return -1;
	}
	if (perm.file_create_gid != (gid_t)-1 &&
	    fchown(fd, (uid_t)-1, perm.file_create_gid) < 0) {
		if (errno == EPERM) {
			e_error(file->event, "%s",
				eperm_error_get_chgrp("fchown", tmp_path,
					perm.file_create_gid,
					perm.file_create_gid_origin));
		} else {
			e_error(file->event, "fchown(%s) failed: %m",
				tmp_path);
		}
		/* with the wrong group others couldn't read the cache */
		i_close_fd(&fd);
		i_unlink(tmp_path);
		file_lock_free(&file->lock);
		return -1;
	}
	file->tmp_fd = fd;
	file->tmp_renamed = FALSE;
	/* Re-read the cache under the lock, so rewriting the file doesn't
	   lose concurrently made updates. */
	if (acl_rights_cache_file_refresh(file) < 0) {
		if (!allow_create || !file->read_failed) {
			acl_rights_cache_file_update_end(file);
			return -1;
		}
		/* A full rebuild may replace a cache file that can't be
		   read (e.g. corrupt content). The entries that would have
		   been preserved for not-locally-readable mailboxes are
		   lost, but that's better than the broken file blocking
		   every rebuild. */
	}
	if (!allow_create && acl_rights_cache_file_exists(file) <= 0) {
		/* There is no cache file to update - it has to be created
		   by a full rebuild. */
		acl_rights_cache_file_update_end(file);
		return 0;
	}
	return 1;
}

int acl_rights_cache_file_set(struct acl_rights_cache_file *file,
			      const char *name,
			      ARRAY_TYPE(acl_rights) *rights,
			      bool marker, const struct timeval *mtime)
{
	int ret;

	if (!acl_rights_cache_name_is_cacheable(name))
		return 1;
	if ((ret = acl_rights_cache_file_update_begin(file, FALSE)) <= 0)
		return ret;
	/* merge duplicate identifiers. This must happen after
	   update_begin(): the merging allocates from rights_pool, which
	   update_begin()'s refresh clears. */
	acl_rights_sort(rights, file->rights_pool);
	ret = acl_rights_cache_file_flush(file, rights, marker, name, mtime);
	if (ret == 0) {
		/* keep the in-memory copy in sync with what was just
		   written - readers within cache_secs would otherwise
		   still see the old state */
		ret = acl_rights_cache_file_read(file);
	}
	acl_rights_cache_file_update_end(file);
	return ret < 0 ? -1 : 1;
}

static bool
acl_rights_cache_rights_modify(struct acl_rights_cache_file *file,
			       const struct acl_rights_update *update,
			       ARRAY_TYPE(acl_rights) *rights)
{
	struct acl_rights *right;

	array_foreach_modifiable(rights, right) {
		if (acl_rights_cmp(&update->rights, right) == 0) {
			/* The identifier already exists for this mailbox,
			   modify its rights. */
			return acl_rights_cache_modify_right(right,
				file->rights_pool, update);
		}
	}
	return FALSE;
}

int acl_rights_cache_file_update(struct acl_rights_cache_file *file,
				 const struct acl_rights_update *update,
				 const char *name, bool marker,
				 const struct timeval *mtime)
{
	ARRAY_TYPE(acl_rights) rights;
	bool changed;
	int ret;

	if (!acl_rights_cache_name_is_cacheable(name))
		return 1;
	if ((ret = acl_rights_cache_file_update_begin(file, FALSE)) <= 0)
		return ret;

	/* Get the currently cached rights of the mailbox */
	t_array_init(&rights, 32);
	acl_rights_cache_file_get(file, name, file->rights_pool, &rights);
	/* merge duplicate identifiers, so the update reaches all of an
	   identifier's rights */
	acl_rights_sort(&rights, file->rights_pool);

	changed = acl_rights_cache_rights_modify(file, update, &rights);
	if (!changed) {
		/* No existing rights were modified, the update's rights
		   need to be added. */
		changed = acl_rights_cache_add_right(&rights,
						     file->rights_pool, update);
	}
	if (!changed) {
		acl_rights_cache_file_update_end(file);
		return 1;
	}

	ret = acl_rights_cache_file_flush(file, &rights, marker, name, mtime);
	if (ret == 0) {
		/* keep the in-memory copy in sync with what was just
		   written - readers within cache_secs would otherwise
		   still see the old state */
		ret = acl_rights_cache_file_read(file);
	}
	acl_rights_cache_file_update_end(file);
	return ret < 0 ? -1 : 1;
}

static bool
acl_rights_cache_rights_have_nonowner(const ARRAY_TYPE(acl_rights) *rights)
{
	const struct acl_rights *right;

	array_foreach(rights, right) {
		if (acl_rights_has_nonowner_lookup_changes(right))
			return TRUE;
	}
	return FALSE;
}

static bool
acl_rights_cache_entry_has_nonowner_lookups(
	const struct acl_rights_cache_entry *entry)
{
	return acl_rights_cache_rights_have_nonowner(&entry->rights);
}

void acl_rights_cache_evict(struct acl_backend *_backend, const char *name,
			    enum acl_rights_cache_evict_flags flags)
{
	struct acl_rights_cache_file *file = _backend->rights_cache_file;
	struct acl_backend_vfile *backend;
	const struct acl_rights_cache_entry *entry;
	bool had_nonowner;
	int ret;

	if (file == NULL) {
		/* not a vfile backend */
		return;
	}
	if (*name == '\0') {
		/* the namespace root is never cached */
		return;
	}
	backend = container_of(_backend, struct acl_backend_vfile, backend);
	if (backend->rebuilding_aclcache || backend->iterating_aclcache) {
		/* The iterated cache state must not change now. A stale
		   entry gets dropped by the next rebuild. */
		return;
	}

	entry = acl_rights_cache_find(file, name);
	if (entry == NULL)
		return;
	had_nonowner = entry->marker ||
		acl_rights_cache_entry_has_nonowner_lookups(entry);

	T_BEGIN {
		ARRAY_TYPE(acl_rights) empty_rights;
		const struct timeval no_mtime = { 0, 0 };

		t_array_init(&empty_rights, 1);
		/* a line that stays without rights tells when they were
		   found to be gone. A mailbox that no longer exists
		   doesn't need one, with mtime 0 its empty line isn't
		   kept. */
		ret = acl_rights_cache_file_set(file, name, &empty_rights,
			(flags & ACL_RIGHTS_CACHE_EVICT_KEEP_MARKER) != 0,
			(flags & ACL_RIGHTS_CACHE_EVICT_MAILBOX_GONE) == 0 &&
			acl_backend_storage_has_cached_files(_backend) ?
			&ioloop_timeval : &no_mtime);
	} T_END;

	if (ret > 0 && had_nonowner) {
		/* the mailbox may have been visible in other users'
		   shared namespaces */
		struct acl_user *auser = ACL_USER_CONTEXT(
			mailbox_list_get_user(_backend->list));
		if (auser != NULL) {
			(void)acl_lookup_dict_rebuild(
				auser->acl_lookup_dict,
				_backend->set->acl_dict_index);
		}
	}
}

void acl_rights_cache_verify(struct acl_object *aclobj,
			     const struct acl_rights *rights,
			     unsigned int count, const struct timeval *mtime)
{
	struct acl_backend_vfile *backend =
		container_of(aclobj->backend, struct acl_backend_vfile,
			     backend);
	struct acl_rights_cache_file *file =
		aclobj->backend->rights_cache_file;
	const struct acl_rights_cache_entry *entry;
	unsigned int i;
	bool marker;
	int ret;

	if (*aclobj->name == '\0') {
		/* the namespace root never has a cache entry */
		return;
	}
	if (backend->rebuilding_aclcache || backend->iterating_aclcache)
		return;
	if (mtime->tv_sec == ACL_VFILE_VALIDITY_MTIME_NOTFOUND ||
	    mtime->tv_sec == ACL_VFILE_VALIDITY_MTIME_NOACCESS) {
		/* There is no readable local ACL file - either the mailbox
		   has no ACLs or they were served from the cache. Nothing
		   to synchronize. */
		return;
	}

	acl_rights_cache_refresh(backend, TRUE);
	marker = acl_object_has_global_nonowner_lookup(aclobj);
	entry = acl_rights_cache_find(file, aclobj->name);
	/* The marker follows the configured ACLs, which can change without
	   the ACL file changing. Only a private namespace's sessions bring it
	   up to date: a shared namespace's session is another user's, and a
	   public namespace's cache is verified by all users. They may see
	   other settings, and would keep rewriting the entry. */
	bool old_marker = entry != NULL && entry->marker;
	bool marker_ok = TRUE;

	if (!acl_rights_cache_ns_is_private(file))
		marker = old_marker;
	else
		marker_ok = old_marker == marker;

	if (entry != NULL && timeval_cmp(&entry->mtime, mtime) == 0 &&
	    marker_ok)
		return;
	if (entry == NULL && count == 0 && marker_ok)
		return;
	if (entry != NULL && array_count(&entry->rights) == 0 &&
	    count == 0 && marker_ok) {
		/* an entry that has only flags and the ACL file has no
		   rights either - keep it as it is */
		return;
	}

	/* The ACL file was changed without going through
	   acl_backend_vfile_object_update() (e.g. dsync), or the configured
	   ACLs changed. If any nonowner lookup rights are involved in the
	   change, the ACL lookup dict needs a rebuild as well. Check before
	   file_set() invalidates the entry pointer. */
	bool nonowner_changes = marker;

	if (entry != NULL) {
		nonowner_changes = entry->marker != marker ||
			acl_rights_cache_entry_has_nonowner_lookups(entry);
	}
	for (i = 0; i < count && !nonowner_changes; i++) {
		if (acl_rights_has_nonowner_lookup_changes(&rights[i]))
			nonowner_changes = TRUE;
	}

	T_BEGIN {
		/* file_set() modifies the array while merging, use a copy */
		ARRAY_TYPE(acl_rights) copy;

		t_array_init(&copy, count + 1);
		array_append(&copy, rights, count);
		ret = acl_rights_cache_file_set(file, aclobj->name, &copy,
						marker, mtime);
	} T_END;
	if (ret <= 0) {
		/* error, or no cache file - the refresh above already
		   attempted the rebuild that would create it */
		return;
	}

	if (nonowner_changes) {
		struct acl_user *auser = ACL_USER_CONTEXT(
			mailbox_list_get_user(aclobj->backend->list));
		if (auser != NULL) {
			(void)acl_lookup_dict_rebuild(auser->acl_lookup_dict,
				aclobj->backend->set->acl_dict_index);
		}
	}
}

/* Read the object's ACLs and return TRUE if its global rights give a
   nonowner the lookup right. Returns FALSE if reading them fails. */
static bool acl_rights_cache_read_global_nonowner(struct acl_object *aclobj)
{
	if (!array_is_created(&aclobj->rights)) {
		aclobj->rights_pool =
			pool_alloconly_create("acl rights", 256);
		i_array_init(&aclobj->rights, 8);
	}
	if (acl_backend_get_mailbox_acl(aclobj->backend, aclobj) < 0)
		return FALSE;
	return acl_object_has_global_nonowner_lookup(aclobj);
}

/* The dovecot-acl-list file of earlier versions, in the same directory as
   the cache. */
static const char *
acl_rights_cache_legacy_list_path(struct acl_rights_cache_file *file)
{
	const char *p = strrchr(file->path, '/');

	i_assert(p != NULL);
	return t_strdup_printf("%.*s/"ACL_LEGACY_LIST_FILENAME,
			       (int)(p - file->path), file->path);
}

/* Read the mailbox names from the dovecot-acl-list file, which lists the
   mailboxes with nonowner lookup rights as "<mtime> <name>" lines. Returns
   1 if the file exists, 0 if it doesn't or its content is broken, -1 on
   error. */
static int
acl_rights_cache_read_legacy_list(struct acl_rights_cache_file *file,
				  pool_t pool, ARRAY_TYPE(const_string) *names)
{
	struct istream *input;
	const char *path, *line, *p, *name;
	int ret = 1;

	path = acl_rights_cache_legacy_list_path(file);
	input = acl_rights_cache_open_stream(path);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		p = strchr(line, ' ');
		if (p == NULL || p[1] == '\0') {
			/* Nothing in the file can be trusted. Go on as if it
			   didn't exist, so a successful rebuild removes it. */
			e_error(file->event, "Broken %s file: %s - ignoring it",
				ACL_LEGACY_LIST_FILENAME, path);
			array_clear(names);
			ret = 0;
			break;
		}
		name = p_strdup(pool, p + 1);
		array_push_back(names, &name);
	}
	if (ret > 0 && input->stream_errno != 0) {
		if (ENOTFOUND(input->stream_errno))
			ret = 0;
		else {
			e_error(file->event, "read(%s) failed: %s", path,
				i_stream_get_error(input));
			ret = -1;
		}
	}
	i_stream_destroy(&input);
	array_sort(names, i_strcmp_p);
	return ret;
}

/* A rebuild in the owner's own namespace removes dovecot-acl-list, so
   finding it next to the cache means a version without the rights cache
   wrote it afterwards. */
static bool
acl_rights_cache_legacy_list_exists(struct acl_rights_cache_file *file)
{
	struct stat st;

	if (acl_rights_cache_ns_is_shared(file))
		return FALSE;
	return stat(acl_rights_cache_legacy_list_path(file), &st) == 0;
}

/* The mailbox's local ACL file can't be relied on. Open the mailbox, so a
   storage keeping its mailbox files in a local cache (obox metacache)
   fetches them, and read the ACL file while the mailbox is open. opened_r is
   set to TRUE if the mailbox could be opened: its ACL file is then known to
   be current, also when there is none. */
static int
acl_rights_cache_rebuild_fetch(struct acl_backend_vfile *backend,
			       struct acl_object *aclobj, const char *vname,
			       pool_t pool, ARRAY_TYPE(acl_rights) *rights_r,
			       struct timeval *mtime_r, bool *opened_r)
{
	struct acl_rights_cache_file *file = backend->backend.rights_cache_file;
	struct mailbox *box;
	int ret;

	e_debug(file->event, "Rebuilding %s: Fetching the ACL file of mailbox %s",
		file->path, vname);
	box = mailbox_alloc(backend->backend.list, vname,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND) {
			/* listed, but gone - there is no ACL file to read */
			e_debug(file->event, "Mailbox %s doesn't exist, not fetching its ACL file",
				vname);
			ret = 0;
		} else {
			e_error(file->event, "Rebuilding %s failed: Can't open mailbox %s: %s",
				file->path, vname,
				mailbox_get_last_internal_error(box, NULL));
			ret = -1;
		}
		mailbox_free(&box);
		return ret;
	}
	/* The mailbox's files may be removed from the local cache again as
	   soon as it's closed. */
	*opened_r = TRUE;
	ret = acl_backend_vfile_object_read_rights(aclobj, pool,
						   rights_r, mtime_r);
	mailbox_free(&box);
	return ret;
}

/* Which mailboxes a rebuild fetches with acl_rights_cache_rebuild_fetch().
   Only a storage with cached files fetches anything. A local ACL file
   older than the mailbox's cache entry counts as missing. */
enum acl_rights_cache_fetch {
	/* The default. Fetch the mailboxes that dovecot-acl-list names and
	   that have neither a local ACL file nor a cache entry. Without
	   dovecot-acl-list nothing is fetched. The cache entries of the
	   mailboxes without a local ACL file are preserved. */
	ACL_RIGHTS_CACHE_FETCH_LEGACY,
	/* dovecot-acl-list exists next to a usable cache: a version without
	   the rights cache was used after the last rebuild, and the cache
	   entries may be stale. Fetch the mailboxes that have a cache entry
	   or that dovecot-acl-list names. Their local ACL files aren't read:
	   that version may have changed them on another server, so a local
	   ACL file can be an old copy even when it's as new as the cache
	   entry. */
	ACL_RIGHTS_CACHE_FETCH_LEGACY_AND_STALE_CACHED,
	/* There is no usable rights cache and no dovecot-acl-list, but the
	   ACL lookup dict has (or may have) shares of this user. Fetch every
	   mailbox whose ACL file isn't among the storage's cached files.
	   Without a rights cache there is no entry mtime to compare with,
	   so a cached ACL file is used even if it's an old copy. Opening
	   every mailbox (FETCH_ALL) would avoid that, but this runs from an
	   ordinary ACL read. */
	ACL_RIGHTS_CACHE_FETCH_MISSING,
	/* doveadm acl recalc: fetch every mailbox. A local ACL file is the
	   copy from when the mailbox was last open on this server, and the
	   mailbox may have been changed elsewhere since. The newer cache
	   entry check notices that only if the change also updated the
	   cache, so the local file isn't read at all. */
	ACL_RIGHTS_CACHE_FETCH_ALL,
};

static int
acl_rights_cache_rebuild_mailbox(struct acl_backend_vfile *backend,
				 struct ostream *output, string_t *str,
				 const char *vname,
				 const ARRAY_TYPE(const_string) *legacy_names,
				 enum acl_rights_cache_fetch fetch,
				 bool *have_nonowner)
{
	struct acl_rights_cache_file *file = backend->backend.rights_cache_file;
	const struct acl_rights_cache_entry *entry;
	struct acl_object *aclobj;
	ARRAY_TYPE(acl_rights) mailbox_rights;
	const ARRAY_TYPE(acl_rights) *write_rights = NULL;
	const char *name;
	struct timeval mtime = { 0, 0 };
	bool want_fetch = FALSE, fetched = FALSE;
	int ret;

	name = mailbox_list_get_storage_name(backend->backend.list, vname);
	if (!acl_rights_cache_name_is_cacheable(name))
		return 0;
	/* Read the ACL file directly - going through the acl_object
	   refresh would flush and repopulate the process-wide ACL cache
	   as a side effect, and merge in the configuration-provided ACLs,
	   which must not end up in the rights cache. */
	aclobj = acl_object_init_from_name(&backend->backend, name);
	t_array_init(&mailbox_rights, 16);
	/* the rights can't be allocated from a data stack pool - the
	   reader parses them inside its own data stack frame */
	pool_t pool = pool_alloconly_create("acl rights cache rebuild", 1024);
	/* The storage may have a mailbox's files locally only while the
	   mailbox is open (e.g. obox metacache). Then a missing ACL file
	   doesn't mean there is none, and an existing one may be an old
	   copy. */
	bool storage_cached =
		acl_backend_storage_has_cached_files(&backend->backend);

	entry = acl_rights_cache_find(file, name);
	bool legacy_named = legacy_names != NULL &&
		array_bsearch(legacy_names, name, search_strcmp) != NULL;
	if (fetch == ACL_RIGHTS_CACHE_FETCH_ALL ||
	    (fetch == ACL_RIGHTS_CACHE_FETCH_LEGACY_AND_STALE_CACHED &&
	     (entry != NULL || legacy_named))) {
		/* Handle a local ACL file like one that isn't locally
		   available, it may be an old copy. With
		   ACL_RIGHTS_CACHE_FETCH_LEGACY_AND_STALE_CACHED also when
		   it's as new as the cache entry. */
		ret = 0;
	} else {
		ret = acl_backend_vfile_object_read_rights(aclobj, pool,
				&mailbox_rights, &mtime);
	}
	if (ret > 0 && storage_cached && entry != NULL &&
	    timeval_cmp(&entry->mtime, &mtime) > 0) {
		/* The cache entry is newer than the local ACL file: the
		   mailbox was changed on another server, and its local files
		   aren't refreshed before it's next opened. Handle it like
		   an ACL file that isn't locally available. */
		array_clear(&mailbox_rights);
		i_zero(&mtime);
		ret = 0;
	}
	if (ret != 0 || !storage_cached) {
		/* The ACL file was read or reading it failed, or the
		   mailbox's files are always local and it has no ACL
		   file. */
	} else if (entry != NULL) {
		/* The cache entry is preserved as it is, unless everything
		   is wanted, or a version without the rights cache may have
		   changed the mailbox's ACLs since it was written. */
		want_fetch = fetch != ACL_RIGHTS_CACHE_FETCH_LEGACY;
	} else {
		/* There is no cache entry to preserve. Either everything is
		   wanted or dovecot-acl-list says the mailbox has nonowner
		   lookup rights. */
		want_fetch = fetch == ACL_RIGHTS_CACHE_FETCH_MISSING ||
			fetch == ACL_RIGHTS_CACHE_FETCH_ALL || legacy_named;
	}
	if (want_fetch) {
		/* Fetch the mailbox's ACL file, so its shares aren't lost. */
		ret = acl_rights_cache_rebuild_fetch(backend, aclobj, vname,
						     pool, &mailbox_rights,
						     &mtime, &fetched);
	}
	if (ret > 0) {
		/* merge duplicate identifiers, like the other writers do */
		acl_rights_sort(&mailbox_rights, pool);
		write_rights = &mailbox_rights;
	} else if (ret == 0 && storage_cached && !fetched && entry != NULL) {
		/* The mailbox's ACL file isn't locally available, e.g. with
		   obox the mailbox isn't in metacache. Preserve its existing
		   cache entry - dropping the entry would also remove the
		   mailbox's share entries from the ACL lookup dict. A mailbox
		   that was just fetched and has no ACL file really has none,
		   so its entry is dropped. */
		write_rights = &entry->rights;
		mtime = entry->mtime;
	}
	if (ret >= 0) {
		/* The configured ACLs may provide nonowner lookup rights.
		   The marker flag is set then, also next to the ACL file's
		   rights, so the mailbox stays part of the nonowner
		   iteration and the ACL lookup dict whatever the file says.
		   The rights themselves always come from the
		   configuration. A public namespace keeps the marker it
		   has, like acl_rights_cache_verify() does. */
		bool marker = acl_rights_cache_ns_is_private(file) ?
			acl_rights_cache_read_global_nonowner(aclobj) :
			(entry != NULL && entry->marker);

		acl_rights_cache_write_line(file, output, str, name, &mtime,
			marker, entry == NULL ? NULL : entry->unknown_flags,
			write_rights);
		if (!*have_nonowner &&
		    (marker ||
		     (write_rights != NULL &&
		      acl_rights_cache_rights_have_nonowner(write_rights))))
			*have_nonowner = TRUE;
	}
	acl_object_deinit(&aclobj);
	pool_unref(&pool);
	return ret < 0 ? -1 : 0;
}

static int acl_rights_cache_rebuild_real(struct acl_backend_vfile *backend,
					 bool fetch_all, bool *have_nonowner_r)
{
	struct mailbox_list *list = backend->backend.list;
	struct acl_rights_cache_file *file = backend->backend.rights_cache_file;
	struct mail_namespace *ns = mailbox_list_get_namespace(list);
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct ostream *output;
	string_t *str;
	const char *tmp_path;
	int ret = 0;

	if (!acl_rights_cache_resolve_path(file))
		return 0;
	if ((ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		/* we can't write anything here */
		return 0;
	}

	int begin_ret = acl_rights_cache_file_update_begin(file, TRUE);
	if (begin_ret <= 0)
		return begin_ret;

	pool_t pool = pool_alloconly_create("acl rights cache rebuild", 1024);
	ARRAY_TYPE(const_string) legacy_names;
	const ARRAY_TYPE(const_string) *seed_names = NULL;
	p_array_init(&legacy_names, pool, 16);
	bool rights_cache_usable = acl_rights_cache_file_exists(file) > 0 &&
		!file->read_failed;
	/* only then an ACL file that isn't local can exist at all */
	bool storage_cached =
		acl_backend_storage_has_cached_files(&backend->backend);
	/* doveadm acl recalc fetches the local ACL files as well. The
	   fallback to ACL_RIGHTS_CACHE_FETCH_MISSING below runs from an
	   ordinary ACL read and fetches only the missing ones. */
	enum acl_rights_cache_fetch fetch = fetch_all && storage_cached ?
		ACL_RIGHTS_CACHE_FETCH_ALL : ACL_RIGHTS_CACHE_FETCH_LEGACY;
	int seed_ret = acl_rights_cache_read_legacy_list(file, pool,
							 &legacy_names);
	if (seed_ret < 0) {
		pool_unref(&pool);
		acl_rights_cache_file_update_end(file);
		return -1;
	}
	if (seed_ret > 0) {
		/* A dovecot-acl-list left behind by an earlier version names
		   the mailboxes with nonowner lookup rights. Without a
		   usable cache it is from before the upgrade, and it tells
		   which mailboxes to fetch when their ACL files aren't
		   locally readable. Next to a usable cache it was written
		   after the last rebuild, which removes it: the earlier
		   version was used again, and the ACLs it changed never
		   reached the cache. Then the cached mailboxes and those the
		   list names are fetched, also when they have a local ACL
		   file, which may be an old copy. */
		seed_names = &legacy_names;
		if (fetch == ACL_RIGHTS_CACHE_FETCH_LEGACY &&
		    rights_cache_usable && storage_cached)
			fetch = ACL_RIGHTS_CACHE_FETCH_LEGACY_AND_STALE_CACHED;
	} else if (!fetch_all && !rights_cache_usable && storage_cached) {
		/* There is no usable cache to preserve entries from and no
		   list either, so the mailboxes whose ACL files aren't
		   locally available would be left out, and the ACL lookup
		   dict rebuild would then drop their shares. The dict tells
		   whether there is anything to protect at all. */
		struct acl_user *auser = ACL_USER_CONTEXT(
			mailbox_list_get_user(backend->backend.list));

		if (auser != NULL &&
		    acl_lookup_dict_has_shares(auser->acl_lookup_dict,
				backend->backend.set->acl_dict_index) != 0) {
			/* shares exist, but nothing says which mailboxes -
			   fetch them all (also when the dict can't tell) */
			fetch = ACL_RIGHTS_CACHE_FETCH_MISSING;
		} else {
			/* Normal for a user without shares. With shares it
			   means the dict doesn't know them, e.g. no
			   acl_sharing_map, or acl_dict_index without the
			   reverse index in the dict. */
			e_debug(file->event, "Rebuilding %s: No %s and no shares of the user in the ACL sharing dict, not fetching ACL files that don't exist in the local cache",
				file->path, ACL_LEGACY_LIST_FILENAME);
		}
	}

	const char *fetch_str = "";
	switch (fetch) {
	case ACL_RIGHTS_CACHE_FETCH_LEGACY:
		if (seed_names != NULL)
			fetch_str = ", fetching the ACL files dovecot-acl-list names";
		break;
	case ACL_RIGHTS_CACHE_FETCH_LEGACY_AND_STALE_CACHED:
		fetch_str = ", fetching the ACL files of the cached mailboxes and those dovecot-acl-list names";
		break;
	case ACL_RIGHTS_CACHE_FETCH_MISSING:
		fetch_str = ", fetching all ACL files that don't exist in the local cache";
		break;
	case ACL_RIGHTS_CACHE_FETCH_ALL:
		fetch_str = ", fetching all ACL files";
		break;
	}
	e_debug(file->event, "Rebuilding %s%s", file->path,
		storage_cached ? fetch_str : "");

	tmp_path = t_strdup_printf("%s.tmp", file->path);
	output = o_stream_create_fd_file(file->tmp_fd, 0, FALSE);
	o_stream_cork(output);
	acl_rights_cache_write_header(output);

	str = str_new(default_pool, 256);
	iter = mailbox_list_iter_init(list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while (ret == 0 &&
	       (info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		ret = acl_rights_cache_rebuild_mailbox(backend, output, str,
						       info->vname, seed_names,
						       fetch, have_nonowner_r);
	} T_END;
	pool_unref(&pool);
	if (mailbox_list_iter_deinit(&iter) < 0) {
		e_error(file->event, "Rebuilding %s failed: Mailbox list iteration failed: %s",
			file->path,
			mailbox_list_get_last_internal_error(list, NULL));
		ret = -1;
	}
	str_free(&str);

	if (o_stream_finish(output) < 0) {
		e_error(file->event, "write(%s) failed: %s", tmp_path,
			o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);

	if (ret == 0) {
		if (rename(tmp_path, file->path) < 0) {
			e_error(file->event, "rename(%s, %s) failed: %m",
				tmp_path, file->path);
			ret = -1;
		} else {
			file->tmp_renamed = TRUE;
		}
	}
	if (ret == 0) {
		/* reload the in-memory copy */
		if (acl_rights_cache_file_read(file) < 0)
			ret = -1;
		file->last_check = ioloop_time;
	}
	if (ret == 0) {
		/* The cache now has everything dovecot-acl-list could tell.
		   An earlier version rebuilds the list by itself when it is
		   missing. Only a full rebuild removes it, so finding it
		   again later means such a version was used in between. */
		i_unlink_if_exists(acl_rights_cache_legacy_list_path(file));
	}
	acl_rights_cache_file_update_end(file);
	return ret < 0 ? -1 : 1;
}

static int
acl_rights_cache_rebuild_full(struct acl_backend_vfile *backend,
			      bool fetch_all)
{
	struct acl_user *auser =
		ACL_USER_CONTEXT(mailbox_list_get_user(backend->backend.list));
	int ret;

	if (backend->rebuilding_aclcache)
		return 0;
	if (acl_rights_cache_ns_is_shared(backend->backend.rights_cache_file)) {
		/* A shared namespace's ACL root is the owner's own mail root,
		   so this would create the owner's cache from the few
		   mailboxes this user sees. Leave it to the owner's own
		   session. */
		return 0;
	}

	bool have_nonowner = FALSE;
	backend->rebuilding_aclcache = TRUE;
	ret = acl_rights_cache_rebuild_real(backend, fetch_all, &have_nonowner);
	if (ret > 0 && have_nonowner && auser != NULL) {
		/* The cached nonowner ACLs may have changed, rebuild the
		   lookup dict as well. Skipped when the cache has no
		   nonowner lookup rights at all - the same user may have
		   another ACL area with them (e.g. an imapc frontend of a
		   backend that has the real ACLs), and rebuilding the dict
		   from this one would remove that area's share entries. */
		(void)acl_lookup_dict_rebuild(
			auser->acl_lookup_dict,
			backend->backend.set->acl_dict_index);
	}
	backend->rebuilding_aclcache = FALSE;
	return ret < 0 ? -1 : 0;
}

int acl_rights_cache_rebuild(struct acl_backend_vfile *backend)
{
	return acl_rights_cache_rebuild_full(backend, FALSE);
}

struct acl_mailbox_list_context *
acl_backend_vfile_nonowner_iter_init(struct acl_backend *_backend)
{
	struct acl_backend_vfile *backend =
		container_of(_backend, struct acl_backend_vfile, backend);
	struct acl_rights_cache_list_context_vfile *ctx;

	acl_rights_cache_refresh(backend, TRUE);

	ctx = i_new(struct acl_rights_cache_list_context_vfile, 1);
	ctx->ctx.backend = _backend;
	if (acl_rights_cache_file_exists(_backend->rights_cache_file) <= 0 ||
	    _backend->rights_cache_file->read_failed) {
		/* There is no cache file (the rebuild failed or was
		   skipped), or reading it failed, so the nonowner mailboxes
		   are unknown. Fail the iteration instead of yielding an
		   empty result - an empty result would make the ACL lookup
		   dict rebuild remove the user's existing share entries. */
		ctx->ctx.failed = TRUE;
	}
	backend->iterating_aclcache = TRUE;
	return &ctx->ctx;
}

bool acl_backend_vfile_nonowner_iter_next(struct acl_mailbox_list_context *_ctx,
					  const char **name_r)
{
	struct acl_rights_cache_list_context_vfile *ctx =
		container_of(_ctx, struct acl_rights_cache_list_context_vfile,
			     ctx);
	struct acl_backend *backend = _ctx->backend;
	const struct acl_rights_cache_entry *rightslist;
	unsigned int count;

	if (_ctx->failed)
		return FALSE;

	rightslist = array_get(&backend->rights_cache_file->entries,
			       &count);
	if (count == 0)
		_ctx->empty = TRUE;
	while (ctx->idx < count) {
		const struct acl_rights_cache_entry *entry =
			&rightslist[ctx->idx++];

		/* Skip mailboxes whose cached rights don't give any
		   non-owner the lookup right - they can't be visible in
		   other users' shared namespaces. An entry with a marker is
		   returned: it exists exactly because the mailbox has
		   nonowner lookup rights from configured ACLs. */
		if (entry->marker ||
		    acl_rights_cache_entry_has_nonowner_lookups(entry)) {
			*name_r = entry->name;
			return TRUE;
		}
	}
	return FALSE;
}

int
acl_backend_vfile_nonowner_iter_deinit(struct acl_mailbox_list_context *ctx)
{
	struct acl_backend_vfile *backend =
		container_of(ctx->backend, struct acl_backend_vfile, backend);
	int ret;

	backend->iterating_aclcache = FALSE;
	if (ctx->failed)
		ret = -1;
	else if (ctx->empty)
		ret = 0;
	else
		ret = 1;
	i_free(ctx);
	return ret;
}

int acl_backend_vfile_nonowner_lookups_rebuild(struct acl_backend *_backend,
					       bool fetch_all)
{
	struct acl_backend_vfile *backend =
		container_of(_backend, struct acl_backend_vfile, backend);

	return acl_rights_cache_rebuild_full(backend, fetch_all);
}

/* TRUE if name is root or a child of it. */
static bool
acl_rights_cache_name_in_tree(const char *name, const char *root, char sep)
{
	size_t len = strlen(root);

	return strncmp(name, root, len) == 0 &&
		(name[len] == '\0' || name[len] == sep);
}

enum acl_rights_cache_move_type {
	/* Remove the entry for root_name. Exact match only: deleting a mailbox
	   leaves its children in place as \NoSelect mailboxes, ACLs and
	   all. */
	ACL_RIGHTS_CACHE_MOVE_DELETE,
	/* Move root_name and its children under dest_root_name. */
	ACL_RIGHTS_CACHE_MOVE_RENAME,
	/* Remove root_name and its children. Used when the mailbox moved to a
	   list this backend's cache cannot describe. */
	ACL_RIGHTS_CACHE_MOVE_DROP,
};

static bool
acl_rights_cache_entry_is_nonowner(const struct acl_rights_cache_entry *entry)
{
	/* a marker exists exactly because the mailbox has nonowner lookup
	   rights from configured ACLs */
	return entry->marker ||
		acl_rights_cache_entry_has_nonowner_lookups(entry);
}

static void
acl_rights_cache_write_entry(struct acl_rights_cache_file *file,
			     struct ostream *output, string_t *str,
			     const struct acl_rights_cache_entry *entry,
			     const char *name)
{
	acl_rights_cache_write_line(file, output, str, name, &entry->mtime,
				    entry->marker, entry->unknown_flags,
				    &entry->rights);
}

/* Update the entries of a renamed or deleted mailbox in place, reading no
   mailbox at all: the mtime is carried over from the old entry, because the
   mailbox's own dovecot-acl file is not touched by a rename. Recomputing it
   would make acl_rights_cache_verify() rewrite the entry for nothing.
   Returns 1 if the cache was updated, 0 if there was nothing to update and
   -1 on error. */
static int
acl_rights_cache_file_move(struct acl_rights_cache_file *file,
			   enum acl_rights_cache_move_type type,
			   const char *root_name, const char *dest_root_name,
			   bool *dropped_nonowner_r)
{
	const struct acl_rights_cache_entry *entry;
	struct ostream *output;
	string_t *str, *src_name, *dest_name;
	size_t root_len, dest_root_len = 0;
	char sep;
	bool changed = FALSE;
	int ret = 0;

	*dropped_nonowner_r = FALSE;

	if ((ret = acl_rights_cache_file_update_begin(file, FALSE)) <= 0)
		return ret;

	sep = mailbox_list_get_hierarchy_sep(file->backend->list);
	output = o_stream_create_fd_file(file->tmp_fd, 0, FALSE);
	o_stream_cork(output);
	acl_rights_cache_write_header(output);
	str = str_new(default_pool, 256);
	ret = 0;

	root_len = strlen(root_name);
	src_name = t_str_new(128);
	dest_name = t_str_new(128);
	if (type == ACL_RIGHTS_CACHE_MOVE_RENAME) {
		dest_root_len = strlen(dest_root_name);
		str_append(src_name, root_name);
		str_append(dest_name, dest_root_name);
	}

	array_foreach(&file->entries, entry) {
		bool matched =
			type == ACL_RIGHTS_CACHE_MOVE_DELETE ?
			strcmp(entry->name, root_name) == 0 :
			acl_rights_cache_name_in_tree(entry->name,
						      root_name, sep);
		if (matched) {
			changed = TRUE;
			if (type == ACL_RIGHTS_CACHE_MOVE_RENAME) {
				str_truncate(dest_name, dest_root_len);
				str_append(dest_name, entry->name + root_len);
				acl_rights_cache_write_entry(file, output, str,
					entry, str_c(dest_name));
			} else if (acl_rights_cache_entry_is_nonowner(entry)) {
				*dropped_nonowner_r = TRUE;
			}
			continue;
		}
		bool overwritten = FALSE;
		if (type == ACL_RIGHTS_CACHE_MOVE_RENAME &&
		    acl_rights_cache_name_in_tree(entry->name, dest_root_name,
						  sep)) {
			/* An entry that a moved entry lands on was overwritten
			   by the rename and must be dropped. The moved entry
			   is looked up by its old name, since it can come
			   after this one. */
			str_truncate(src_name, root_len);
			str_append(src_name, entry->name + dest_root_len);
			overwritten = acl_rights_cache_find(file,
				str_c(src_name)) != NULL;
		}
		if (overwritten) {
			changed = TRUE;
			if (acl_rights_cache_entry_is_nonowner(entry))
				*dropped_nonowner_r = TRUE;
			continue;
		}
		acl_rights_cache_write_entry(file, output, str, entry,
					     entry->name);
	}
	str_free(&str);

	if (!changed) {
		/* no entry for the mailbox - nothing to update */
		o_stream_abort(output);
		o_stream_destroy(&output);
		acl_rights_cache_file_update_end(file);
		return 0;
	}
	if (o_stream_finish(output) < 0) {
		e_error(file->event, "write(%s.tmp) failed: %s",
			file->path, o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);
	if (ret == 0) T_BEGIN {
		const char *tmp_path = t_strdup_printf("%s.tmp",
						       file->path);
		if (rename(tmp_path, file->path) < 0) {
			e_error(file->event, "rename(%s, %s) failed: %m",
				tmp_path, file->path);
			ret = -1;
		} else {
			file->tmp_renamed = TRUE;
		}
	} T_END;
	if (ret == 0) {
		/* keep the in-memory copy in sync with what was just
		   written */
		ret = acl_rights_cache_file_read(file);
	}
	acl_rights_cache_file_update_end(file);
	return ret < 0 ? -1 : 1;
}

int acl_backend_vfile_nonowner_lookups_rename(struct acl_backend *_backend,
					      const char *name,
					      struct acl_backend *dest_backend,
					      const char *dest_name)
{
	struct acl_backend_vfile *backend =
		container_of(_backend, struct acl_backend_vfile, backend);
	enum acl_rights_cache_move_type type;
	bool dropped_nonowner;
	int ret;

	if (backend->rebuilding_aclcache || backend->iterating_aclcache) {
		/* The iterated cache state must not change now. A stale
		   entry gets dropped by the next rebuild. */
		return 0;
	}
	if (dest_name == NULL)
		type = ACL_RIGHTS_CACHE_MOVE_DELETE;
	else if (dest_backend == _backend &&
		 acl_rights_cache_name_is_cacheable(dest_name))
		type = ACL_RIGHTS_CACHE_MOVE_RENAME;
	else {
		/* The mailbox moved to a list this cache can't describe -
		   drop the subtree. FIXME: The destination's cache gets the
		   moved mailboxes' entries only when their ACL files are next
		   read there. The rename reads the renamed mailbox's when it
		   opens it, but not its children's. Until then the lookup dict
		   misses grantees whose only shares are in those children, and
		   shared namespaces don't list them. Not reachable with obox,
		   which refuses renames between namespaces. A fix would write
		   the dropped entries under their new names to dest_backend's
		   cache after this file's lock is released (a RENAME if both
		   namespaces use this file), then rebuild the dict once. */
		type = ACL_RIGHTS_CACHE_MOVE_DROP;
	}

	/* Move the entries instead of rebuilding the cache: with a
	   MAIL_STORAGE_CLASS_FLAG_CACHED_FILES storage a rebuild keeps the
	   entry of a mailbox whose ACL file isn't locally available only
	   under its existing name, so renamed mailboxes would lose theirs
	   unless every mailbox were opened. */
	T_BEGIN {
		ret = acl_rights_cache_file_move(_backend->rights_cache_file,
						 type, name, dest_name,
						 &dropped_nonowner);
	} T_END;
	if (ret > 0 && dropped_nonowner) {
		/* the mailbox may have been visible in other users' shared
		   namespaces */
		struct acl_user *auser = ACL_USER_CONTEXT(
			mailbox_list_get_user(_backend->list));
		if (auser != NULL) {
			(void)acl_lookup_dict_rebuild(auser->acl_lookup_dict,
					_backend->set->acl_dict_index);
		}
	}
	return ret < 0 ? -1 : 0;
}
