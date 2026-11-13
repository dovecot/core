/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "time-util.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
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

	/* sorted by name, one entry per mailbox */
	ARRAY_TYPE(acl_rights_cache_entry) entries;

	pool_t rights_pool;

	bool has_path:1;
	/* reading an existing cache file failed (e.g. corrupt content) -
	   the in-memory copy is empty, but must not be treated as an
	   authoritative empty result */
	bool read_failed:1;
};

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
