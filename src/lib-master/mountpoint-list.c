/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "file-copy.h"
#include "safe-mkstemp.h"
#include "str.h"
#include "write-full.h"
#include "mountpoint.h"
#include "mountpoint-list.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

struct mountpoint_list {
	pool_t pool;
	const char *perm_path, *state_path;
	ARRAY(struct mountpoint_list_rec *) recs;
	struct stat load_st;
	bool load_failed;
};

struct mountpoint_list_iter {
	struct mountpoint_list *list;
	unsigned int idx;
};

const char *const mountpoint_list_default_ignore_types[] = {
	"proc", /* Linux, Solaris */
	"procfs", /* AIX, BSD */
	"tmpfs", /* Linux */
	"sysfs", /* Linux */
	"debugfs", /* Linux */
	"securityfs", /* Linux */
	"devpts", /* Linux */
	"devtmpfs", /* Linux */
	"rpc_pipefs", /* Linux */
	"fusectl", /* Linux */
	"nfsd", /* Linux */
	"cgroup", /* Linux */
	"binfmt_misc", /* Linux */
	"devfs", /* Solaris, OSX, BSD */
	"ctfs", /* Solaris */
	"mntfs", /* Solaris */
	"objfs", /* Solaris */
	"sharefs", /* Solaris */
	"lofs", /* Solaris */
	"fd", /* Solaris */
	NULL
};

const char *const mountpoint_list_default_ignore_prefixes[] = {
	"/cdrom",
	"/media",
	"/sys",
	"/proc",
	"/var/run",
	"/var/tmp",
	"/tmp",
	"/run",
#ifdef __APPLE__
	"/Volumes",
	"/private/tmp",
#endif
	NULL
};

static struct mountpoint_list * ATTR_NULL(1)
mountpoint_list_init_internal(const char *perm_path, const char *state_path)
{
	struct mountpoint_list *list;
	pool_t pool;

	pool = pool_alloconly_create("mountpoint list", 1024);
	list = p_new(pool, struct mountpoint_list, 1);
	list->pool = pool;
	list->perm_path = p_strdup(pool, perm_path);
	list->state_path = p_strdup(pool, state_path);
	p_array_init(&list->recs, pool, 16);

	(void)mountpoint_list_refresh(list);
	return list;
}

struct mountpoint_list *
mountpoint_list_init(const char *perm_path, const char *state_path)
{
	return mountpoint_list_init_internal(perm_path, state_path);
}

struct mountpoint_list *
mountpoint_list_init_readonly(const char *state_path)
{
	return mountpoint_list_init_internal(NULL, state_path);
}

void mountpoint_list_deinit(struct mountpoint_list **_list)
{
	struct mountpoint_list *list = *_list;

	*_list = NULL;
	pool_unref(&list->pool);
}

static int mountpoint_list_load(struct mountpoint_list *list)
{
	struct mountpoint_list_rec rec;
	struct istream *input;
	char *p, *line;
	unsigned int len;
	int fd, ret = 0;

	memset(&rec, 0, sizeof(rec));

	fd = open(list->state_path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT) {
			i_error("open(%s) failed: %m", list->state_path);
			return -1;
		}
		if (list->perm_path == NULL) {
			/* we're in read-only mode */
			return 0;
		}
		if (file_copy(list->perm_path, list->state_path, FALSE) < 0)
			return -1;
		fd = open(list->perm_path, O_RDONLY);
		if (fd == -1) {
			if (errno == ENOENT) {
				/* perm_path didn't exist either */
				return 0;
			}
			i_error("open(%s) failed: %m", list->state_path);
			return -1;
		}
	}
	if (fstat(fd, &list->load_st) < 0)
		i_error("fstat(%s) failed: %m", list->state_path);
	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		p = strchr(line, ' ');
		if (p == NULL) {
			i_error("Corrupted line in %s: %s",
				list->state_path, line);
			ret = -1;
			break;
		}
		*p++ = '\0';
		rec.mount_path = p;
		rec.state = line;
		len = strlen(p);
		if (len > 0 && p[len-1] == '*') {
			p[len-1] = '\0';
			rec.wildcard = TRUE;
		}
		mountpoint_list_add(list, &rec);
	}
	if (input->stream_errno != 0) {
		i_error("read(%s) failed: %m", list->state_path);
		ret = -1;
	}
	i_stream_destroy(&input);
	return ret;
}

int mountpoint_list_refresh(struct mountpoint_list *list)
{
	struct stat st;

	if (list->load_st.st_mtime != 0) {
		if (stat(list->state_path, &st) < 0) {
			if (errno == ENOENT)
				return 0;
			i_error("stat(%s) failed: %m", list->state_path);
			return -1;
		}
		if (st.st_mtime == list->load_st.st_mtime &&
		    ST_MTIME_NSEC(st) == ST_MTIME_NSEC(list->load_st) &&
		    st.st_ino == list->load_st.st_ino) {
			/* unchanged */
			return 0;
		}
	}
	array_clear(&list->recs);
	return mountpoint_list_load(list);
}

static int
mountpoint_list_save_to(struct mountpoint_list *list, const char *path)
{
	struct mountpoint_list_rec *const *recp;
	string_t *data, *temp_path = t_str_new(128);
	int fd;

	str_append(temp_path, path);
	str_append(temp_path, ".tmp.");
	fd = safe_mkstemp(temp_path, 0644, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(temp_path));
		return -1;
	}
	data = t_str_new(256);
	array_foreach(&list->recs, recp) {
		str_append(data, (*recp)->state);
		str_append_c(data, ' ');
		str_append(data, (*recp)->mount_path);
		if ((*recp)->wildcard)
			str_append_c(data, '*');
		str_append_c(data, '\n');
	}
	if (write_full(fd, str_data(data), str_len(data)) < 0) {
		i_error("write(%s) failed: %m", str_c(temp_path));
		i_close_fd(&fd);
	} else if (fdatasync(fd) < 0) {
		i_error("fdatasync(%s) failed: %m", str_c(temp_path));
		i_close_fd(&fd);
	} else if (close(fd) < 0) {
		i_error("close(%s) failed: %m", str_c(temp_path));
	} else if (rename(str_c(temp_path), path) < 0) {
		i_error("rename(%s, %s) failed: %m", str_c(temp_path), path);
	} else {
		return 0;
	}
	(void)unlink(str_c(temp_path));
	return -1;
}

int mountpoint_list_save(struct mountpoint_list *list)
{
	int ret;

	i_assert(list->perm_path != NULL);

	if (list->load_failed)
		return -1;

	ret = mountpoint_list_save_to(list, list->state_path);
	if (mountpoint_list_save_to(list, list->perm_path) < 0)
		ret = -1;
	return ret;
}

void mountpoint_list_add(struct mountpoint_list *list,
			 const struct mountpoint_list_rec *rec)
{
	struct mountpoint_list_rec *new_rec;

	new_rec = mountpoint_list_find(list, rec->mount_path);
	if (new_rec == NULL) {
		new_rec = p_new(list->pool, struct mountpoint_list_rec, 1);
		new_rec->mount_path = p_strdup(list->pool, rec->mount_path);
		array_append(&list->recs, &new_rec, 1);
	}
	new_rec->state = p_strdup(list->pool, rec->state);
	new_rec->wildcard = rec->wildcard;
	new_rec->mounted = rec->mounted;
}

bool mountpoint_list_remove(struct mountpoint_list *list,
			    const char *mount_path)
{
	struct mountpoint_list_rec *const *recs;
	unsigned int i, count;

	recs = array_get(&list->recs, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(recs[i]->mount_path, mount_path) == 0) {
			array_delete(&list->recs, i, 1);
			return TRUE;
		}
	}
	return FALSE;
}

static bool str_array_find_prefix(const char *const *prefixes, const char *str)
{
	if (prefixes == NULL)
		return FALSE;
	for (; *prefixes != NULL; prefixes++) {
		if (strncmp(*prefixes, str, strlen(*prefixes)) == 0)
			return TRUE;
	}
	return FALSE;
}

int mountpoint_list_add_missing(struct mountpoint_list *list,
				const char *default_state,
				const char *const *ignore_prefixes,
				const char *const *ignore_types)
{
	struct mountpoint_list_rec new_rec, *rec, *const *recp;
	struct mountpoint_iter *iter;
	const struct mountpoint *mnt;

	memset(&new_rec, 0, sizeof(new_rec));
	new_rec.state = default_state;
	new_rec.mounted = TRUE;

	array_foreach(&list->recs, recp)
		(*recp)->mounted = FALSE;

	/* get a sorted list of all current mountpoints */
	iter = mountpoint_iter_init();
	while ((mnt = mountpoint_iter_next(iter)) != NULL) {
		rec = mountpoint_list_find(list, mnt->mount_path);
		if (rec != NULL) {
			if (!rec->wildcard)
				rec->mounted = TRUE;
		} else if (!str_array_find(ignore_types, mnt->type) &&
			   !str_array_find_prefix(ignore_prefixes,
						  mnt->mount_path)) {
			new_rec.mount_path = mnt->mount_path;
			mountpoint_list_add(list, &new_rec);
		}
	}
	return mountpoint_iter_deinit(&iter);
}

int mountpoint_list_update_mounted(struct mountpoint_list *list)
{
	struct mountpoint_list_rec *rec, *const *recp;
	struct mountpoint_iter *iter;
	const struct mountpoint *mnt;

	array_foreach(&list->recs, recp)
		(*recp)->mounted = FALSE;

	iter = mountpoint_iter_init();
	while ((mnt = mountpoint_iter_next(iter)) != NULL) {
		rec = mountpoint_list_find(list, mnt->mount_path);
		if (rec != NULL && !rec->wildcard)
			rec->mounted = TRUE;
	}
	return mountpoint_iter_deinit(&iter);
}

struct mountpoint_list_rec *
mountpoint_list_find(struct mountpoint_list *list, const char *path)
{
	struct mountpoint_list_rec **recp;

	array_foreach_modifiable(&list->recs, recp) {
		const char *prefix = (*recp)->mount_path;
		unsigned int prefix_len = strlen(prefix);

		if (strncmp(prefix, path, prefix_len) == 0 &&
		    (path[prefix_len] == '/' || path[prefix_len] == '\0'))
			return *recp;
	}
	return NULL;
}

struct mountpoint_list_iter *
mountpoint_list_iter_init(struct mountpoint_list *list)
{
	struct mountpoint_list_iter *iter;

	iter = i_new(struct mountpoint_list_iter, 1);
	iter->list = list;
	return iter;
}

struct mountpoint_list_rec *
mountpoint_list_iter_next(struct mountpoint_list_iter *iter)
{
	struct mountpoint_list_rec *const *recp;

	if (iter->idx == array_count(&iter->list->recs))
		return NULL;

	recp = array_idx(&iter->list->recs, iter->idx++);
	return *recp;
}

void mountpoint_list_iter_deinit(struct mountpoint_list_iter **_iter)
{
	struct mountpoint_list_iter *iter = *_iter;

	*_iter = NULL;
	i_free(iter);
}
