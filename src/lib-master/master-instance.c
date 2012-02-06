/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "file-dotlock.h"
#include "str.h"
#include "strescape.h"
#include "master-instance.h"

#include <unistd.h>
#include <fcntl.h>

struct master_instance_list {
	pool_t pool;
	const char *path;

	ARRAY_DEFINE(instances, struct master_instance);
};

struct master_instance_list_iter {
	struct master_instance_list *list;
	unsigned int idx;
};

static const struct dotlock_settings dotlock_set = {
	.timeout = 1,
	.stale_timeout = 60
};

struct master_instance_list *master_instance_list_init(const char *path)
{
	struct master_instance_list *list;
	pool_t pool;

	pool = pool_alloconly_create("master instances", 256);
	list = p_new(pool, struct master_instance_list, 1);
	list->pool = pool;
	list->path = p_strdup(pool, path);
	p_array_init(&list->instances, pool, 8);
	return list;
}

void master_instance_list_deinit(struct master_instance_list **_list)
{
	struct master_instance_list *list = *_list;

	*_list = NULL;
	pool_unref(&list->pool);
}

static void master_instance_list_drop_stale(struct master_instance_list *list)
{
	const struct master_instance *instances;
	unsigned int i, count;
	time_t stale_timestamp = time(NULL) - MASTER_INSTANCE_AUTO_STALE_SECS;

	instances = array_get(&list->instances, &count);
	for (i = 0; i < count; ) {
		if (instances[i].name[0] == '\0' &&
		    instances[i].last_used < stale_timestamp) {
			array_delete(&list->instances, i, 1);
			instances = array_get(&list->instances, &count);
		} else {
			i++;
		}
	}
}

static int
master_instance_list_add_line(struct master_instance_list *list,
			      const char *line)
{
	struct master_instance *inst;
	const char *const *args;
	time_t last_used;

	/* <last used> <name> <base dir> */
	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 3)
		return -1;
	if (str_to_time(args[0], &last_used) < 0)
		return -1;

	inst = array_append_space(&list->instances);
	inst->last_used = last_used;
	inst->name = p_strdup(list->pool, args[1]);
	inst->base_dir = p_strdup(list->pool, args[2]);
	return 0;
}

static int master_instance_list_refresh(struct master_instance_list *list)
{
	struct istream *input;
	const char *line;
	int fd, ret = 0;

	array_clear(&list->instances);

	fd = open(list->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;

		i_error("open(%s) failed: %m", list->path);
		return -1;
	}
	input = i_stream_create_fd(fd, PATH_MAX, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		if (master_instance_list_add_line(list, line) < 0)
			i_error("Invalid line in %s: %s", list->path, line);
	} T_END;
	if (input->stream_errno != 0) {
		i_error("read(%s) failed: %m", line);
		ret = -1;
	}
	i_stream_destroy(&input);
	return ret;
}

static int
master_instance_list_write(struct master_instance_list *list,
			   int fd, const char *path)
{
	struct ostream *output;
	const struct master_instance *inst;
	string_t *str = t_str_new(128);

	output = o_stream_create_fd(fd, 0, FALSE);
	o_stream_cork(output);
	array_foreach(&list->instances, inst) {
		str_truncate(str, 0);
		str_printfa(str, "%ld\t", (long)inst->last_used);
		str_tabescape_write(str, inst->name);
		str_append_c(str, '\t');
		str_tabescape_write(str, inst->base_dir);
		str_append_c(str, '\n');
		(void)o_stream_send(output, str_data(str), str_len(str));
	}
	o_stream_uncork(output);
	(void)o_stream_flush(output);
	if (output->last_failed_errno != 0) {
		errno = output->last_failed_errno;
		i_error("write(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int master_instance_write_init(struct master_instance_list *list,
				      struct dotlock **dotlock_r)
{
	int fd;

	*dotlock_r = NULL;

	fd = file_dotlock_open_mode(&dotlock_set, list->path, 0, 0644,
				    (uid_t)-1, (gid_t)-1, dotlock_r);
	if (fd == -1) {
		i_error("file_dotlock_open(%s) failed: %m", list->path);
		return -1;
	}
	if (master_instance_list_refresh(list) < 0) {
		(void)file_dotlock_delete(dotlock_r);
		return -1;
	}
	return fd;
}

static int master_instance_write_finish(struct master_instance_list *list,
					int fd, struct dotlock **dotlock)
{
	const char *lock_path = file_dotlock_get_lock_path(*dotlock);
	int ret;

	master_instance_list_drop_stale(list);

	T_BEGIN {
		ret = master_instance_list_write(list, fd, lock_path);
	} T_END;
	if (ret < 0) {
		(void)file_dotlock_delete(dotlock);
		return -1;
	}
	if (fdatasync(fd) < 0) {
		i_error("fdatasync(%s) failed: %m", lock_path);
		(void)file_dotlock_delete(dotlock);
		return -1;
	}
	return file_dotlock_replace(dotlock, 0);
}

static struct master_instance *
master_instance_find(struct master_instance_list *list,
		     const char *base_dir)
{
	struct master_instance *inst;

	array_foreach_modifiable(&list->instances, inst) {
		if (strcmp(inst->base_dir, base_dir) == 0)
			return inst;
	}
	return NULL;
}

int master_instance_list_update(struct master_instance_list *list,
				const char *base_dir)
{
	struct master_instance *inst;
	struct dotlock *dotlock;
	int fd;

	if ((fd = master_instance_write_init(list, &dotlock)) == -1)
		return -1;

	inst = master_instance_find(list, base_dir);
	if (inst == NULL) {
		inst = array_append_space(&list->instances);
		inst->name = "";
		inst->base_dir = p_strdup(list->pool, base_dir);
	}
	inst->last_used = time(NULL);

	return master_instance_write_finish(list, fd, &dotlock);
}

int master_instance_list_set_name(struct master_instance_list *list,
				  const char *base_dir, const char *name)
{
	const struct master_instance *orig_inst;
	struct master_instance *inst;
	struct dotlock *dotlock;
	int fd;

	i_assert(*name != '\0');

	if ((fd = master_instance_write_init(list, &dotlock)) == -1)
		return -1;

	orig_inst = master_instance_list_find_by_name(list, name);
	if (orig_inst != NULL &&
	    strcmp(orig_inst->base_dir, base_dir) != 0) {
		/* name already used */
		(void)file_dotlock_delete(&dotlock);
		return 0;
	}

	inst = master_instance_find(list, base_dir);
	if (inst == NULL) {
		inst = array_append_space(&list->instances);
		inst->base_dir = p_strdup(list->pool, base_dir);
	}
	inst->name = p_strdup(list->pool, name);
	inst->last_used = time(NULL);

	return master_instance_write_finish(list, fd, &dotlock) < 0 ? -1 : 1;
}

int master_instance_list_remove(struct master_instance_list *list,
				const char *base_dir)
{
	struct dotlock *dotlock;
	const struct master_instance *instances;
	unsigned int i, count;
	int fd;

	if ((fd = master_instance_write_init(list, &dotlock)) == -1)
		return -1;

	instances = array_get(&list->instances, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(instances[i].base_dir, base_dir) == 0) {
			array_delete(&list->instances, i, 1);
			break;
		}
	}

	if (i == count) {
		(void)file_dotlock_delete(&dotlock);
		return 0;
	}
	return master_instance_write_finish(list, fd, &dotlock) < 0 ? -1 : 1;
}

const struct master_instance *
master_instance_list_find_by_name(struct master_instance_list *list,
				  const char *name)
{
	const struct master_instance *inst;

	i_assert(*name != '\0');

	if (array_count(&list->instances) == 0)
		(void)master_instance_list_refresh(list);

	array_foreach(&list->instances, inst) {
		if (strcmp(inst->name, name) == 0)
			return inst;
	}
	return NULL;
}

struct master_instance_list_iter *
master_instance_list_iterate_init(struct master_instance_list *list)
{
	struct master_instance_list_iter *iter;

	iter = i_new(struct master_instance_list_iter, 1);
	iter->list = list;
	(void)master_instance_list_refresh(list);
	master_instance_list_drop_stale(list);
	return iter;
}

const struct master_instance *
master_instance_iterate_list_next(struct master_instance_list_iter *iter)
{
	if (iter->idx == array_count(&iter->list->instances))
		return NULL;
	return array_idx(&iter->list->instances, iter->idx++);
}

void master_instance_iterate_list_deinit(struct master_instance_list_iter **_iter)
{
	struct master_instance_list_iter *iter = *_iter;

	*_iter = NULL;

	i_free(iter);
}
