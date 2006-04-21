/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "nfs-workarounds.h"
#include "file-dotlock.h"
#include "read-full.h"
#include "write-full.h"
#include "str.h"
#include "quota-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAILDIRSIZE_FILENAME "maildirsize"
#define MAILDIRSIZE_STALE_SECS (60*15)

struct maildir_quota_root {
	struct quota_root root;

	uint64_t message_bytes_limit;
	uint64_t message_count_limit;

	uint64_t total_bytes;
	uint64_t total_count;

	int fd;

	unsigned int master_message_limits:1;
};

struct maildir_list_context {
	struct mailbox_list_context *ctx;
	struct mailbox_list *list;

	string_t *path;
	int state;
};

extern struct quota_backend quota_backend_maildir;

const struct dotlock_settings dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 0,
	MEMBER(stale_timeout) 30,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

static int maildir_sum_dir(struct mail_storage *storage, const char *dir,
			   uint64_t *total_bytes, uint64_t *total_count)
{
	DIR *dirp;
	struct dirent *dp;
	string_t *path;
	const char *p;
	size_t len;
	uoff_t num;
	int ret = 0;

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno == ENOENT || errno == ESTALE)
			return 0;
		mail_storage_set_critical(storage, "opendir(%s) failed: %m",
					  dir);
		return -1;
	}

	path = t_str_new(256);
	str_append(path, dir);
	str_append_c(path, '/');

	len = str_len(path);
	while ((dp = readdir(dirp)) != NULL) {
		p = strstr(dp->d_name, ",S=");
		num = (uoff_t)-1;
		if (p != NULL) {
			/* ,S=nnnn[:,] */
			p += 3;
			for (num = 0; *p >= '0' && *p <= '9'; p++)
				num = num * 10 + (*p - '0');

			if (*p != ':' && *p != '\0' && *p != ',') {
				/* not in expected format, fallback to stat() */
				num = (uoff_t)-1;
			} else {
				*total_bytes += num;
				*total_count += 1;
			}
		}
		if (num == (uoff_t)-1) {
			struct stat st;

			str_truncate(path, len);
			str_append(path, dp->d_name);
			if (stat(str_c(path), &st) == 0) {
				*total_bytes += st.st_size;
				*total_count += 1;
			} else if (errno != ENOENT && errno != ESTALE) {
				mail_storage_set_critical(storage,
					"stat(%s) failed: %m", str_c(path));
				ret = -1;
			}
		}
	}

	if (closedir(dirp) < 0) {
		mail_storage_set_critical(storage, "closedir(%s) failed: %m",
					  dir);
		return -1;
	}
	return ret;
}

static struct maildir_list_context *
maildir_list_init(struct mail_storage *storage)
{
	struct maildir_list_context *ctx;

	ctx = i_new(struct maildir_list_context, 1);
	ctx->path = str_new(default_pool, 512);
	ctx->ctx = mail_storage_mailbox_list_init(storage, "", "*",
						  MAILBOX_LIST_FAST_FLAGS |
						  MAILBOX_LIST_INBOX);
	return ctx;
}

static const char *
maildir_list_next(struct maildir_list_context *ctx, time_t *mtime_r)
{
	struct stat st;
	const char *path;
	bool is_file;

	for (;;) {
		if (ctx->state == 0) {
			ctx->list = mail_storage_mailbox_list_next(ctx->ctx);
			if (ctx->list == NULL)
				return NULL;
		}

		t_push();
		path = mail_storage_get_mailbox_path(ctx->ctx->storage,
						     ctx->list->name,
						     &is_file);
		str_truncate(ctx->path, 0);
		str_append(ctx->path, path);
		str_append(ctx->path, ctx->state == 0 ? "/new" : "/cur");
		t_pop();

		if (++ctx->state == 2)
			ctx->state = 0;

		if (stat(str_c(ctx->path), &st) == 0)
			break;
		/* ignore if the directory got lost, stale or if it was
		   actually a file and not a directory */
		if (errno != ENOENT && errno != ESTALE && errno != ENOTDIR) {
			mail_storage_set_critical(ctx->ctx->storage,
				"stat(%s) failed: %m", str_c(ctx->path));
			ctx->state = 0;
		}
	}

	*mtime_r = st.st_size;
	return str_c(ctx->path);
}

static int maildir_list_deinit(struct maildir_list_context *ctx)
{
	int ret = mail_storage_mailbox_list_deinit(&ctx->ctx);

	str_free(&ctx->path);
	i_free(ctx);
	return ret;
}

static int
maildirs_check_have_changed(struct mail_storage *storage, time_t latest_mtime)
{
	struct maildir_list_context *ctx;
	const char *dir;
	time_t mtime;
	int ret = 0;

	ctx = maildir_list_init(storage);
	while ((dir = maildir_list_next(ctx, &mtime)) != NULL) {
		if (mtime > latest_mtime) {
			ret = 1;
			break;
		}
	}
	if (maildir_list_deinit(ctx) < 0)
		return -1;
	return ret;
}

static int maildirsize_write(struct maildir_quota_root *root,
			     struct mail_storage *storage, const char *path)
{
	struct dotlock *dotlock;
	string_t *str;
	int fd;

	fd = file_dotlock_open(&dotlock_settings, path,
			       DOTLOCK_CREATE_FLAG_NONBLOCK, &dotlock);
	if (fd == -1) {
		if (errno == EAGAIN) {
			/* someone's just in the middle of updating it */
			return -1;
		}

		mail_storage_set_critical(storage,
			"file_dotlock_open(%s) failed: %m", path);
		return -1;
	}

	str = t_str_new(128);
	if (root->message_bytes_limit != (uint64_t)-1) {
		str_printfa(str, "%lluS",
			    (unsigned long long)root->message_bytes_limit);
	}
	if (root->message_count_limit != (uint64_t)-1) {
		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_printfa(str, "%lluC",
			    (unsigned long long)root->message_count_limit);
	}
	str_printfa(str, "\n%llu %llu\n",
		    (unsigned long long)root->total_bytes,
		    (unsigned long long)root->total_count);
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		mail_storage_set_critical(storage,
			"write_full(%s) failed: %m", path);
		file_dotlock_delete(&dotlock);
		return -1;
	}

	if (file_dotlock_replace(&dotlock, 0) < 0) {
		mail_storage_set_critical(storage,
			"file_dotlock_replace(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static const char *maildirsize_get_path(struct mail_storage *storage)
{
	return t_strconcat(mail_storage_get_mailbox_control_dir(storage, ""),
			   "/"MAILDIRSIZE_FILENAME, NULL);
}

static int maildirsize_recalculate(struct maildir_quota_root *root,
				   struct mail_storage *storage)
{
	struct maildir_list_context *ctx;
	const char *dir, *path;
	time_t mtime, last_stamp = 0;
	int ret = 0;

	root->total_bytes = root->total_count = 0;

	ctx = maildir_list_init(storage);
	while ((dir = maildir_list_next(ctx, &mtime)) != NULL) {
		if (mtime > last_stamp)
			last_stamp = mtime;

		t_push();
		if (maildir_sum_dir(storage, dir,
				    &root->total_bytes,
				    &root->total_count) < 0)
			ret = -1;
		t_pop();
	}
	if (maildir_list_deinit(ctx) < 0)
		ret = -1;

	if (ret == 0)
		ret = maildirs_check_have_changed(storage, last_stamp);

	t_push();
	path = maildirsize_get_path(storage);
	if (ret == 0) {
		/* maildir didn't change, we can write the maildirsize file */
		ret = maildirsize_write(root, storage, path);
	}
	if (ret != 0) {
		/* make sure it gets rebuilt later */
		if (unlink(path) < 0 && errno != ENOENT && errno != ESTALE) {
			mail_storage_set_critical(storage,
				"unlink(%s) failed: %m", path);
		}
	}
	t_pop();

	return ret;
}

static int maildirsize_parse(struct maildir_quota_root *root,
			     int fd, const char *const *lines)
{
	unsigned long long bytes;
	uint64_t message_bytes_limit, message_count_limit;
	long long bytes_diff, total_bytes;
	int count_diff, total_count;
	unsigned int line_count = 0;
	const char *const *limit;
	char *pos;

	if (*lines == NULL)
		return -1;

	/* first line contains the limits. 0 value mean unlimited. */
	message_bytes_limit = (uint64_t)-1;
	message_count_limit = (uint64_t)-1;
	for (limit = t_strsplit(lines[0], ","); *limit != NULL; limit++) {
		bytes = strtoull(*limit, &pos, 10);
		if (pos[0] != '\0' && pos[1] == '\0') {
			switch (pos[0]) {
			case 'C':
				if (bytes != 0)
					message_count_limit = bytes;
				break;
			case 'S':
				if (bytes != 0)
					message_bytes_limit = bytes;
				break;
			}
		}
	}

	if (!root->master_message_limits) {
		/* we don't know the limits, use whatever the file says */
		root->message_bytes_limit = message_bytes_limit;
		root->message_count_limit = message_count_limit;
	} else if (root->message_bytes_limit != message_bytes_limit ||
		   root->message_count_limit != message_count_limit) {
		/* we know the limits and they've changed.
		   the file must be rewritten. */
		return 0;
	}

	/* rest of the lines contains <bytes> <count> diffs */
	total_bytes = 0; total_count = 0;
	for (lines++; **lines != '\0'; lines++, line_count++) {
		if (sscanf(*lines, "%lld %d", &bytes_diff, &count_diff) != 2)
			return -1;

		total_bytes += bytes_diff;
		total_count += count_diff;
	}
	/* we end always with LF, which shows up as empty last line. there
	   should be no other empty lines */
	if (lines[1] != NULL)
		return -1;

	if (total_bytes < 0 || total_count < 0) {
		/* corrupted */
		return -1;
	}

	if ((uint64_t)total_bytes > root->message_bytes_limit ||
	    (uint64_t)total_count > root->message_count_limit) {
		/* we're over quota. don't trust these values if the file
		   contains more than the initial summary line, or if the file
		   is older than 15 minutes. */
		struct stat st;

		if (line_count > 1)
			return 0;

		if (fstat(fd, &st) < 0 ||
		    st.st_mtime < ioloop_time - MAILDIRSIZE_STALE_SECS)
			return 0;
	}
	root->total_bytes = (uint64_t)total_bytes;
	root->total_count = (uint64_t)total_count;
	return 1;
}

static int maildirsize_read(struct maildir_quota_root *root,
			    struct mail_storage *storage)
{
	const char *path;
	char buf[5120+1];
	unsigned int size;
	int fd, ret;

	t_push();
	path = maildirsize_get_path(storage);
	if (root->fd != -1) {
		if (close(root->fd) < 0) {
			mail_storage_set_critical(storage,
				"close(%s) failed: %m", path);
		}
		root->fd = -1;
	}

	fd = nfs_safe_open(path, O_RDWR | O_APPEND);
	if (fd == -1) {
		if (errno == ENOENT)
			ret = 0;
		else {
			ret = -1;
			mail_storage_set_critical(storage,
				"open(%s) failed: %m", path);
		}
		t_pop();
		return ret;
	}

	size = 0;
	while ((ret = read(fd, buf, sizeof(buf)-1)) != 0) {
		if (ret < 0) {
			if (errno == ESTALE)
				break;
			mail_storage_set_critical(storage, "read(%s) failed: %m",
						  path);
		}
		size += ret;
	}
	if (ret < 0 || size == sizeof(buf)-1) {
		/* error / recalculation needed. */
		(void)close(fd);
		t_pop();
		return ret < 0 ? -1 : 0;
	}

	/* file is smaller than 5120 bytes, which means we can use it */
	root->total_bytes = root->total_count = 0;

	/* skip the last line if there's no LF at the end */
	while (size > 0 && buf[size-1] != '\n') size--;
	buf[size] = '\0';

	if (maildirsize_parse(root, fd, t_strsplit(buf, "\n")) > 0) {
		root->fd = fd;
		ret = 1;
	} else {
		/* broken file / need recalculation */
		(void)close(root->fd);
		root->fd = -1;
		ret = 0;
	}
	t_pop();
	return ret;
}

static int maildirquota_refresh(struct maildir_quota_root *root,
				struct mail_storage *storage)
{
	int ret;

	ret = maildirsize_read(root, storage);
	if (ret == 0) {
		if (root->message_bytes_limit == (uint64_t)-1 &&
		    root->message_count_limit == (uint64_t)-1) {
			/* no quota */
			return 0;
		}

		ret = maildirsize_recalculate(root, storage);
	}
	return ret < 0 ? -1 : 0;
}

static int maildirsize_update(struct maildir_quota_root *root,
			      struct mail_storage *storage,
			      int count_diff, int64_t bytes_diff)
{
	const char *str;
	int ret = 0;

	if (count_diff == 0 && bytes_diff == 0)
		return 0;

	t_push();

	/* We rely on O_APPEND working in here. That isn't NFS-safe, but it
	   isn't necessarily that bad because the file is recreated once in
	   a while, and sooner if corruption cases calculations to go
	   over quota. This is also how Maildir++ spec specifies it should be
	   done.. */
	str = t_strdup_printf("%lld %d\n", (long long)bytes_diff, count_diff);
	if (write_full(root->fd, str, strlen(str)) < 0) {
		ret = -1;
		if (errno == ESTALE) {
			/* deleted/replaced already, ignore */
		} else {
			mail_storage_set_critical(storage,
				"write_full(%s) failed: %m",
				maildirsize_get_path(storage));
		}
	}
	t_pop();
	return ret;
}

static struct quota_root *
maildir_quota_init(struct quota_setup *setup, const char *name __attr_unused__)
{
	struct maildir_quota_root *root;
	const char *const *args;

	root = i_new(struct maildir_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_maildir.v;
	root->fd = -1;
	root->message_bytes_limit = (uint64_t)-1;
	root->message_count_limit = (uint64_t)-1;

	t_push();
	args = t_strsplit(setup->data, ":");

	for (; *args != '\0'; args++) {
		if (strncmp(*args, "storage=", 8) == 0) {
			root->message_bytes_limit =
				strtoull(*args + 8, NULL, 10) * 1024;
			root->master_message_limits = TRUE;
		} else if (strncmp(*args, "messages=", 9) == 0) {
			root->message_count_limit =
				strtoull(*args + 9, NULL, 10);
			root->master_message_limits = TRUE;
		}
	}
	t_pop();

	return &root->root;
}

static void maildir_quota_deinit(struct quota_root *_root)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	i_free(root->root.name);
	i_free(root);
}

static bool
maildir_quota_add_storage(struct quota_root *root __attr_unused__,
			  struct mail_storage *storage __attr_unused__)
{
	return TRUE;
}

static void
maildir_quota_remove_storage(struct quota_root *root __attr_unused__,
			     struct mail_storage *storage __attr_unused__)
{
}

static const char *const *
maildir_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources_both[] = {
		QUOTA_NAME_STORAGE,
		QUOTA_NAME_MESSAGES,
		NULL
	};

	return resources_both;
}

static struct mail_storage *
maildir_quota_root_get_storage(struct quota_root *root)
{
	/* FIXME: figure out how to support multiple storages */
	struct mail_storage *const *storages;
	unsigned int count;

	storages = array_get(&root->storages, &count);
	i_assert(count > 0);

	return storages[0];
}

static int
maildir_quota_get_resource(struct quota_root *_root, const char *name,
			   uint64_t *value_r, uint64_t *limit_r)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;

	if (maildirquota_refresh(root,
				 maildir_quota_root_get_storage(_root)) < 0)
		return -1;

	if (root->message_bytes_limit == (uint64_t)-1 &&
	    root->message_count_limit == (uint64_t)-1)
		return 0;

	if (strcmp(name, QUOTA_NAME_STORAGE) == 0) {
		*limit_r = root->message_bytes_limit / 1024;
		*value_r = root->total_bytes / 1024;
	} else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0) {
		*limit_r = root->message_count_limit;
		*value_r = root->total_count;
	} else {
		return 0;
	}
	return 1;
}

static int
maildir_quota_set_resource(struct quota_root *root,
			   const char *name __attr_unused__,
			   uint64_t value __attr_unused__)
{
	quota_set_error(root->setup->quota, MAIL_STORAGE_ERR_NO_PERMISSION);
	return -1;
}

static struct quota_root_transaction_context *
maildir_quota_transaction_begin(struct quota_root *_root,
				struct quota_transaction_context *_ctx)
{
	struct maildir_quota_root *root = (struct maildir_quota_root *)_root;
	struct quota_root_transaction_context *ctx;

	ctx = i_new(struct quota_root_transaction_context, 1);
	ctx->root = _root;
	ctx->ctx = _ctx;

	if (maildirquota_refresh(root,
				 maildir_quota_root_get_storage(_root)) < 0) {
		/* failed calculating the current quota */
		ctx->bytes_current = (uint64_t)-1;
	} else {
		ctx->bytes_limit = root->message_bytes_limit;
		ctx->count_limit = root->message_count_limit;
		ctx->bytes_current = root->total_bytes;
		ctx->count_current = root->total_count;
	}
	return ctx;
}

static int
maildir_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	struct maildir_quota_root *root =
		(struct maildir_quota_root *)ctx->root;
	int ret = ctx->bytes_current == (uint64_t)-1 ? -1 : 0;

	if (root->fd != -1 && ret == 0) {
		/* if writing fails, we don't care all that much */
		(void)maildirsize_update(root,
				maildir_quota_root_get_storage(ctx->root),
				ctx->count_diff, ctx->bytes_diff);
	}
	i_free(ctx);
	return ret;
}

struct quota_backend quota_backend_maildir = {
	"maildir",

	{
		maildir_quota_init,
		maildir_quota_deinit,

		maildir_quota_add_storage,
		maildir_quota_remove_storage,

		maildir_quota_root_get_resources,

		maildir_quota_get_resource,
		maildir_quota_set_resource,

		maildir_quota_transaction_begin,
		maildir_quota_transaction_commit,
		quota_default_transaction_rollback,

		quota_default_try_alloc,
		quota_default_try_alloc_bytes,
		quota_default_alloc,
		quota_default_free
	}
};
