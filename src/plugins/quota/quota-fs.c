/* Copyright (C) 2005 Timo Sirainen */

/* Only for reporting filesystem quota */

#include "lib.h"
#include "str.h"
#include "quota-private.h"
#include "quota-fs.h"

#ifdef HAVE_FS_QUOTA

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef HAVE_STRUCT_DQBLK_CURSPACE
#  define dqb_curblocks dqb_curspace
#endif

#define MTAB_PATH "/etc/mtab"

/* AIX doesn't have these defined */
#ifndef MNTTYPE_SWAP
#  define MNTTYPE_SWAP "swap"
#endif
#ifndef MNTTYPE_IGNORE
#  define MNTTYPE_IGNORE "ignore"
#endif

struct fs_quota {
	struct quota quota;

	pool_t pool;
	const char *device;
	const char *error;

	unsigned int blk_size;
	uid_t uid;

	struct quota_root root;
};

struct fs_quota_root_iter {
	struct quota_root_iter iter;

	bool sent;
};

extern struct quota fs_quota;

static const char *path_to_device(const char *path, unsigned int *blk_size_r)
{
#ifdef HAVE_STATFS_MNTFROMNAME
	struct statfs buf;

	if (statfs(path, &buf) < 0) {
		i_error("statfs(%s) failed: %m", path);
		return NULL;
	}

	*blk_size_r = buf.f_bsize;
	return t_strdup(buf.f_mntfromname);
#else
	struct mntent *ent;
	struct stat st, st2;
	const char *dev = NULL;
	FILE *f;

	if (stat(path, &st) < 0) {
		i_error("stat(%s) failed: %m", path);
		return NULL;
	}
	*blk_size_r = st.st_blksize;

	f = fopen(MTAB_PATH, "r");
	if (f == NULL) {
		i_error("open(%s) failed: %m", MTAB_PATH);
		return NULL;
	}
	while ((ent = getmntent(f)) != NULL) {
		if (strcmp(ent->mnt_type, MNTTYPE_SWAP) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_IGNORE) == 0)
			continue;

		if (stat(ent->mnt_fsname, &st2) == 0 &&
		    CMP_DEV_T(st.st_dev, st2.st_dev)) {
			dev = t_strdup(ent->mnt_fsname);
			break;
		}
	}
	endmntent(f);
	return dev;
#endif
}

static struct quota *fs_quota_init(const char *data)
{
	struct fs_quota *quota;
	const char *device;
	pool_t pool;
	unsigned int blk_size = 0;

	device = path_to_device(data, &blk_size);

	if (getenv("DEBUG") != NULL) {
		i_info("fs quota path = %s", data);
		i_info("fs quota block device = %s",
		       device == NULL ? "(unknown)" : device);
	}

	if (device == NULL)
		return NULL;

	pool = pool_alloconly_create("quota", 1024);
	quota = p_new(pool, struct fs_quota, 1);
	quota->pool = pool;
	quota->quota = fs_quota;
	quota->device = p_strdup(pool, device);
	quota->uid = geteuid();
	quota->blk_size = blk_size;

	quota->root.quota = &quota->quota;
	return &quota->quota;
}

static void fs_quota_deinit(struct quota *_quota)
{
	struct fs_quota *quota = (struct fs_quota *)_quota;

	pool_unref(quota->pool);
}

static struct quota_root_iter *
fs_quota_root_iter_init(struct quota *quota,
			struct mailbox *box __attr_unused__)
{
	struct fs_quota_root_iter *iter;

	iter = i_new(struct fs_quota_root_iter, 1);
	iter->iter.quota = quota;
	return &iter->iter;
}

static struct quota_root *
fs_quota_root_iter_next(struct quota_root_iter *_iter)
{
	struct fs_quota_root_iter *iter =
		(struct fs_quota_root_iter *)_iter;
	struct fs_quota *quota = (struct fs_quota *)_iter->quota;

	if (iter->sent)
		return NULL;

	iter->sent = TRUE;
	return &quota->root;
}

static int fs_quota_root_iter_deinit(struct quota_root_iter *iter)
{
	i_free(iter);
	return 0;
}

static struct quota_root *
fs_quota_root_lookup(struct quota *_quota, const char *name)
{
	struct fs_quota *quota = (struct fs_quota *)_quota;

	if (*name == '\0')
		return &quota->root;
	else
		return NULL;
}

static const char *
fs_quota_root_get_name(struct quota_root *root __attr_unused__)
{
	return "";
}

static const char *const *
fs_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static int
fs_quota_root_create(struct quota *_quota,
		     const char *name __attr_unused__,
		     struct quota_root **root_r __attr_unused__)
{
	struct fs_quota *quota = (struct fs_quota *)_quota;

        quota->error = "Permission denied";
	return -1;
}

static int
fs_quota_get_resource(struct quota_root *root, const char *name,
		      uint64_t *value_r, uint64_t *limit_r)
{
	struct fs_quota *quota = (struct fs_quota *)root->quota;
	struct dqblk dqblk;

	*value_r = 0;
	*limit_r = 0;

	if (strcasecmp(name, QUOTA_NAME_STORAGE) != 0)
		return 0;

	if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), quota->device,
		     quota->uid, (void *)&dqblk) < 0) {
		i_error("quotactl(Q_GETQUOTA, %s) failed: %m", quota->device);
		quota->error = "Internal quota error";
		return -1;
	}
	*value_r =  dqblk.dqb_curblocks * quota->blk_size / 1024;
	*limit_r = dqblk.dqb_bsoftlimit * quota->blk_size / 1024;
	return 1;
}

static int
fs_quota_set_resource(struct quota_root *root,
		      const char *name __attr_unused__,
		      uint64_t value __attr_unused__)
{
	struct fs_quota *quota = (struct fs_quota *)root->quota;

	quota->error = "Permission denied";
	return -1;
}

static struct quota_transaction_context *
fs_quota_transaction_begin(struct quota *quota)
{
	struct quota_transaction_context *ctx;

	ctx = i_new(struct quota_transaction_context, 1);
	ctx->quota = quota;
	return ctx;
}

static int
fs_quota_transaction_commit(struct quota_transaction_context *ctx)
{
	i_free(ctx);
	return 0;
}

static void
fs_quota_transaction_rollback(struct quota_transaction_context *ctx)
{
	i_free(ctx);
}

static int
fs_quota_try_alloc(struct quota_transaction_context *ctx __attr_unused__,
		   struct mail *mail __attr_unused__,
		   bool *too_large_r __attr_unused__)
{
	/* no-op */
	return 1;
}

static int
fs_quota_try_alloc_bytes(struct quota_transaction_context *ctx __attr_unused__,
			 uoff_t size __attr_unused__,
			 bool *too_large_r __attr_unused__)
{
	/* no-op */
	return 1;
}

static void
fs_quota_alloc(struct quota_transaction_context *ctx __attr_unused__,
		struct mail *mail __attr_unused__)
{
	/* no-op */
}

static void
fs_quota_free(struct quota_transaction_context *ctx __attr_unused__,
	      struct mail *mail __attr_unused__)
{
	/* no-op */
}

static const char *fs_quota_last_error(struct quota *_quota)
{
	struct fs_quota *quota = (struct fs_quota *)_quota;

	return quota->error;
}

struct quota fs_quota = {
	"fs",

	fs_quota_init,
	fs_quota_deinit,

	fs_quota_root_iter_init,
	fs_quota_root_iter_next,
	fs_quota_root_iter_deinit,

	fs_quota_root_lookup,

	fs_quota_root_get_name,
	fs_quota_root_get_resources,

	fs_quota_root_create,
	fs_quota_get_resource,
	fs_quota_set_resource,

	fs_quota_transaction_begin,
	fs_quota_transaction_commit,
	fs_quota_transaction_rollback,

	fs_quota_try_alloc,
	fs_quota_try_alloc_bytes,
	fs_quota_alloc,
	fs_quota_free,

	fs_quota_last_error,

	ARRAY_INIT
};

#endif
