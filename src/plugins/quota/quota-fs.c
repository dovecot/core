/* Copyright (C) 2005-2006 Timo Sirainen */

/* Only for reporting filesystem quota */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "quota-private.h"
#include "quota-fs.h"

#ifdef HAVE_FS_QUOTA

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
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

struct fs_quota_mountpoint {
	char *mount_path;
	char *device_path;

	unsigned int blk_size;

#ifdef HAVE_Q_QUOTACTL
	int fd;
	char *path;
#endif
};

struct fs_quota_root {
	struct quota_root root;

	uid_t uid;
	struct fs_quota_mountpoint *mount;
};

struct fs_quota_root_iter {
	struct quota_root_iter iter;

	bool sent;
};

extern struct quota_backend quota_backend_fs;

static struct quota_root *
fs_quota_init(struct quota_setup *setup __attr_unused__, const char *name)
{
	struct fs_quota_root *root;

	root = i_new(struct fs_quota_root, 1);
	root->root.name = i_strdup(name);
	root->root.v = quota_backend_fs.v;
	root->uid = geteuid();

	return &root->root;
}

static void fs_quota_mountpoint_free(struct fs_quota_mountpoint *mount)
{
#ifdef HAVE_Q_QUOTACTL
	if (mount->fd != -1) {
		if (close(mount->fd) < 0)
			i_error("close(%s) failed: %m", mount->path);
	}
	i_free(mount->path);
#endif

	i_free(mount->device_path);
	i_free(mount->mount_path);
	i_free(mount);
}

static void fs_quota_deinit(struct quota_root *_root)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;

	if (root->mount != NULL)
		fs_quota_mountpoint_free(root->mount);
	i_free(root->root.name);
	i_free(root);
}

static struct fs_quota_mountpoint *fs_quota_mountpoint_get(const char *dir)
{
	struct fs_quota_mountpoint *mount;
#ifdef HAVE_STATFS_MNTFROMNAME
	struct statfs buf;

	if (statfs(dir, &buf) < 0) {
		i_error("statfs(%s) failed: %m", dir);
		return NULL;
	}

	mount = i_new(struct fs_quota_mountpoint, 1);
	mount->blk_size = buf.f_bsize;
	mount->device_path = i_strdup(buf.f_mntfromname);
	mount->mount_path = i_strdup(buf.f_mntonname);
	return mount;
#else
#ifdef HAVE_SYS_MNTTAB_H
	struct mnttab ent;
#else
	struct mntent *ent;
#endif
	struct stat st, st2;
	const char *device_path = NULL, *mount_path = NULL;
	unsigned int blk_size;
	FILE *f;

	if (stat(dir, &st) < 0) {
		i_error("stat(%s) failed: %m", dir);
		return NULL;
	}
	blk_size = st.st_blksize;

#ifdef HAVE_SYS_MNTTAB_H
	f = fopen(MTAB_PATH, "r");
	if (f == NULL) {
		i_error("open(%s) failed: %m", MTAB_PATH);
		return NULL;
	}
	while ((getmntent(f, &ent)) == 0) {
		if (strcmp(ent.mnt_fstype, MNTTYPE_SWAP) == 0 ||
		    strcmp(ent.mnt_fstype, MNTTYPE_IGNORE) == 0)
			continue;

		if (stat(ent.mnt_special, &st2) == 0 &&
		    CMP_DEV_T(st.st_dev, st2.st_dev)) {
			device_path = ent.mnt_special;
			mount_path = ent.mnt_mountp;
			break;
		}
	}
	fclose(f);
#else
	f = setmntent(MTAB_PATH, "r");
	if (f == NULL) {
		i_error("setmntent(%s) failed: %m", MTAB_PATH);
		return NULL;
	}
	while ((ent = getmntent(f)) != NULL) {
		if (strcmp(ent->mnt_type, MNTTYPE_SWAP) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_IGNORE) == 0)
			continue;

		if (stat(ent->mnt_fsname, &st2) == 0 &&
		    CMP_DEV_T(st.st_dev, st2.st_dev)) {
			device_path = ent->mnt_fsname;
			mount_path = ent->mnt_dir;
			break;
		}
	}
	endmntent(f);
#endif
	if (device_path == NULL) {
		if (getenv("DEBUG") != NULL) {
			i_info("fs quota: mount path for %s not found from %s",
			       dir, MTAB_PATH);
		}
		return NULL;
	}

	mount = i_new(struct fs_quota_mountpoint, 1);
	mount->blk_size = blk_size;
	mount->device_path = i_strdup(device_path);
	mount->mount_path = i_strdup(mount_path);

	return mount;
#endif
}

static bool fs_quota_add_storage(struct quota_root *_root,
				 struct mail_storage *storage)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	struct fs_quota_mountpoint *mount;
	const char *dir;
	bool is_file;

	dir = mail_storage_get_mailbox_path(storage, "", &is_file);

	if (getenv("DEBUG") != NULL)
		i_info("fs quota add storage dir = %s", dir);

	mount = fs_quota_mountpoint_get(dir);
	if (root->mount == NULL) {
		if (mount == NULL) {
			/* Not found */
			return TRUE;
		}
		root->mount = mount;
	} else {
		bool match = strcmp(root->mount->mount_path,
				    mount->mount_path) == 0;

		fs_quota_mountpoint_free(mount);
		if (!match) {
			/* different mountpoints, can't use this */
			return FALSE;
		}
		mount = root->mount;
	}

	if (getenv("DEBUG") != NULL) {
		i_info("fs quota block device = %s", mount->device_path);
		i_info("fs quota mount point = %s", mount->mount_path);
	}

#ifdef HAVE_Q_QUOTACTL
	if (mount->path == NULL) {
		mount->path = i_strconcat(mount->mount_path, "/quotas", NULL);
		mount->fd = open(mount->path, O_RDONLY);
		if (mount->fd == -1 && errno != ENOENT)
			i_error("open(%s) failed: %m", mount->path);
	}
#endif
	return TRUE;
}

static void
fs_quota_remove_storage(struct quota_root *root __attr_unused__,
			struct mail_storage *storage __attr_unused__)
{
}

static const char *const *
fs_quota_root_get_resources(struct quota_root *root __attr_unused__)
{
	static const char *resources[] = { QUOTA_NAME_STORAGE, NULL };

	return resources;
}

static int
fs_quota_get_resource(struct quota_root *_root, const char *name,
		      uint64_t *value_r, uint64_t *limit_r)
{
	struct fs_quota_root *root = (struct fs_quota_root *)_root;
	struct dqblk dqblk;
#ifdef HAVE_Q_QUOTACTL
	struct quotctl ctl;
#endif

	*value_r = 0;
	*limit_r = 0;

	if (strcasecmp(name, QUOTA_NAME_STORAGE) != 0 || root->mount == NULL)
		return 0;

#ifdef HAVE_QUOTACTL
	if (quotactl(QCMD(Q_GETQUOTA, USRQUOTA), root->mount->device_path,
		     root->uid, (void *)&dqblk) < 0) {
		i_error("quotactl(Q_GETQUOTA, %s) failed: %m",
			root->mount->device_path);
		quota_set_error(_root->setup->quota, "Internal quota error");
		return -1;
	}
#else
	/* Solaris */
	if (root->mount->fd == -1)
		return 0;

	ctl.op = Q_GETQUOTA;
	ctl.uid = root->uid;
	ctl.addr = (caddr_t)&dqblk;
	if (ioctl(root->mount->fd, Q_QUOTACTL, &ctl) < 0) {
		i_error("ioctl(%s, Q_QUOTACTL) failed: %m", root->mount->path);
		quota_set_error(_root->setup->quota, "Internal quota error");
		return -1;
	}
#endif
	*value_r = dqblk.dqb_curblocks * root->mount->blk_size / 1024;
	*limit_r = dqblk.dqb_bsoftlimit * root->mount->blk_size / 1024;
	return 1;
}

static int
fs_quota_set_resource(struct quota_root *root,
		      const char *name __attr_unused__,
		      uint64_t value __attr_unused__)
{
	quota_set_error(root->setup->quota, MAIL_STORAGE_ERR_NO_PERMISSION);
	return -1;
}

static struct quota_root_transaction_context *
fs_quota_transaction_begin(struct quota_root *root,
			   struct quota_transaction_context *ctx)
{
	struct quota_root_transaction_context *root_ctx;

	root_ctx = i_new(struct quota_root_transaction_context, 1);
	root_ctx->root = root;
	root_ctx->ctx = ctx;
	return root_ctx;
}

static int
fs_quota_transaction_commit(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
	return 0;
}

static void
fs_quota_transaction_rollback(struct quota_root_transaction_context *ctx)
{
	i_free(ctx);
}

static int
fs_quota_try_alloc(struct quota_root_transaction_context *ctx __attr_unused__,
		   struct mail *mail __attr_unused__,
		   bool *too_large_r __attr_unused__)
{
	/* no-op */
	return 1;
}

static int
fs_quota_try_alloc_bytes(struct quota_root_transaction_context *ctx
			 	__attr_unused__,
			 uoff_t size __attr_unused__,
			 bool *too_large_r __attr_unused__)
{
	/* no-op */
	return 1;
}

static void
fs_quota_alloc(struct quota_root_transaction_context *ctx __attr_unused__,
	       struct mail *mail __attr_unused__)
{
	/* no-op */
}

static void
fs_quota_free(struct quota_root_transaction_context *ctx __attr_unused__,
	      struct mail *mail __attr_unused__)
{
	/* no-op */
}

struct quota_backend quota_backend_fs = {
	"fs",

	{
		fs_quota_init,
		fs_quota_deinit,

		fs_quota_add_storage,
		fs_quota_remove_storage,

		fs_quota_root_get_resources,

		fs_quota_get_resource,
		fs_quota_set_resource,

		fs_quota_transaction_begin,
		fs_quota_transaction_commit,
		fs_quota_transaction_rollback,

		fs_quota_try_alloc,
		fs_quota_try_alloc_bytes,
		fs_quota_alloc,
		fs_quota_free
	}
};

#endif
