/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mountpoint.h"

#include <sys/stat.h>

#ifdef HAVE_SYS_VMOUNT_H
#  include <stdio.h>
#  include <sys/vmount.h> /* AIX */
#  define MOUNTPOINT_AIX_MNTCTL
#elif defined(HAVE_STATVFS_MNTFROMNAME)
#  include <sys/statvfs.h> /* NetBSD 3.0+, FreeBSD 5.0+ */
#  define STATVFS_STR "statvfs"
#  define MOUNTPOINT_STATVFS
#elif defined(HAVE_STATFS_MNTFROMNAME)
#  include <sys/param.h> /* Older BSDs */
#  include <sys/mount.h>
#  define statvfs statfs
#  define STATVFS_STR "statfs"
#  define MOUNTPOINT_STATVFS
#elif defined(HAVE_MNTENT_H)
#  include <stdio.h>
#  include <mntent.h> /* Linux */
#  define MOUNTPOINT_LINUX
#elif defined(HAVE_SYS_MNTTAB_H)
#  include <stdio.h>
#  include <sys/mnttab.h> /* Solaris */
#  include <sys/mntent.h>
#  define MOUNTPOINT_SOLARIS
#else
#  define MOUNTPOINT_UNKNOWN
#endif

#ifdef MOUNTPOINT_SOLARIS
#  define MTAB_PATH MNTTAB /* Solaris */
#else
#  define MTAB_PATH "/etc/mtab" /* Linux */
#endif

/* AIX doesn't have these defined */
#ifndef MNTTYPE_SWAP
#  define MNTTYPE_SWAP "swap"
#endif
#ifndef MNTTYPE_IGNORE
#  define MNTTYPE_IGNORE "ignore"
#endif
#ifndef MNTTYPE_JFS
#  define MNTTYPE_JFS "jfs"
#endif
#ifndef MNTTYPE_NFS
#  define MNTTYPE_NFS "nfs"
#endif

/* Linux sometimes has mtab entry for "rootfs" as well as the real root
   entry. Skip the rootfs. */
#ifndef MNTTYPE_ROOTFS
#  define MNTTYPE_ROOTFS "rootfs"
#endif

#ifdef MOUNTPOINT_STATVFS
static int
mountpoint_get_statvfs(const char *path, pool_t pool,
                       struct mountpoint *point_r)
{
	struct statvfs buf;

	memset(point_r, 0, sizeof(*point_r));
	if (statvfs(path, &buf) < 0) {
		if (errno == ENOENT)
			return 0;

		i_error(STATVFS_STR"(%s) failed: %m", path);
		return -1;
	}

	point_r->device_path = p_strdup(pool, buf.f_mntfromname);
	point_r->mount_path = p_strdup(pool, buf.f_mntonname);
#ifdef __osf__ /* Tru64 */
	point_r->type = p_strdup(pool, getvfsbynumber(buf.f_type));
#else
	point_r->type = p_strdup(pool, buf.f_fstypename);
#endif
	point_r->block_size = buf.f_bsize;
	return 1;
}
#endif

int mountpoint_get(const char *path, pool_t pool, struct mountpoint *point_r)
{
#ifdef MOUNTPOINT_UNKNOWN
	memset(point_r, 0, sizeof(*point_r));
	errno = ENOSYS;
	return -1;
#elif defined (MOUNTPOINT_STATVFS)
        /* BSDs, Tru64 */
        return mountpoint_get_statvfs(path, pool, point_r);
#else
	/* find via mount iteration */
	struct mountpoint_iter *iter;
	const struct mountpoint *mnt;
	struct stat st;

	memset(point_r, 0, sizeof(*point_r));
	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;

		i_error("stat(%s) failed: %m", path);
		return -1;
	}

	iter = mountpoint_iter_init();
	while ((mnt = mountpoint_iter_next(iter)) != NULL) {
		if (minor(st.st_dev) == minor(mnt->dev) &&
		    major(st.st_dev) == major(mnt->dev))
			break;
        }
        if (mnt != NULL) {
                point_r->device_path = p_strdup(pool, mnt->device_path);
                point_r->mount_path = p_strdup(pool, mnt->mount_path);
                point_r->type = p_strdup(pool, mnt->type);
                point_r->dev = mnt->dev;
                point_r->block_size = st.st_blksize;
        }
	if (mountpoint_iter_deinit(&iter) < 0 && mnt == NULL)
		return -1;
        return mnt != NULL ? 1 : 0;
#endif
}

struct mountpoint_iter {
#ifdef MOUNTPOINT_AIX_MNTCTL
	char *mtab;
	struct vmount *vmt;
	int count;
#elif defined(MOUNTPOINT_SOLARIS) || defined(MOUNTPOINT_LINUX)
	FILE *f;
#elif defined(HAVE_GETMNTINFO) /* BSDs */
#ifndef __NetBSD__
	struct statfs *fs;
#else
	struct statvfs *fs;
#endif
	int count;
#endif
	struct mountpoint mnt;
	bool failed;
};

struct mountpoint_iter *mountpoint_iter_init(void)
{
	struct mountpoint_iter *iter = i_new(struct mountpoint_iter, 1);
#ifdef MOUNTPOINT_AIX_MNTCTL
	unsigned int size = STATIC_MTAB_SIZE;
	char *mtab;
	int count;

	mtab = t_buffer_get(size);
	while ((count = mntctl(MCTL_QUERY, size, mtab)) == 0) {
		size = *(unsigned int *)mtab;
		mtab = t_buffer_get(size);
	}
	if (count < 0) {
		i_error("mntctl(MCTL_QUERY) failed: %m");
		iter->failed = TRUE;
		return iter;
	}
	iter->count = count;
	iter->mtab = i_malloc(size);
	memcpy(iter->mtab, mtab, size);
	iter->vmt = (void *)iter->mtab;
#elif defined(MOUNTPOINT_SOLARIS)
	iter->f = fopen(MTAB_PATH, "r");
	if (iter->f == NULL) {
		i_error("fopen(%s) failed: %m", MTAB_PATH);
		iter->failed = TRUE;
		return iter;
	}
	resetmnttab(iter->f);
#elif defined(MOUNTPOINT_LINUX)
	iter->f = setmntent(MTAB_PATH, "r");
	if (iter->f == NULL) {
		i_error("setmntent(%s) failed: %m", MTAB_PATH);
		iter->failed = TRUE;
	}
#elif defined(HAVE_GETMNTINFO) /* BSDs */
	iter->count = getmntinfo(&iter->fs, MNT_NOWAIT);
	if (iter->count < 0) {
		i_error("getmntinfo() failed: %m");
		iter->failed = TRUE;
	}
#else
	iter->failed = TRUE;
#endif
	return iter;
}

const struct mountpoint *mountpoint_iter_next(struct mountpoint_iter *iter)
{
#ifdef MOUNTPOINT_AIX_MNTCTL
	struct vmount *vmt = iter->vmt;
	char *vmt_base = (char *)vmt;
	char *vmt_object, *vmt_stub, *vmt_hostname;
	struct stat vst;

	if (iter->count == 0)
		return NULL;
	iter->count--;

	iter->vmt = PTR_OFFSET(vmt, vmt->vmt_length);
	vmt_hostname = vmt_base + vmt->vmt_data[VMT_HOSTNAME].vmt_off;
	vmt_object   = vmt_base + vmt->vmt_data[VMT_OBJECT].vmt_off;
	vmt_stub     = vmt_base + vmt->vmt_data[VMT_STUB].vmt_off;

	memset(&iter->mnt, 0, sizeof(iter->mnt));
	switch (vmt->vmt_gfstype) {
	case MNT_NFS:
	case MNT_NFS3:
	case MNT_NFS4:
	case MNT_RFS4:
		iter->mnt.device_path =
			t_strconcat(vmt_hostname, ":", vmt_object, NULL);
		iter->mnt.mount_path = vmt_stub;
		iter->mnt.type       = MNTTYPE_NFS;
		break;

	case MNT_J2:
	case MNT_JFS:
		iter->mnt.device_path = vmt_object;
		iter->mnt.mount_path  = vmt_stub;
		iter->mnt.type        = MNTTYPE_JFS;
		break;
	default:
		/* unwanted filesystem */
		return mountpoint_iter_next(iter);
	}
	if (stat(iter->mnt.mount_path, &vst) == 0) {
		iter->mnt.dev = vst.st_dev;
		iter->mnt.block_size = vst.st_blksize;
	}
	return &iter->mnt;
#elif defined (MOUNTPOINT_SOLARIS)
	union {
		struct mnttab ent;
		struct extmnttab ext;
	} ent;

	if (iter->f == NULL)
		return NULL;

	memset(&iter->mnt, 0, sizeof(iter->mnt));
	while ((getextmntent(iter->f, &ent.ext, sizeof(ent.ext))) == 0) {
		if (hasmntopt(&ent.ent, MNTOPT_IGNORE) != NULL)
			continue;

		/* mnt_type contains tmpfs with swap */
		if (strcmp(ent.ent.mnt_special, MNTTYPE_SWAP) == 0)
			continue;

		iter->mnt.device_path = ent.ent.mnt_special;
		iter->mnt.mount_path = ent.ent.mnt_mountp;
		iter->mnt.type = ent.ent.mnt_fstype;
		iter->mnt.dev = makedev(ent.ext.mnt_major, ent.ext.mnt_minor);
		return &iter->mnt;
	}
	return NULL;
#elif defined (MOUNTPOINT_LINUX)
	const struct mntent *ent;
	struct stat st;

	if (iter->f == NULL)
		return NULL;

	memset(&iter->mnt, 0, sizeof(iter->mnt));
	while ((ent = getmntent(iter->f)) != NULL) {
		if (strcmp(ent->mnt_type, MNTTYPE_SWAP) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_IGNORE) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_ROOTFS) == 0)
			continue;

		iter->mnt.device_path = ent->mnt_fsname;
		iter->mnt.mount_path = ent->mnt_dir;
		iter->mnt.type = ent->mnt_type;
		if (stat(ent->mnt_dir, &st) == 0) {
			iter->mnt.dev = st.st_dev;
			iter->mnt.block_size = st.st_blksize;
		}
		return &iter->mnt;
	}
	return NULL;
#elif defined(HAVE_GETMNTINFO) /* BSDs */
	while (iter->count > 0) {
#ifndef __NetBSD__
		struct statfs *fs = iter->fs;
#else
		struct statvfs *fs = iter->fs;
#endif

		iter->fs++;
		iter->count--;

		iter->mnt.device_path = fs->f_mntfromname;
		iter->mnt.mount_path = fs->f_mntonname;
#ifdef __osf__ /* Tru64 */
		iter->mnt.type = getvfsbynumber(fs->f_type);
#else
		iter->mnt.type = fs->f_fstypename;
#endif
		iter->mnt.block_size = fs->f_bsize;
		return &iter->mnt;
	}
	return NULL;
#else
	return NULL;
#endif
}

int mountpoint_iter_deinit(struct mountpoint_iter **_iter)
{
	struct mountpoint_iter *iter = *_iter;
	int ret = iter->failed ? -1 : 0;

	*_iter = NULL;
#ifdef MOUNTPOINT_AIX_MNTCTL
	i_free(iter->mtab);
#elif defined (MOUNTPOINT_SOLARIS)
	if (iter->f != NULL)
		fclose(iter->f);
#elif defined (MOUNTPOINT_LINUX)
	if (iter->f != NULL)
		endmntent(iter->f);
#endif
	i_free(iter);
	return ret;
}
