/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mountpoint.h"

#include <sys/stat.h>

#ifdef HAVE_SYS_VMOUNT_H
#  include <stdio.h>
#  include <sys/vmount.h> /* AIX */
#elif defined(HAVE_STATVFS_MNTFROMNAME)
#  include <sys/statvfs.h> /* NetBSD 3.0+, FreeBSD 5.0+ */
#  define STATVFS_STR "statvfs"
#elif defined(HAVE_STATFS_MNTFROMNAME)
#  include <sys/param.h> /* Older BSDs */
#  include <sys/mount.h>
#  define statvfs statfs
#  define STATVFS_STR "statfs"
#elif defined(HAVE_MNTENT_H)
#  include <stdio.h>
#  include <mntent.h> /* Linux */
#elif defined(HAVE_SYS_MNTTAB_H)
#  include <stdio.h>
#  include <sys/mnttab.h> /* Solaris */
#  include <sys/mntent.h>
#else
#  define MOUNTPOINT_UNKNOWN
#endif

#ifdef HAVE_SYS_MNTTAB_H
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

int mountpoint_get(const char *path, pool_t pool, struct mountpoint *point_r)
{
#ifdef MOUNTPOINT_UNKNOWN
	memset(point_r, 0, sizeof(*point_r));
	errno = ENOSYS;
	return -1;
#elif defined (HAVE_STATFS_MNTFROMNAME) || defined(HAVE_STATVFS_MNTFROMNAME)
	/* BSDs */
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
#else
	/* Linux, Solaris: /etc/mtab reading */
#ifdef HAVE_SYS_MNTTAB_H
	union {
		struct mnttab ent;
		struct extmnttab ext;
	} ent;
#else
	struct mntent *ent;
	struct stat st2;
#endif
	struct stat st;
	const char *device_path = NULL, *mount_path = NULL, *type = NULL;
	unsigned int block_size;
	FILE *f;

	memset(point_r, 0, sizeof(*point_r));
	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return 0;

		i_error("stat(%s) failed: %m", path);
		return -1;
	}
	block_size = st.st_blksize;

#ifdef HAVE_SYS_VMOUNT_H
{
	char static_mtab[STATIC_MTAB_SIZE], *mtab = static_mtab;
	int i, count;
	const struct vmount *vmt;

	count = mntctl(MCTL_QUERY, sizeof(static_mtab), mtab);
	while (count == 0) {
		unsigned int size = *(unsigned int *)mtab;

		mtab  = t_malloc(size);
		count = mntctl(MCTL_QUERY, size, mtab);
	}
	if (count < 0) {
		i_error("mntctl(MCTL_QUERY) failed: %m");
		return -1;
	}
	vmt = (struct vmount *)mtab;
	for (i = 0; i < count && device_path == NULL; i++) {
		struct stat vst;
		const char *vmt_base = (const char *)vmt;
		const char *vmt_object, *vmt_stub, *vmt_hostname;

		vmt_hostname = vmt_base + vmt->vmt_data[VMT_HOSTNAME].vmt_off;
		vmt_object   = vmt_base + vmt->vmt_data[VMT_OBJECT].vmt_off;
		vmt_stub     = vmt_base + vmt->vmt_data[VMT_STUB].vmt_off;

		switch (vmt->vmt_gfstype) {
		case MNT_NFS:
		case MNT_NFS3:
		case MNT_NFS4:
		case MNT_RFS4:
			if (stat(vmt_stub, &vst) == 0 &&
			    st.st_dev == vst.st_dev) {
				device_path = t_strconcat(vmt_hostname, ":",
							  vmt_object, NULL);
				mount_path  = vmt_stub;
				type        = MNTTYPE_NFS;
			}
			break;

		case MNT_J2:
		case MNT_JFS:
			if (stat(vmt_stub, &vst) == 0 &&
			    st.st_dev == vst.st_dev) {
				device_path = vmt_object;
				mount_path  = vmt_stub;
				type        = MNTTYPE_JFS;
			}
			break;
		}
		vmt = CONST_PTR_OFFSET(vmt, vmt->vmt_length);
	}
}
#elif defined(HAVE_SYS_MNTTAB_H)

	/* Solaris */
	f = fopen(MTAB_PATH, "r");
	if (f == NULL) {
		i_error("fopen(%s) failed: %m", MTAB_PATH);
		return -1;
	}
	resetmnttab(f);
	while ((getextmntent(f, &ent.ext, sizeof(ent.ext))) == 0) {
		if (hasmntopt(&ent.ent, MNTOPT_IGNORE) != NULL)
			continue;

		/* mnt_type contains tmpfs with swap */
		if (strcmp(ent.ent.mnt_special, MNTTYPE_SWAP) == 0)
			continue;

		if (major(st.st_dev) == ent.ext.mnt_major &&
		    minor(st.st_dev) == ent.ext.mnt_minor) {
			device_path = ent.ent.mnt_special;
			mount_path = ent.ent.mnt_mountp;
			type = ent.ent.mnt_fstype;
			break;
		}
	}
	fclose(f);
#else
	/* Linux */
	f = setmntent(MTAB_PATH, "r");
	if (f == NULL) {
		i_error("setmntent(%s) failed: %m", MTAB_PATH);
		return -1;
	}
	while ((ent = getmntent(f)) != NULL) {
		if (strcmp(ent->mnt_type, MNTTYPE_SWAP) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_IGNORE) == 0 ||
		    strcmp(ent->mnt_type, MNTTYPE_ROOTFS) == 0)
			continue;

		if (stat(ent->mnt_dir, &st2) == 0 &&
		    CMP_DEV_T(st.st_dev, st2.st_dev)) {
			device_path = ent->mnt_fsname;
			mount_path = ent->mnt_dir;
			type = ent->mnt_type;
			break;
		}
	}
	endmntent(f);
#endif
	if (device_path == NULL)
		return 0;

	point_r->device_path = p_strdup(pool, device_path);
	point_r->mount_path = p_strdup(pool, mount_path);
	point_r->type = p_strdup(pool, type);
	point_r->block_size = block_size;
	return 1;
#endif
}
