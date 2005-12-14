#ifndef __QUOTA_FS_H
#define __QUOTA_FS_H

#define HAVE_FS_QUOTA

#ifdef HAVE_SYS_QUOTA_H
#  include <sys/quota.h> /* Linux */
#elif defined(HAVE_SYS_FS_UFS_QUOTA_H)
#  include <sys/fs/ufs_quota.h> /* Solaris */
#elif defined(HAVE_UFS_UFS_QUOTA_H)
#  include <ufs/ufs/quota.h> /* BSDs */
#else
#  undef HAVE_FS_QUOTA
#endif

#ifdef HAVE_STATFS_MNTFROMNAME
#  include <sys/param.h> /* BSDs */
#  include <sys/mount.h>
#elif defined(HAVE_MNTENT_H)
#  include <mntent.h> /* Linux */
#elif defined(HAVE_SYS_MNTTAB_H)
#  include <sys/mnttab.h> /* Solaris */
#else
#  undef HAVE_FS_QUOTA
#endif

#endif
