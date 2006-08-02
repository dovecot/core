#ifndef __QUOTA_FS_H
#define __QUOTA_FS_H

#define HAVE_FS_QUOTA

#ifdef HAVE_SYS_QUOTA_H
#  include <sys/quota.h> /* Linux */
#elif defined(HAVE_SYS_FS_UFS_QUOTA_H)
#  include <sys/fs/ufs_quota.h> /* Solaris */
#elif defined(HAVE_UFS_UFS_QUOTA_H)
#  include <ufs/ufs/quota.h> /* BSDs */
#elif defined(HAVE_JFS_QUOTA_H)
#  include <jfs/quota.h> /* AIX */
#else
#  undef HAVE_FS_QUOTA
#endif

#if !defined(HAVE_QUOTACTL) && !defined(HAVE_Q_QUOTACTL)
#  undef HAVE_FS_QUOTA
#endif

#endif
