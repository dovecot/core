#ifndef __UNLINK_LOCKFILES_H
#define __UNLINK_LOCKFILES_H

void unlink_lockfiles(const char *dir, const char *pidprefix,
		      const char *otherprefix, time_t other_min_time);

#endif
