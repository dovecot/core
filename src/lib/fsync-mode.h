#ifndef FSYNC_MODE_H
#define FSYNC_MODE_H

enum fsync_mode {
	/* fsync when it's necessary for data safety. */
	FSYNC_MODE_OPTIMIZED = 0,
	/* never fsync (in case of a crash can lose data) */
	FSYNC_MODE_NEVER,
	/* fsync after all writes. this is necessary with NFS to avoid
	   write failures being delayed until file is close(). */
	FSYNC_MODE_ALWAYS
};

#endif
