#ifndef MOUNTPOINT_H
#define MOUNTPOINT_H

struct mountpoint {
	char *device_path;
	char *mount_path;
	char *type;
	unsigned int block_size;
};

/* Returns 1 = found, 0 = not found (from mount tabs, or the path itself),
   -1 = error */
int mountpoint_get(const char *path, pool_t pool, struct mountpoint *point_r);

#endif
