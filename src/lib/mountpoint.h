#ifndef MOUNTPOINT_H
#define MOUNTPOINT_H

struct mountpoint {
	char *device_path;
	char *mount_path;
	char *type;
	dev_t dev;
	unsigned int block_size; /* may not be set for iteration */
};

/* Returns 1 = found, 0 = not found (from mount tabs, or the path itself),
   -1 = error */
int mountpoint_get(const char *path, pool_t pool, struct mountpoint *point_r);

/* Iterate through mountpoints */
struct mountpoint_iter *mountpoint_iter_init(void);
/* Returns the next mountpoint or NULL if there are no more. */
const struct mountpoint *mountpoint_iter_next(struct mountpoint_iter *iter);
/* Returns 0 if mountpoints were iterated successfully, -1 if it failed. */
int mountpoint_iter_deinit(struct mountpoint_iter **iter);

#endif
