#ifndef MOUNTPOINT_LIST_H
#define MOUNTPOINT_LIST_H

#define MOUNTPOINT_LIST_FNAME "mounts"
#define MOUNTPOINT_STATE_DEFAULT "online"
#define MOUNTPOINT_STATE_IGNORE "ignore"

#define MOUNTPOINT_WRONGLY_NOT_MOUNTED(rec) \
	(!(rec)->mounted && !(rec)->wildcard && \
	 strcmp((rec)->state, MOUNTPOINT_STATE_IGNORE) != 0)

struct mountpoint_list_rec {
	const char *mount_path;
	const char *state;
	/* _add_missing() skips all mountpoints below this mount_path */
	bool wildcard;
	/* TRUE, if _add_missing() saw this mount */
	bool mounted;
};

/* A default known good list of mountpoint types that don't contain emails
   (e.g. proc, tmpfs, etc.) */
extern const char *const mountpoint_list_default_ignore_types[];
/* A default known good list of directories which shouldn't contain emails
   (e.g. /media) */
extern const char *const mountpoint_list_default_ignore_prefixes[];

struct mountpoint_list *
mountpoint_list_init(const char *perm_path, const char *state_path);
struct mountpoint_list *
mountpoint_list_init_readonly(const char *state_path);
void mountpoint_list_deinit(struct mountpoint_list **list);

/* Reload the mountpoints if they have changed. Returns 0 if ok,
   -1 if I/O error. */
int mountpoint_list_refresh(struct mountpoint_list *list);
/* Save the current list of mountpoints. Returns 0 if successful,
   -1 if I/O error. */
int mountpoint_list_save(struct mountpoint_list *list);

/* Add a mountpoint. If it already exists, replace the old one. */
void mountpoint_list_add(struct mountpoint_list *list,
			 const struct mountpoint_list_rec *rec);
/* Remove a mountpoint. Returns TRUE if mountpoint was found and removed. */
bool mountpoint_list_remove(struct mountpoint_list *list,
			    const char *mount_path);
/* Add all currently mounted missing mountpoints to the list and update all
   mountpoints' mounted state. The mountpoints that match existing wildcards
   aren't added. Mountpoints with paths under ignore_prefixes aren't added.
   Mountpoints with type in ignore_types list also aren't added.
   Returns 0 if we successfully iterated through all mountpoints, -1 if not. */
int mountpoint_list_add_missing(struct mountpoint_list *list,
				const char *default_state,
				const char *const *ignore_prefixes,
				const char *const *ignore_types);
/* Update "mounted" status for all mountpoints. */
int mountpoint_list_update_mounted(struct mountpoint_list *list);

/* Find a mountpoint record for given path. */
struct mountpoint_list_rec *
mountpoint_list_find(struct mountpoint_list *list, const char *path);

/* Iterate through all mountpoints in the list. */
struct mountpoint_list_iter *
mountpoint_list_iter_init(struct mountpoint_list *list);
struct mountpoint_list_rec *
mountpoint_list_iter_next(struct mountpoint_list_iter *iter);
void mountpoint_list_iter_deinit(struct mountpoint_list_iter **iter);

#endif
