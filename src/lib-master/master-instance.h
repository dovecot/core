#ifndef MASTER_INSTANCE_H
#define MASTER_INSTANCE_H

#define MASTER_INSTANCE_FNAME "instances"

struct master_instance_list;

struct master_instance {
	time_t last_used;
	const char *name;
	const char *base_dir;
	const char *config_path;
};

struct master_instance_list *master_instance_list_init(const char *path);
void master_instance_list_deinit(struct master_instance_list **list);

/* Add/update last_used timestamp for an instance. Returns 0 if ok,
   -1 if I/O error. */
int master_instance_list_update(struct master_instance_list *list,
				const char *base_dir);
/* Set instance's name. Returns 1 if ok, 0 if name was already used for
   another instance (base_dir) or -1 if I/O error. */
int master_instance_list_set_name(struct master_instance_list *list,
				  const char *base_dir, const char *name);
/* Remove instance. Returns 1 if ok, 0 if it didn't exist or -1 if I/O error. */
int master_instance_list_remove(struct master_instance_list *list,
				const char *base_dir);

/* Find instance by its name. */
const struct master_instance *
master_instance_list_find_by_name(struct master_instance_list *list,
				  const char *name);

/* Iterate through existing instances. */
struct master_instance_list_iter *
master_instance_list_iterate_init(struct master_instance_list *list);
const struct master_instance *
master_instance_iterate_list_next(struct master_instance_list_iter *iter);
void master_instance_iterate_list_deinit(struct master_instance_list_iter **iter);

#endif
