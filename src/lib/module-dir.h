#ifndef __MODULE_DIR_H
#define __MODULE_DIR_H

struct module {
	void *handle;
	void (*deinit)(void);

        struct module *next;
};

/* Load all modules in given directory. */
struct module *module_dir_load(const char *dir);
/* Unload all modules */
void module_dir_unload(struct module *modules);

#endif
