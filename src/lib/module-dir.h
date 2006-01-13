#ifndef __MODULE_DIR_H
#define __MODULE_DIR_H

struct module {
	char *path, *name;

	void *handle;
	void (*deinit)(void);

        struct module *next;
};

/* Load all modules in given directory. */
struct module *module_dir_load(const char *dir, bool require_init_funcs);
/* Unload all modules */
void module_dir_unload(struct module *modules);

void *module_get_symbol(struct module *module, const char *symbol);

#endif
