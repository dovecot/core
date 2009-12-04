#ifndef MODULE_DIR_H
#define MODULE_DIR_H

struct module {
	char *path, *name;

	void *handle;
	void (*init)(struct module *module);
	void (*deinit)(void);

        struct module *next;
};

/* Load modules in given directory. module_names is a space separated list of
   module names to load, or NULL to load everything. If version is non-NULL and
   the module contains a version symbol, fail the load if they're different. */
struct module *module_dir_load(const char *dir, const char *module_names,
			       bool require_init_funcs, const char *version);
/* Call init() in all modules */
void module_dir_init(struct module *modules);
/* Call deinit() in all modules and mark them NULL so module_dir_unload()
   won't do it again. */
void module_dir_deinit(struct module *modules);
/* Unload all modules */
void module_dir_unload(struct module **modules);

void *module_get_symbol(struct module *module, const char *symbol);
void *module_get_symbol_quiet(struct module *module, const char *symbol);

/* Returns module's base name from the filename. */
const char *module_file_get_name(const char *fname);

#endif
