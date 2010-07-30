#ifndef MODULE_DIR_H
#define MODULE_DIR_H

struct module_dir_load_settings {
	/* If version is non-NULL and the module contains a version symbol,
	   fail the load if they're different. */
	const char *version;
	/* Binary name used for checking if plugin is tried to be loaded for
	   wrong binary. */
	const char *binary_name;
	/* Setting name used in plugin dependency error message */
	const char *setting_name;

	/* Require all plugins to have <plugin_name>_init() function */
	unsigned int require_init_funcs:1;
	/* Enable debug logging */
	unsigned int debug:1;
	/* If dlopen() fails for some modules, silently skip it. */
	unsigned int ignore_dlopen_errors:1;
};

struct module {
	char *path, *name;

	void *handle;
	void (*init)(struct module *module);
	void (*deinit)(void);

	unsigned int initialized:1;

        struct module *next;
};

/* Load modules in given directory. module_names is a space separated list of
   module names to load, or NULL to load everything. */
struct module *module_dir_load(const char *dir, const char *module_names,
			       const struct module_dir_load_settings *set);
/* Load modules that aren't already loaded. */
struct module *
module_dir_load_missing(struct module *old_modules,
			const char *dir, const char *module_names,
			const struct module_dir_load_settings *set);
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
/* Returns module's name without "_plugin" suffix. */
const char *module_get_plugin_name(struct module *module);

#endif
