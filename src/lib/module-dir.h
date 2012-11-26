#ifndef MODULE_DIR_H
#define MODULE_DIR_H

struct module_dir_load_settings {
	/* If abi_version is non-NULL and the module contains a version symbol,
	   fail the load if they're different. In both strings ignore anything
	   after the first '(' character, so the version can be e.g.:
	   2.2.ABIv1(2.2.15) */
	const char *abi_version;
	/* Binary name used for checking if plugin is tried to be loaded for
	   wrong binary. */
	const char *binary_name;
	/* Setting name used in plugin dependency error message */
	const char *setting_name;

	/* If non-NULL, load only modules where filter_callback returns TRUE */
	bool (*filter_callback)(const char *name, void *context);
	void *filter_context;

	/* Require all plugins to have <plugin_name>_init() function */
	unsigned int require_init_funcs:1;
	/* Enable debug logging */
	unsigned int debug:1;
	/* If dlopen() fails for some modules, silently skip it. */
	unsigned int ignore_dlopen_errors:1;
	/* Don't fail if some specified modules weren't found */
	unsigned int ignore_missing:1;
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
   module names to load. */
struct module *module_dir_load(const char *dir, const char *module_names,
			       const struct module_dir_load_settings *set)
	ATTR_NULL(2);
/* Load modules that aren't already loaded. */
struct module *
module_dir_load_missing(struct module *old_modules,
			const char *dir, const char *module_names,
			const struct module_dir_load_settings *set)
	ATTR_NULL(1, 3);
/* Call init() in all modules */
void module_dir_init(struct module *modules);
/* Call deinit() in all modules and mark them NULL so module_dir_unload()
   won't do it again. */
void module_dir_deinit(struct module *modules);
/* Unload all modules */
void module_dir_unload(struct module **modules);
/* Find a module by name. */
struct module *module_dir_find(struct module *modules, const char *name);

void *module_get_symbol(struct module *module, const char *symbol);
void *module_get_symbol_quiet(struct module *module, const char *symbol);

/* Returns module's base name from the filename. */
const char *module_file_get_name(const char *fname);
/* Returns module's name without "_plugin" suffix. */
const char *module_get_plugin_name(struct module *module);

#endif
