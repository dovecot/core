/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "module-dir.h"

#ifdef HAVE_MODULES

#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>

#ifndef RTLD_GLOBAL
#  define RTLD_GLOBAL 0
#endif

#ifndef RTLD_NOW
#  define RTLD_NOW 0
#endif

void *module_get_symbol(struct module *module, const char *symbol)
{
	const char *error;
	void *ret;

	/* get our init func */
	ret = dlsym(module->handle, symbol);

	error = dlerror();
	if (error != NULL) {
		i_error("module %s: dlsym(%s) failed: %s",
			module->path, symbol, error);
		ret = NULL;
	}

	return ret;
}

static void module_free(struct module *module)
{
	if (module->deinit != NULL)
		module->deinit();
	if (dlclose(module->handle) != 0)
		i_error("dlclose(%s) failed: %m", module->path);
	i_free(module->path);
	i_free(module->name);
	i_free(module);
}

static struct module *
module_load(const char *path, const char *name, int require_init_funcs)
{
	void *handle;
	void (*init)(void);
	struct module *module;

	handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
	if (handle == NULL) {
		i_error("dlopen(%s) failed: %s", path, dlerror());
		return NULL;
	}

	module = i_new(struct module, 1);
	module->path = i_strdup(path);
	module->name = i_strdup(name);
	module->handle = handle;

	/* get our init func */
	init = (void (*)())
		module_get_symbol(module, t_strconcat(name, "_init", NULL));
	module->deinit = init == NULL ? NULL : (void (*)())
		module_get_symbol(module, t_strconcat(name, "_deinit", NULL));

	if ((init == NULL || module->deinit == NULL) && require_init_funcs) {
		module->deinit = NULL;
		module_free(module);
		return NULL;
	}

	if (init != NULL)
		init();
	return module;
}

struct module *module_dir_load(const char *dir, int require_init_funcs)
{
	DIR *dirp;
	struct dirent *d;
	const char *name, *path, *p;
	struct module *modules, *module;

	dirp = opendir(dir);
	if (dirp == NULL) {
		i_error("opendir(%s) failed: %m", dir);
		return NULL;
	}

	modules = NULL;
	while ((d = readdir(dirp)) != NULL) {
		name = d->d_name;

		if (name[0] == '.')
			continue;

		p = strstr(name, ".so");
		if (p == NULL || strlen(p) != 3)
			continue;

		if (strncmp(name, "lib", 3) == 0)
			name += 3;

		t_push();
		name = t_strdup_until(d->d_name, p);
		path = t_strconcat(dir, "/", d->d_name, NULL);
		module = module_load(path, name, require_init_funcs);
		t_pop();

		if (module != NULL) {
			module->next = modules;
			modules = module;
		}
	}

	if (closedir(dirp) < 0)
		i_error("closedir(%s) failed: %m", dir);

	return modules;
}

void module_dir_unload(struct module *modules)
{
	struct module *next;

	while (modules != NULL) {
		next = modules->next;
		module_free(modules);
		modules = next;
	}
}

#else

struct module *module_dir_load(const char *dir __attr_unused__)
{
	i_error("Dynamically loadable module support not built in");
	return NULL;
}

void module_dir_unload(struct module *modules __attr_unused__)
{
}

#endif
