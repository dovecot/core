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

static void *get_symbol(const char *path, void *handle, const char *symbol)
{
	const char *error;
	void *ret;

	/* get our init func */
	ret = dlsym(handle, symbol);

	error = dlerror();
	if (error != NULL) {
		i_error("module %s: dlsym(%s) failed: %s", path, symbol, error);
		ret = NULL;
	}

	return ret;
}

static struct module *module_load(const char *path, const char *name)
{
	void *handle;
	void (*init)(void);
	void (*deinit)(void);
	struct module *module;

	handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
	if (handle == NULL) {
		i_error("dlopen(%s) failed: %s", path, dlerror());
		return NULL;
	}

	/* get our init func */
	init = (void (*)()) get_symbol(path, handle,
				       t_strconcat(name, "_init", NULL));
	deinit = init == NULL ? NULL :
		(void (*)()) get_symbol(path, handle,
					t_strconcat(name, "_deinit", NULL));

	if (init == NULL || deinit == NULL) {
		(void)dlclose(handle);
		return NULL;
	}

	init();

	module = i_new(struct module, 1);
	module->handle = handle;
	module->deinit = deinit;
	return module;
}

struct module *module_dir_load(const char *dir)
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
		module = module_load(path, name);
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
		modules->deinit();
		if (dlclose(modules->handle) != 0)
			i_error("dlclose() failed: %m");
		i_free(modules);
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
