/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "module-dir.h"

#ifdef HAVE_MODULES

#include <stdlib.h>
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

static void *get_symbol(struct module *module, const char *symbol, bool quiet)
{
	if (quiet)
		return dlsym(module->handle, symbol);

	return module_get_symbol(module, symbol);
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
module_load(const char *path, const char *name, bool require_init_funcs)
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
		get_symbol(module, t_strconcat(name, "_init", NULL),
			   !require_init_funcs);
	module->deinit = init == NULL ? NULL : (void (*)())
		get_symbol(module, t_strconcat(name, "_deinit", NULL),
			   !require_init_funcs);

	if ((init == NULL || module->deinit == NULL) && require_init_funcs) {
		module->deinit = NULL;
		module_free(module);
		return NULL;
	}

	if (getenv("DEBUG") != NULL)
		i_info("Module loaded: %s", path);

	if (init != NULL)
		init();
	return module;
}

static int module_name_cmp(const void *p1, const void *p2)
{
	const char *n1 = p1, *n2 = p2;

	if (strncmp(n1, "lib", 3) == 0)
		n1 += 3;
	if (strncmp(n2, "lib", 3) == 0)
		n1 += 3;

	return strcmp(n1, n2);
}

struct module *module_dir_load(const char *dir, bool require_init_funcs)
{
	DIR *dirp;
	struct dirent *d;
	const char *name, *path, *p, *stripped_name, **names_p;
	struct module *modules, *module;
	unsigned int i, count;
	array_t ARRAY_DEFINE(names, const char *);
	pool_t pool;

	if (getenv("DEBUG") != NULL)
		i_info("Loading modules from directory: %s", dir);

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (errno != ENOENT)
			i_error("opendir(%s) failed: %m", dir);
		return NULL;
	}

	pool = pool_alloconly_create("module loader", 1024);
	ARRAY_CREATE(&names, pool, const char *, 32);

	modules = NULL;
	while ((d = readdir(dirp)) != NULL) {
		name = d->d_name;

		if (name[0] == '.')
			continue;

		p = strstr(name, ".so");
		if (p == NULL || strlen(p) != 3)
			continue;

		name = p_strdup(pool, d->d_name);
		array_append(&names, &name, 1);
	}

	names_p = array_get_modifyable(&names, NULL);
	count = array_count(&names);
	qsort(names_p, count, sizeof(const char *), module_name_cmp);

	for (i = 0; i < count; i++) {
		const char *name = names_p[i];

		/* [lib][nn_]name(.so) */
                stripped_name = name;
		if (strncmp(stripped_name, "lib", 3) == 0)
			stripped_name += 3;

		for (p = stripped_name; *p != '\0'; p++) {
			if (*p < '0' || *p > '9')
				break;
		}
		if (*p == '_')
			stripped_name = p + 1;

		p = strstr(stripped_name, ".so");
		i_assert(p != NULL);

		t_push();
		stripped_name = t_strdup_until(stripped_name, p);
		path = t_strconcat(dir, "/", name, NULL);
		module = module_load(path, stripped_name, require_init_funcs);
		t_pop();

		if (module != NULL) {
			module->next = modules;
			modules = module;
		}
	}
	pool_unref(pool);

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

struct module *module_dir_load(const char *dir __attr_unused__,
			       bool require_init_funcs __attr_unused__)
{
	i_error("Dynamically loadable module support not built in");
	return NULL;
}

void module_dir_unload(struct module *modules __attr_unused__)
{
}

#endif
