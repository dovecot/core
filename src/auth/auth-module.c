/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"

#ifdef HAVE_MODULES

#include "auth-module.h"

#include <sys/stat.h>
#include <dlfcn.h>

#ifndef RTLD_GLOBAL
#  define RTLD_GLOBAL 0
#endif

#ifndef RTLD_NOW
#  define RTLD_NOW 0
#endif

struct auth_module {
	struct auth_module *next;

	int refcount;
	char *name;
	void *handle;
};

static struct auth_module *auth_modules = NULL;

static struct auth_module *auth_module_find(const char *name)
{
	struct auth_module *module;

	for (module = auth_modules; module != NULL; module = module->next) {
		if (strcmp(module->name, name) == 0)
			return module;
	}

	return NULL;
}

struct auth_module *auth_module_open(const char *name)
{
        struct auth_module *module;
	const char *path;
	struct stat st;
	void *handle;

	module = auth_module_find(name);
	if (module != NULL) {
		module->refcount++;
		return module;
	}

	path = t_strconcat(AUTH_MODULE_DIR"/", name, ".so", NULL);
	if (stat(path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", path);
		return NULL;
	}

	handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
	if (handle == NULL)
		i_error("dlopen(%s) failed: %s", path, dlerror());

	module = i_new(struct auth_module, 1);
	module->refcount = 1;
	module->name = i_strdup(name);
	module->handle = handle;

	module->next = auth_modules;
	auth_modules = module;
	return module;
}

void auth_module_close(struct auth_module *module)
{
	struct auth_module **pos;

	if (--module->refcount > 0)
		return;

	for (pos = &auth_modules; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == module) {
			*pos = module->next;
			break;
		}
	}

	if (dlclose(module->handle) != 0)
		i_error("dlclose() failed: %s", dlerror());
	i_free(module->name);
	i_free(module);
}

void *auth_module_sym(struct auth_module *module, const char *name)
{
	const char *error;
	void *ret;

	ret = dlsym(module->handle, name);

	error = dlerror();
	if (error != NULL)
		i_error("dlsym(%s) failed: %s", name, error);
	return ret;
}

#endif
