/* Copyright (c) 2003-2009 Dovecot authors, see the included COPYING file */

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

void *module_get_symbol_quiet(struct module *module, const char *symbol)
{
	/* clear out old errors */
	(void)dlerror();

	return dlsym(module->handle, symbol);
}

void *module_get_symbol(struct module *module, const char *symbol)
{
	const char *error;
	void *ret;

	ret = module_get_symbol_quiet(module, symbol);
	if (ret == NULL) {
		error = dlerror();
		if (error != NULL) {
			i_error("module %s: dlsym(%s) failed: %s",
				module->path, symbol, error);
			ret = NULL;
		}
	}
	return ret;
}

const char *module_file_get_name(const char *fname)
{
	const char *p;

	/* [lib][nn_]name(.so) */
	if (strncmp(fname, "lib", 3) == 0)
		fname += 3;

	for (p = fname; *p != '\0'; p++) {
		if (*p < '0' || *p > '9')
			break;
	}
	if (*p == '_')
		fname = p + 1;

	p = strstr(fname, MODULE_SUFFIX);
	if (p == NULL)
		return fname;

	return t_strdup_until(fname, p);
}

static void *get_symbol(struct module *module, const char *symbol, bool quiet)
{
	if (quiet)
		return module_get_symbol_quiet(module, symbol);

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

static bool
module_check_missing_dependencies(struct module *module,
				  struct module *all_modules)
{
	const char **deps;
	struct module *m;
	unsigned int len;

	deps = dlsym(module->handle,
		     t_strconcat(module->name, "_dependencies", NULL));
	if (deps == NULL)
		return TRUE;

	for (; *deps != NULL; deps++) {
		len = strlen(*deps);
		for (m = all_modules; m != NULL; m = m->next) {
			if (strncmp(m->name, *deps, len) == 0 &&
			    (m->name[len] == '\0' ||
			     strcmp(m->name+len, "_plugin") == 0))
				break;
		}
		if (m == NULL) {
			i_error("Can't load plugin %s: "
				"Plugin %s must be loaded also",
				module->name, *deps);
			return FALSE;
		}
	}
	return TRUE;
}

static struct module *
module_load(const char *path, const char *name, bool require_init_funcs,
	    const char *version, struct module *all_modules)
{
	void *handle;
	struct module *module;
	const char *const *module_version;

	handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
	if (handle == NULL) {
		i_error("dlopen(%s) failed: %s", path, dlerror());
		return NULL;
	}

	module = i_new(struct module, 1);
	module->path = i_strdup(path);
	module->name = i_strdup(name);
	module->handle = handle;

	module_version = version == NULL ? NULL :
		get_symbol(module, t_strconcat(name, "_version", NULL), TRUE);
	if (module_version != NULL &&
	    strcmp(*module_version, version) != 0) {
		i_error("Module is for different version %s: %s",
			*module_version, path);
		module_free(module);
		return NULL;
	}

	/* get our init func */
	module->init = (void (*)(struct module *))
		get_symbol(module, t_strconcat(name, "_init", NULL),
			   !require_init_funcs);
	module->deinit = module->init == NULL ? NULL : (void (*)(void))
		get_symbol(module, t_strconcat(name, "_deinit", NULL),
			   !require_init_funcs);

	if ((module->init == NULL || module->deinit == NULL) &&
	    require_init_funcs) {
		i_error("Module doesn't have %s function: %s",
			module->init == NULL ? "init" : "deinit", path);
		module->deinit = NULL;
		module_free(module);
		return NULL;
	}

	if (!module_check_missing_dependencies(module, all_modules)) {
		module->deinit = NULL;
		module_free(module);
		return NULL;
	}

	if (getenv("DEBUG") != NULL)
		i_info("Module loaded: %s", path);
	return module;
}

static int module_name_cmp(const char *const *n1, const char *const *n2)
{
	const char *s1 = *n1, *s2 = *n2;

	if (strncmp(s1, "lib", 3) == 0)
		s1 += 3;
	if (strncmp(s2, "lib", 3) == 0)
		s2 += 3;

	return strcmp(s1, s2);
}

static bool module_want_load(const char **names, const char *name)
{
	size_t len;

	if (names == NULL)
		return TRUE;

	len = strlen(name);
	if (len > 7 && strcmp(name + len - 7, "_plugin") == 0)
		name = t_strndup(name, len - 7);

	for (; *names != NULL; names++) {
		if (strcmp(*names, name) == 0) {
			*names = "";
			return TRUE;
		}
	}
	return FALSE;
}

static void check_duplicates(ARRAY_TYPE(const_string) *names,
			     const char *name, const char *dir)
{
	const char *const *names_p, *base_name, *tmp;
	unsigned int i, count;

	base_name = module_file_get_name(name);
	names_p = array_get(names, &count);
	for (i = 0; i < count; i++) {
		tmp = module_file_get_name(names_p[i]);

		if (strcmp(tmp, base_name) == 0)
			i_fatal("Multiple files for module %s: %s/%s, %s/%s",
				base_name, dir, name, dir, names_p[i]);
	}
}

static struct module *
module_dir_load_real(const char *dir, const char *module_names,
		     bool require_init_funcs, const char *version)
{
	DIR *dirp;
	struct dirent *d;
	const char *name, *p, *const *names_p;
	const char **module_names_arr;
	struct module *modules, *module, **module_pos;
	unsigned int i, count;
	ARRAY_TYPE(const_string) names;
	pool_t pool;

	if (getenv("DEBUG") != NULL)
		i_info("Loading modules from directory: %s", dir);

	dirp = opendir(dir);
	if (dirp == NULL) {
		if (module_names != NULL) {
			/* we were given a list of modules to load.
			   we can't fail. */
			i_fatal("opendir(%s) failed: %m", dir);
		}
		if (errno != ENOENT)
			i_error("opendir(%s) failed: %m", dir);
		return NULL;
	}

	pool = pool_alloconly_create("module loader", 4096);
	p_array_init(&names, pool, 32);

	modules = NULL;
	while ((d = readdir(dirp)) != NULL) {
		name = d->d_name;

		if (name[0] == '.')
			continue;

		p = strstr(name, MODULE_SUFFIX);
		if (p == NULL || strlen(p) != 3)
			continue;

		T_BEGIN {
			check_duplicates(&names, name, dir);
		} T_END;

		name = p_strdup(pool, d->d_name);
		array_append(&names, &name, 1);
	}

	array_sort(&names, module_name_cmp);
	names_p = array_get(&names, &count);

	if (module_names == NULL)
		module_names_arr = NULL;
	else {
		module_names_arr = t_strsplit_spaces(module_names, ", ");
		/* allow giving the module names also in non-base form.
		   convert them in here. */
		for (i = 0; module_names_arr[i] != NULL; i++) {
			module_names_arr[i] =
				module_file_get_name(module_names_arr[i]);
		}
	}

	module_pos = &modules;
	for (i = 0; i < count; i++) T_BEGIN {
		const char *path, *stripped_name;

		name = names_p[i];
		stripped_name = module_file_get_name(name);
		if (!module_want_load(module_names_arr, stripped_name))
			module = NULL;
		else {
			path = t_strconcat(dir, "/", name, NULL);
			module = module_load(path, stripped_name,
					     require_init_funcs, version,
					     modules);
			if (module == NULL && module_names_arr != NULL)
				i_fatal("Couldn't load required plugins");
		}

		if (module != NULL) {
			*module_pos = module;
			module_pos = &module->next;
		}
	} T_END;

	if (module_names_arr != NULL) {
		/* make sure all modules were found */
		for (; *module_names_arr != NULL; module_names_arr++) {
			if (**module_names_arr != '\0') {
				i_fatal("Plugin %s not found from directory %s",
					*module_names_arr, dir);
			}
		}
	}
	pool_unref(&pool);

	if (closedir(dirp) < 0)
		i_error("closedir(%s) failed: %m", dir);

	return modules;
}

struct module *module_dir_load(const char *dir, const char *module_names,
			       bool require_init_funcs, const char *version)
{
	struct module *modules;

	T_BEGIN {
		modules = module_dir_load_real(dir, module_names,
					       require_init_funcs, version);
	} T_END;
	return modules;
}

void module_dir_init(struct module *modules)
{
	struct module *module;

	for (module = modules; module != NULL; module = module->next) {
		if (module->init != NULL) {
			T_BEGIN {
				module->init(module);
			} T_END;
		}
	}
}

void module_dir_deinit(struct module *modules)
{
	struct module *module, **rev;
	unsigned int i, count = 0;

	for (module = modules; module != NULL; module = module->next)
		count++;

	if (count == 0)
		return;

	/* @UNSAFE: deinitialize in reverse order */
	T_BEGIN {
		rev = t_new(struct module *, count);
		for (i = 0, module = modules; i < count; i++) {
			rev[count-i-1] = module;
			module = module->next;
		}

		for (i = 0; i < count; i++) {
			module = rev[i];

			if (module->deinit != NULL) {
				module->deinit();
				module->deinit = NULL;
			}
		}
	} T_END;
}

void module_dir_unload(struct module **modules)
{
	struct module *module, *next;

	/* Call all modules' deinit() first, so that they may still call each
	   others' functions. */
	module_dir_deinit(*modules);

	for (module = *modules; module != NULL; module = next) {
		next = module->next;
		module_free(module);
	}

	*modules = NULL;
}

#else

struct module *module_dir_load(const char *dir ATTR_UNUSED,
			       const char *module_names ATTR_UNUSED,
			       bool require_init_funcs ATTR_UNUSED,
			       const char *version ATTR_UNUSED)
{
	i_error("Dynamically loadable module support not built in");
	return NULL;
}

void module_dir_deinit(struct module *modules ATTR_UNUSED)
{
}

void module_dir_unload(struct module **modules ATTR_UNUSED)
{
}

#endif
