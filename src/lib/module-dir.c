/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "module-dir.h"

#ifdef HAVE_MODULES

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>

#ifndef RTLD_GLOBAL
#  define RTLD_GLOBAL 0
#endif

#ifndef RTLD_NOW
#  define RTLD_NOW 0
#endif

static const char *module_name_drop_suffix(const char *name);

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

static void *get_symbol(struct module *module, const char *symbol, bool quiet)
{
	if (quiet)
		return module_get_symbol_quiet(module, symbol);

	return module_get_symbol(module, symbol);
}

static void module_free(struct module *module)
{
	if (module->deinit != NULL && module->initialized)
		module->deinit();
	if (dlclose(module->handle) != 0)
		i_error("dlclose(%s) failed: %m", module->path);
	i_free(module->path);
	i_free(module->name);
	i_free(module);
}

static bool
module_check_wrong_binary_dependency(const struct module_dir_load_settings *set,
				     struct module *module)
{
	const char *symbol_name, *binary_dep, *const *names;
	string_t *errstr;

	if (set->binary_name == NULL)
		return TRUE;

	symbol_name = t_strconcat(module->name, "_binary_dependency", NULL);
	binary_dep = dlsym(module->handle, symbol_name);
	if (binary_dep == NULL)
		return TRUE;

	names = t_strsplit(binary_dep, " ");
	if (str_array_find(names, set->binary_name))
		return TRUE;

	errstr = t_str_new(128);
	str_printfa(errstr, "Can't load plugin %s: "
		    "Plugin is intended to be used only by ", module->name);
	if (names[1] == NULL)
		str_printfa(errstr, "%s binary", binary_dep);
	else
		str_printfa(errstr, "binaries: %s", binary_dep);
	str_printfa(errstr, " (we're %s)", set->binary_name);
	i_error("%s", str_c(errstr));
	return FALSE;
}

static bool
module_check_missing_plugin_dependencies(const struct module_dir_load_settings *set,
					 struct module *module,
					 struct module *all_modules)
{
	const char **deps;
	struct module *m;
	string_t *errmsg;
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
			errmsg = t_str_new(128);
			str_printfa(errmsg, "Can't load plugin %s: "
				    "Plugin %s must be loaded also",
				    module->name, *deps);
			if (set->setting_name != NULL) {
				str_printfa(errmsg,
					    " (you must set: %s=$%s %s)",
					    set->setting_name,
					    set->setting_name, *deps);
			}
			i_error("%s", str_c(errmsg));
			return FALSE;
		}
	}
	return TRUE;
}

static void *quiet_dlopen(const char *path, int flags)
{
#ifndef __OpenBSD__
	return dlopen(path, flags);
#else
	void *handle;
	int fd, fd_null;

	/* OpenBSD likes to print all "undefined symbol" errors to stderr.
	   Hide them by sending them to /dev/null. */
	fd_null = open("/dev/null", O_WRONLY);
	if (fd_null == -1)
		i_fatal("open(/dev/null) failed: %m");
	fd = dup(STDERR_FILENO);
	if (fd == -1)
		i_fatal("dup() failed: %m");
	if (dup2(fd_null, STDERR_FILENO) < 0)
		i_fatal("dup2() failed: %m");
	handle = dlopen(path, flags);
	if (dup2(fd, STDERR_FILENO) < 0)
		i_fatal("dup2() failed: %m");
	if (close(fd) < 0)
		i_error("close() failed: %m");
	if (close(fd_null) < 0)
		i_error("close() failed: %m");
	return handle;
#endif
}

static struct module *
module_load(const char *path, const char *name,
	    const struct module_dir_load_settings *set,
	    struct module *all_modules)
{
	void *handle;
	struct module *module;
	const char *const *module_version;
	bool failed = FALSE;

	if (set->ignore_dlopen_errors) {
		handle = quiet_dlopen(path, RTLD_GLOBAL | RTLD_NOW);
		if (handle == NULL) {
			if (set->debug) {
				i_debug("Skipping module %s, "
					"because dlopen() failed: %s "
					"(this is usually intentional, "
					"so just ignore this message)",
					name, dlerror());
			}
			return NULL;
		}
	} else {
		handle = dlopen(path, RTLD_GLOBAL | RTLD_NOW);
		if (handle == NULL) {
			i_error("dlopen(%s) failed: %s", path, dlerror());
#ifdef RTLD_LAZY
			failed = TRUE;
			/* try to give a better error message by lazily loading
			   the plugin and checking its dependencies */
			handle = dlopen(path, RTLD_LAZY);
			if (handle == NULL)
				return NULL;
#else
			return NULL;
#endif
		}
	}

	module = i_new(struct module, 1);
	module->path = i_strdup(path);
	module->name = i_strdup(name);
	module->handle = handle;

	module_version = set->version == NULL ? NULL :
		get_symbol(module, t_strconcat(name, "_version", NULL), TRUE);
	if (module_version != NULL &&
	    strcmp(*module_version, set->version) != 0) {
		i_error("Module is for different version %s: %s",
			*module_version, path);
		module_free(module);
		return NULL;
	}

	/* get our init func */
	module->init = (void (*)(struct module *))
		get_symbol(module, t_strconcat(name, "_init", NULL),
			   !set->require_init_funcs);
	module->deinit = module->init == NULL ? NULL : (void (*)(void))
		get_symbol(module, t_strconcat(name, "_deinit", NULL),
			   !set->require_init_funcs);

	if ((module->init == NULL || module->deinit == NULL) &&
	    set->require_init_funcs) {
		i_error("Module doesn't have %s function: %s",
			module->init == NULL ? "init" : "deinit", path);
		failed = TRUE;
	} else if (!module_check_wrong_binary_dependency(set, module) ||
		   !module_check_missing_plugin_dependencies(set, module,
							     all_modules))
		failed = TRUE;

	if (failed) {
		module->deinit = NULL;
		module_free(module);
		return NULL;
	}

	if (set->debug)
		i_debug("Module loaded: %s", path);
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
	if (names == NULL)
		return TRUE;

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

static bool module_is_loaded(struct module *modules, const char *name)
{
	struct module *module;
	unsigned int len = strlen(name);

	for (module = modules; module != NULL; module = module->next) {
		if (strncmp(module->name, name, len) == 0) {
			if (module->name[len] == '\0' ||
			    strcmp(module->name + len, "_plugin") == 0)
				return TRUE;
		}
	}
	return FALSE;
}

static void module_names_fix(const char **module_names)
{
	unsigned int i, j;

	if (module_names[0] == NULL)
		return;

	/* allow giving the module names also in non-base form.
	   convert them in here. */
	for (i = 0; module_names[i] != NULL; i++)
		module_names[i] = module_file_get_name(module_names[i]);

	/* @UNSAFE: drop duplicates */
	qsort(module_names, i, sizeof(*module_names), i_strcmp_p);
	for (i = j = 1; module_names[i] != NULL; i++) {
		if (strcmp(module_names[i-1], module_names[i]) != 0)
			module_names[j++] = module_names[i];
	}
	module_names[j] = NULL;
}

static bool
module_dir_is_all_loaded(struct module *old_modules, const char **module_names)
{
	unsigned int i;

	for (i = 0; module_names[i] != NULL; i++) {
		if (!module_is_loaded(old_modules, module_names[i]))
			return FALSE;
	}
	return TRUE;
}

static struct module *
module_dir_load_real(struct module *old_modules,
		     const char *dir, const char **module_names,
		     const struct module_dir_load_settings *set)
{
	DIR *dirp;
	struct dirent *d;
	const char *name, *p, *const *names_p;
	struct module *modules, *module, **module_pos;
	unsigned int i, count;
	ARRAY_TYPE(const_string) names;
	pool_t pool;

	if (module_names != NULL) {
		if (module_dir_is_all_loaded(old_modules, module_names))
			return old_modules;
	}

	if (set->debug)
		i_debug("Loading modules from directory: %s", dir);

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
	if (closedir(dirp) < 0)
		i_error("closedir(%s) failed: %m", dir);

	array_sort(&names, module_name_cmp);
	names_p = array_get(&names, &count);

	modules = old_modules;
	module_pos = &modules;
	while (*module_pos != NULL)
		module_pos = &(*module_pos)->next;
	for (i = 0; i < count; i++) T_BEGIN {
		const char *path, *stripped_name, *suffixless_name;

		name = names_p[i];
		stripped_name = module_file_get_name(name);
		suffixless_name = module_name_drop_suffix(stripped_name);
		if (!module_want_load(module_names, suffixless_name) ||
		    module_is_loaded(old_modules, suffixless_name))
			module = NULL;
		else {
			path = t_strconcat(dir, "/", name, NULL);
			module = module_load(path, stripped_name, set, modules);
			if (module == NULL && module_names != NULL)
				i_fatal("Couldn't load required plugins");
		}

		if (module != NULL) {
			*module_pos = module;
			module_pos = &module->next;
		}
	} T_END;

	if (module_names != NULL) {
		/* make sure all modules were found */
		for (; *module_names != NULL; module_names++) {
			if (**module_names != '\0') {
				i_fatal("Plugin '%s' not found from directory %s",
					*module_names, dir);
			}
		}
	}
	pool_unref(&pool);
	return modules;
}

struct module *
module_dir_load_missing(struct module *old_modules,
			const char *dir, const char *module_names,
			const struct module_dir_load_settings *set)
{
	struct module *modules;

	T_BEGIN {
		const char **arr = NULL;

		if (module_names != NULL) {
			arr = t_strsplit_spaces(module_names, ", ");
			module_names_fix(arr);
		}

		modules = module_dir_load_real(old_modules, dir, arr, set);
	} T_END;
	return modules;
}

void module_dir_init(struct module *modules)
{
	struct module *module;

	for (module = modules; module != NULL; module = module->next) {
		if (module->init != NULL && !module->initialized) T_BEGIN {
			module->initialized = TRUE;
			module->init(module);
		} T_END;
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

			if (module->deinit != NULL && module->initialized) {
				module->deinit();
				module->initialized = FALSE;
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

struct module *
module_dir_load_missing(struct module *old_modules ATTR_UNUSED,
			const char *dir ATTR_UNUSED,
			const char *module_names,
			const struct module_dir_load_settings *set ATTR_UNUSED)
{
#define NO_SUPPORT_ERRSTR "Dynamically loadable module support not built in"
	if (module_names == NULL)
		i_error(NO_SUPPORT_ERRSTR);
	else {
		i_fatal(NO_SUPPORT_ERRSTR", can't load plugins: %s",
			module_names);
	}
	return NULL;
}

void module_dir_init(struct module *modules ATTR_UNUSED)
{
}

void module_dir_deinit(struct module *modules ATTR_UNUSED)
{
}

void module_dir_unload(struct module **modules ATTR_UNUSED)
{
}

void *module_get_symbol(struct module *module ATTR_UNUSED,
			const char *symbol ATTR_UNUSED)
{
	return NULL;
}

void *module_get_symbol_quiet(struct module *module ATTR_UNUSED,
			      const char *symbol ATTR_UNUSED)
{
	return NULL;
}

#endif

struct module *module_dir_load(const char *dir, const char *module_names,
			       const struct module_dir_load_settings *set)
{
	return module_dir_load_missing(NULL, dir, module_names, set);
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

static const char *module_name_drop_suffix(const char *name)
{
	unsigned int len;

	len = strlen(name);
	if (len > 7 && strcmp(name + len - 7, "_plugin") == 0)
		name = t_strndup(name, len - 7);
	return name;
}

const char *module_get_plugin_name(struct module *module)
{
	return module_name_drop_suffix(module->name);
}
