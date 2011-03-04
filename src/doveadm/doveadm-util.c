/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "network.h"
#include "master-service.h"
#include "module-dir.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "doveadm-util.h"

#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

bool doveadm_verbose = FALSE, doveadm_debug = FALSE, doveadm_server = FALSE;
static struct module *modules = NULL;

void doveadm_load_modules(void)
{
	struct module_dir_load_settings mod_set;

	/* some doveadm plugins have dependencies to mail plugins. we can load
	   only those whose dependencies have been loaded earlier, the rest are
	   ignored. */
	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = doveadm_debug;
	mod_set.ignore_dlopen_errors = TRUE;

	modules = module_dir_load_missing(modules, DOVEADM_MODULEDIR,
					  NULL, &mod_set);
	module_dir_init(modules);
}

void doveadm_unload_modules(void)
{
	module_dir_unload(&modules);
}

bool doveadm_has_unloaded_plugin(const char *name)
{
	struct module *module;
	DIR *dir;
	struct dirent *d;
	const char *plugin_name;
	unsigned int name_len = strlen(name);
	bool found = FALSE;

	/* first check that it's not actually loaded */
	for (module = modules; module != NULL; module = module->next) {
		if (strcmp(module_get_plugin_name(module), name) == 0)
			return FALSE;
	}

	dir = opendir(DOVEADM_MODULEDIR);
	if (dir == NULL)
		return FALSE;

	while ((d = readdir(dir)) != NULL) {
		plugin_name = module_file_get_name(d->d_name);
		if (strncmp(plugin_name, "doveadm_", 8) == 0)
			plugin_name += 8;

		if (strncmp(plugin_name, name, name_len) == 0 &&
		    (plugin_name[name_len] == '\0' ||
		     strcmp(plugin_name + name_len, "_plugin") == 0)) {
			found = TRUE;
			break;
		}
	}
	(void)closedir(dir);
	return found;
}

const char *unixdate2str(time_t timestamp)
{
	static char buf[64];
	struct tm *tm;

	tm = localtime(&timestamp);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
	return buf;
}

const char *doveadm_plugin_getenv(const char *name)
{
	const char *const *envs;
	unsigned int i, count;

	if (!array_is_created(&doveadm_settings->plugin_envs))
		return NULL;

	envs = array_get(&doveadm_settings->plugin_envs, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(envs[i], name) == 0)
			return envs[i+1];
	}
	return NULL;
}

static bool
parse_hostport(const char *str, const char **host_r, unsigned int *port_r)
{
	const char *p;

	/* host:port */
	p = strrchr(str, ':');
	if (p == NULL || str_to_uint(p+1, port_r) < 0)
		return FALSE;
	*host_r = t_strdup_until(str, p);

	/* there is any '/' character (unlikely to be found from host names),
	   assume ':' is part of a file path */
	if (strchr(str, '/') != NULL)
		return FALSE;
	return TRUE;
}

int doveadm_connect(const char *path)
{
	struct stat st;
	const char *host;
	struct ip_addr *ips;
	unsigned int port, ips_count;
	int fd, ret;

	if (parse_hostport(path, &host, &port) && stat(path, &st) < 0) {
		/* it's a host:port, connect via TCP */
		ret = net_gethostbyname(host, &ips, &ips_count);
		if (ret != 0) {
			i_fatal("Lookup of host %s failed: %s",
				host, net_gethosterror(ret));
		}
		fd = net_connect_ip_blocking(&ips[0], port, NULL);
		if (fd == -1) {
			i_fatal("connect(%s:%u) failed: %m",
				net_ip2addr(&ips[0]), port);
		}
	} else {
		fd = net_connect_unix(path);
		if (fd == -1)
			i_fatal("net_connect_unix(%s) failed: %m", path);
	}
	return fd;
}
