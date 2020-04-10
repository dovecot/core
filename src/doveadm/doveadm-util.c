/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "time-util.h"
#include "master-service.h"
#include "module-dir.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"
#include "doveadm-util.h"

#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

bool doveadm_verbose = FALSE, doveadm_debug = FALSE, doveadm_server = FALSE;
static struct module *modules = NULL;

void doveadm_load_modules(void)
{
	struct module_dir_load_settings mod_set;

	/* some doveadm plugins have dependencies to mail plugins. we can load
	   only those whose dependencies have been loaded earlier, the rest are
	   ignored. */
	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
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
	size_t name_len = strlen(name);
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
		(void)str_begins(plugin_name, "doveadm_", &plugin_name);

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
	return t_strflocaltime("%Y-%m-%d %H:%M:%S", timestamp);
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

static int
doveadm_tcp_connect_port(const char *host, in_port_t port)
{
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret, fd;

	alarm(DOVEADM_TCP_CONNECT_TIMEOUT_SECS);
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
	alarm(0);
	return fd;
}

int doveadm_tcp_connect(const char *target, in_port_t default_port)
{
	const char *host;
	in_port_t port;

	if (net_str2hostport(target, default_port, &host, &port) < 0) {
		i_fatal("Port not known for %s. Either set proxy_port "
			"or use %s:port", target, target);
	}
	return doveadm_tcp_connect_port(host, port);
}

int doveadm_connect_with_default_port(const char *path,
				      in_port_t default_port)
{
	int fd;

	/* we'll assume UNIX sockets typically have an absolute path,
	   or at the very least '/' somewhere. */
	if (strchr(path, '/') == NULL)
		fd = doveadm_tcp_connect(path, default_port);
	else {
		fd = net_connect_unix(path);
		if (fd == -1)
			i_fatal("net_connect_unix(%s) failed: %m", path);
	}
	return fd;
}

int doveadm_connect(const char *path)
{
	return doveadm_connect_with_default_port(path, 0);
}

int doveadm_blocking_connect(const char *path,
			     const struct connection_settings *set,
			     struct istream **input_r,
			     struct ostream **output_r, const char **error_r)
{
	const char *line;
	int ret = 0;

	int fd = net_connect_unix(path);
	if (fd == -1) {
		*error_r = t_strdup_printf(
			"net_connect_unix(%s) failed: %m", path);
		return -1;
	}
	net_set_nonblock(fd, FALSE);
	*output_r = o_stream_create_fd_blocking(fd);
	o_stream_set_name(*output_r, path);

	if (!set->dont_send_version && set->service_name_out != NULL &&
	    set->major_version != 0) {
		const char *str = t_strdup_printf("VERSION\t%s\t%u\t%u\n",
			set->service_name_out,
			set->major_version, set->minor_version);
		o_stream_nsend_str(*output_r, str);
	}

	*input_r = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	i_stream_set_name(*input_r, path);
	if (set->service_name_in != NULL) {
		alarm(DOVEADM_HANDSHAKE_TIMEOUT_SECS);
		if ((line = i_stream_read_next_line(*input_r)) == NULL) {
			*error_r = t_strdup_printf("read(%s) failed: %s",
				path, i_stream_get_error(*input_r));
			ret = -1;
		} else if (!version_string_verify(line, set->service_name_in,
						  set->major_version)) {
			*error_r = t_strdup_printf(
				"%s is not a compatible socket "
				"(wanted %s v%u, received: %s)", path,
				set->service_name_in, set->major_version, line);
			ret = -1;
		}
		alarm(0);
	}
	if (ret < 0) {
		o_stream_destroy(output_r);
		i_stream_destroy(input_r);
	}
	return ret;
}

int i_strccdascmp(const char *a, const char *b)
{
	while(*a != '\0' && *b != '\0') {
		if ((*a == ' ' || *a == '-') && *a != *b && *b != ' ' && *b != '-') {
			if (i_toupper(*(a+1)) == *(b)) a++;
			else break;
		} else if ((*b == ' ' || *b == '-') && *a != *b && *a != ' ' && *a != '-') {
			if (*a == i_toupper(*(b+1))) b++;
			else break;
		} else if (!((*a == ' ' || *a == '-') &&
			     (*b == ' ' || *b == '-')) &&
			    (*a != *b)) break;
		a++; b++;
	}
	return *a-*b;
}
