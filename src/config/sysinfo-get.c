/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mountpoint.h"
#include "strescape.h"
#include "sysinfo-get.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

static bool readfile(const char *path, const char **data_r)
{
	char buf[1024];
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;
	ret = read(fd, buf, sizeof(buf));
	(void)close(fd);
	if (ret <= 0)
		return FALSE;

	*data_r = t_strndup(buf, ret);
	return TRUE;
}

static bool lsb_distro_get(const char *path, const char **name_r)
{
	const char *data, *const *p, *str, *end;

	if (!readfile(path, &data))
		return FALSE;

	for (p = t_strsplit(data, "\n"); *p != '\0'; p++) {
		if (strncmp(*p, "DISTRIB_DESCRIPTION=", 20) == 0)
			break;
	}
	if (*p == '\0')
		return FALSE;

	str = t_strcut(*p + 20, '\n');
	if (*str != '"')
		*name_r = str;
	else {
		end = strrchr(++str, '"');
		*name_r = str_unescape(p_strdup_until(unsafe_data_stack_pool,
						      str, end));
	}
	return TRUE;
}

static const char *distro_get(void)
{
	static const char *files[] = {
		"", "/etc/redhat-release",
		"", "/etc/SuSE-release",
		"", "/etc/mandriva-release",
		"", "/etc/fedora-release",
		"", "/etc/sourcemage-release",
		"", "/etc/slackware-version",
		"", "/etc/gentoo-release",
		"Debian ", "/etc/debian_version",
		NULL
	};
	const char *name;
	unsigned int i;

	if (lsb_distro_get("/etc/lsb-release", &name))
		return name;
	for (i = 0; files[i] != NULL; i += 2) {
		if (readfile(files[i+1], &name)) {
			return t_strconcat(files[i], t_strcut(name, '\n'),
					   NULL);
		}
	}
	return "";
}

static const char *filesystem_get(const char *mail_location)
{
	struct mountpoint mp;
	const char *path;

	path = strchr(mail_location, ':');
	if (path == NULL)
		path = mail_location;
	else
		path = t_strcut(path + 1, ':');
	if (*path == '~') {
		/* we don't know where users' home dirs are */
		return "";
	}
	path = t_strcut(path, '%');
	if (strlen(path) <= 1)
		return "";

	/* all in all it seems we can support only /<path>/%u style location */
	if (mountpoint_get(path, pool_datastack_create(), &mp) < 0)
		return "";
	return mp.type == NULL ? "" : mp.type;
}

const char *sysinfo_get(const char *mail_location)
{
	const char *distro = "", *fs, *uname_info = "";
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname u;

	if (uname(&u) < 0)
		i_error("uname() failed: %m");
	else {
		uname_info = t_strdup_printf("%s %s %s",
					     u.sysname, u.release, u.machine);
	}
	if (strcmp(u.sysname, "Linux") == 0)
		distro = distro_get();
#endif
	fs = filesystem_get(mail_location);
	if (*uname_info == '\0' && *distro == '\0' && *fs == '\0')
		return "";
	return t_strdup_printf("OS: %s %s %s %s %s", u.sysname, u.release, u.machine, distro, fs);
}
