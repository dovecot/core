/* Copyright (c) 2005-2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "version.h"

bool version_string_verify(const char *line, const char *service_name,
			   unsigned int major_version)
{
	unsigned int minor_version;

	return version_string_verify_full(line, service_name,
					  major_version, &minor_version);
}

bool version_string_verify_full(const char *line, const char *service_name,
				unsigned int major_version,
				unsigned int *minor_version_r)
{
	size_t service_name_len = strlen(service_name);
	bool ret;

	if (!str_begins(line, "VERSION\t", &line))
		return FALSE;

	if (strncmp(line, service_name, service_name_len) != 0 ||
	    line[service_name_len] != '\t')
		return FALSE;
	line += service_name_len + 1;

	T_BEGIN {
		const char *p = strchr(line, '\t');

		if (p == NULL)
			ret = FALSE;
		else {
			ret = str_uint_equals(t_strdup_until(line, p),
					      major_version);
			if (str_to_uint(p+1, minor_version_r) < 0)
				ret = FALSE;
		}
	} T_END;
	return ret;
}

int version_cmp(const char *version1, const char *version2)
{
	unsigned int v1, v2;

	do {
		if (str_parse_uint(version1, &v1, &version1) < 0)
			i_unreached();
		if (str_parse_uint(version2, &v2, &version2) < 0)
			i_unreached();
		if (*version1 == '.')
			version1++;
		else
			i_assert(*version1 == '\0');
		if (*version2 == '.')
			version2++;
		else
			i_assert(*version2 == '\0');

		if (v1 < v2)
			return -1;
		if (v1 > v2)
			return 1;
	} while (*version1 != '\0' && *version2 != '\0');

	if (*version1 != '\0')
		return 1;
	if (*version2 != '\0')
		return -1;
	return 0;
}

bool version_is_valid(const char *version)
{
	unsigned int i;

	for (i = 0; version[i] != '\0'; i++) {
		if (version[i] == '.') {
			if (i == 0 || version[i-1] == '.' ||
			    version[i+1] == '\0')
				return FALSE;
		} else if (version[i] < '0' || version[i] > '9')
			return FALSE;
	}
	return i > 0;
}

