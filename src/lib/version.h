#ifndef VERSION_H
#define VERSION_H

/* Returns TRUE if line contains compatible service name and major version.
   The line is expected to be in format:
   VERSION <tab> service_name <tab> major version <tab> minor version */
bool version_string_verify(const char *line, const char *service_name,
			   unsigned int major_version);
/* Same as version_string_verify(), but return the minor version. */
bool version_string_verify_full(const char *line, const char *service_name,
				unsigned int major_version,
				unsigned int *minor_version_r);
/* Compare number[.number[...]] style version numbers. Assert-crash if the
   version strings are invalid. */
int version_cmp(const char *version1, const char *version2);
/* Returns TRUE if version string is a valid number[.number[...]] string. */
bool version_is_valid(const char *version);

#endif
