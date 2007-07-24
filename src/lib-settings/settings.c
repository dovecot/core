/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "strescape.h"
#include "settings.h"

#include <stdio.h>
#include <fcntl.h>

#define SECTION_ERRORMSG "%s (section changed at line %d)"

settings_section_callback_t *null_settings_section_callback = NULL;

static const char *get_bool(const char *value, bool *result)
{
	if (strcasecmp(value, "yes") == 0)
		*result = TRUE;
	else if (strcasecmp(value, "no") == 0)
		*result = FALSE;
	else
		return t_strconcat("Invalid boolean: ", value, NULL);

	return NULL;
}

static const char *get_uint(const char *value, unsigned int *result)
{
	int num;

	if (!sscanf(value, "%i", &num) || num < 0)
		return t_strconcat("Invalid number: ", value, NULL);
	*result = num;
	return NULL;
}

const char *
parse_setting_from_defs(pool_t pool, struct setting_def *defs, void *base,
			const char *key, const char *value)
{
	struct setting_def *def;

	for (def = defs; def->name != NULL; def++) {
		if (strcmp(def->name, key) == 0) {
			void *ptr = STRUCT_MEMBER_P(base, def->offset);

			switch (def->type) {
			case SET_STR:
				*((char **)ptr) = p_strdup(pool, value);
				return NULL;
			case SET_INT:
				/* use %i so we can handle eg. 0600
				   as octal value with umasks */
				return get_uint(value, (unsigned int *) ptr);
			case SET_BOOL:
				return get_bool(value, (bool *) ptr);
			}
		}
	}

	return t_strconcat("Unknown setting: ", key, NULL);
}

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

#undef settings_read
bool settings_read(const char *path, const char *section,
		   settings_callback_t *callback,
		   settings_section_callback_t *sect_callback, void *context)
{
	struct istream *input;
	const char *errormsg, *next_section, *name;
	char *line, *key, *p, quote;
	size_t len;
	int fd, linenum, last_section_line = 0, skip, sections, root_section;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		i_error("Can't open configuration file %s: %m", path);
		return FALSE;
	}

	t_push();

	if (section == NULL) {
		skip = 0;
                next_section = NULL;
	} else {
		skip = 1;
		next_section = t_strcut(section, '/');
	}

	linenum = 0; sections = 0; root_section = 0; errormsg = NULL;
	input = i_stream_create_file(fd, 2048, TRUE);
	for (;;) {
		line = i_stream_read_next_line(input);
		if (line == NULL) {
			/* EOF. Also handle the last line even if it doesn't
			   contain LF. */
			const unsigned char *data;
			size_t size;

			data = i_stream_get_data(input, &size);
			if (size == 0)
				break;
			line = t_strdup_noconst(t_strndup(data, size));
			i_stream_skip(input, size);
		}
		linenum++;

		/* @UNSAFE: line is modified */

		/* skip whitespace */
		while (IS_WHITE(*line))
			line++;

		/* ignore comments or empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		/* strip away comments. pretty kludgy way really.. */
		for (p = line; *p != '\0'; p++) {
			if (*p == '\'' || *p == '"') {
				quote = *p;
				for (p++; *p != quote && *p != '\0'; p++) {
					if (*p == '\\' && p[1] != '\0')
						p++;
				}
				if (*p == '\0')
					break;
			} else if (*p == '#') {
				*p = '\0';
				break;
			}
		}

		/* remove whitespace from end of line */
		len = strlen(line);
		while (IS_WHITE(line[len-1]))
			len--;
		line[len] = '\0';

		/* a) key = value
		   b) section_type [section_name] {
		   c) } */
		key = line;
		while (!IS_WHITE(*line) && *line != '\0' && *line != '=')
			line++;
		if (IS_WHITE(*line)) {
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;
		}

		if (*line == '=') {
			/* a) */
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;

			len = strlen(line);
			if (len > 0 &&
			    ((*line == '"' && line[len-1] == '"') ||
			     (*line == '\'' && line[len-1] == '\''))) {
				line[len-1] = '\0';
				line = str_unescape(line+1);
			}

			errormsg = skip ? NULL :
				callback(key, line, context);
		} else if (strcmp(key, "}") != 0 || *line != '\0') {
			/* b) + errors */
			line[-1] = '\0';

			if (*line == '{')
				name = "";
			else {
				name = line;
				while (!IS_WHITE(*line) && *line != '\0')
					line++;

				if (*line != '\0') {
					*line++ = '\0';
					while (IS_WHITE(*line))
						line++;
				}
			}

			if (*line != '{')
				errormsg = "Expecting '='";
			else {
				last_section_line = linenum;
				sections++;
				if (next_section != NULL &&
				    strcmp(next_section, name) == 0) {
					section += strlen(next_section);
					if (*section == '\0') {
						skip = 0;
						next_section = NULL;
						root_section = sections;
					} else {
						i_assert(*section == '/');
						section++;
						next_section =
							t_strcut(section, '/');
					}
				}

				if (skip > 0)
					skip++;
				else {
					skip = sect_callback == NULL ? 1 :
						!sect_callback(key, name,
							       context,
							       &errormsg);
					if (errormsg != NULL &&
					    last_section_line != 0) {
						errormsg = t_strdup_printf(
							SECTION_ERRORMSG,
							errormsg, linenum);
					}
				}
			}
		} else {
			/* c) */
			if (sections == 0)
				errormsg = "Unexpected '}'";
			else {
				if (skip > 0)
					skip--;
				else {
					sect_callback(NULL, NULL, context,
						      &errormsg);
					if (root_section == sections &&
					    errormsg == NULL) {
						/* we found the section,
						   now quit */
						break;
					}
				}
				last_section_line = linenum;
				sections--;
			}
		}

		if (errormsg != NULL) {
			i_error("Error in configuration file %s line %d: %s",
				path, linenum, errormsg);
			break;
		}
	}

	i_stream_destroy(&input);
	t_pop();

	return errormsg == NULL;
}
