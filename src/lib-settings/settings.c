/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "strescape.h"
#include "settings.h"

#include <stdio.h>
#include <fcntl.h>
#ifdef HAVE_GLOB_H
#  include <glob.h>
#endif

#ifndef GLOB_BRACE
#  define GLOB_BRACE 0
#endif

#define SECTION_ERRORMSG "%s (section changed in %s at line %d)"

struct input_stack {
	struct input_stack *prev;

	struct istream *input;
	const char *path;
	unsigned int linenum;
};

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
parse_setting_from_defs(pool_t pool, const struct setting_def *defs, void *base,
			const char *key, const char *value)
{
	const struct setting_def *def;

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

static const char *
fix_relative_path(const char *path, struct input_stack *input)
{
	const char *p;

	if (*path == '/')
		return path;

	p = strrchr(input->path, '/');
	if (p == NULL)
		return path;

	return t_strconcat(t_strdup_until(input->path, p+1), path, NULL);
}

static int settings_add_include(const char *path, struct input_stack **inputp,
				bool ignore_errors, const char **error_r)
{
	struct input_stack *tmp, *new_input;
	int fd;

	for (tmp = *inputp; tmp != NULL; tmp = tmp->prev) {
		if (strcmp(tmp->path, path) == 0)
			break;
	}
	if (tmp != NULL) {
		*error_r = t_strdup_printf("Recursive include file: %s", path);
		return -1;
	}

	if ((fd = open(path, O_RDONLY)) == -1) {
		if (ignore_errors)
			return 0;

		*error_r = t_strdup_printf("Couldn't open include file %s: %m",
					   path);
		return -1;
	}

	new_input = t_new(struct input_stack, 1);
	new_input->prev = *inputp;
	new_input->path = t_strdup(path);
	new_input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(new_input->input, TRUE);
	*inputp = new_input;
	return 0;
}

static int
settings_include(const char *pattern, struct input_stack **inputp,
		 bool ignore_errors, const char **error_r)
{
#ifdef HAVE_GLOB
	glob_t globbers;
	unsigned int i;

	switch (glob(pattern, GLOB_BRACE, NULL, &globbers)) {
	case 0:
		break;
	case GLOB_NOSPACE:
		*error_r = "glob() failed: Not enough memory";
		return -1;
	case GLOB_ABORTED:
		*error_r = "glob() failed: Read error";
		return -1;
	case GLOB_NOMATCH:
		if (ignore_errors)
			return 0;
		*error_r = "No matches";
		return -1;
	default:
		*error_r = "glob() failed: Unknown error";
		return -1;
	}

	/* iterate throuth the different files matching the globbing */
	for (i = 0; i < globbers.gl_pathc; i++) {
		if (settings_add_include(globbers.gl_pathv[i], inputp,
					 ignore_errors, error_r) < 0)
			return -1;
	}
	globfree(&globbers);
	return 0;
#else
	return settings_add_include(pattern, inputp, ignore_errors, error_r);
#endif
}

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

static bool
settings_read_real(const char *path, const char *section,
		   settings_callback_t *callback,
		   settings_section_callback_t *sect_callback, void *context)
{
	/* pretty horrible code, but v2.0 will have this rewritten anyway.. */
	struct input_stack root, *input;
	const char *errormsg, *next_section, *name, *last_section_path = NULL;
	char *line, *key, *p, quote;
	string_t *full_line;
	size_t len;
	int fd, last_section_line = 0, skip, sections, root_section;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		i_error("Can't open configuration file %s: %m", path);
		return FALSE;
	}

	if (section == NULL) {
		skip = 0;
                next_section = NULL;
	} else {
		skip = 1;
		next_section = t_strcut(section, '/');
	}

	memset(&root, 0, sizeof(root));
	root.path = path;
	input = &root;

	full_line = t_str_new(512);
	sections = 0; root_section = 0; errormsg = NULL;
	input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(input->input, TRUE);
prevfile:
	while ((line = i_stream_read_next_line(input->input)) != NULL) {
		input->linenum++;

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
				if (!IS_WHITE(p[-1])) {
					i_warning("Configuration file %s line %u: "
						  "Ambiguous '#' character in line, treating it as comment. "
						  "Add a space before it to remove this warning.",
						  input->path, input->linenum);
				}
				*p = '\0';
				break;
			}
		}

		/* remove whitespace from end of line */
		len = strlen(line);
		while (IS_WHITE(line[len-1]))
			len--;
		line[len] = '\0';

		if (len > 0 && line[len-1] == '\\') {
			/* continues in next line */
			len--;
			while (IS_WHITE(line[len-1]))
				len--;
			str_append_n(full_line, line, len);
			str_append_c(full_line, ' ');
			continue;
		}
		if (str_len(full_line) > 0) {
			str_append(full_line, line);
			line = str_c_modifiable(full_line);
		}

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

		if (strcmp(key, "!include_try") == 0 ||
		    strcmp(key, "!include") == 0) {
			if (settings_include(fix_relative_path(line, input),
					     &input,
					     strcmp(key, "!include_try") == 0,
					     &errormsg) == 0)
				goto prevfile;
		} else if (*line == '=') {
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
							errormsg,
							last_section_path,
							last_section_line);
					}
				}
				last_section_path = input->path;
				last_section_line = input->linenum;
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
				last_section_path = input->path;
				last_section_line = input->linenum;
				sections--;
			}
		}

		if (errormsg != NULL) {
			i_error("Error in configuration file %s line %d: %s",
				input->path, input->linenum, errormsg);
			break;
		}
		str_truncate(full_line, 0);
	}

	i_stream_destroy(&input->input);
	input = input->prev;
	if (line == NULL && input != NULL)
		goto prevfile;

	return errormsg == NULL;
}

#undef settings_read
bool settings_read(const char *path, const char *section,
		   settings_callback_t *callback,
		   settings_section_callback_t *sect_callback, void *context)
{
	bool ret;

	T_BEGIN {
		ret = settings_read_real(path, section, callback,
					 sect_callback, context);
	} T_END;
	return ret;
}
