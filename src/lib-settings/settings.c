/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "settings.h"

#include <stdio.h>
#include <fcntl.h>

static const char *get_bool(const char *value, int *result)
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
				*((char **) ptr) =
					p_strdup_empty(pool, value);
				return NULL;
			case SET_INT:
				/* use %i so we can handle eg. 0600
				   as octal value with umasks */
				return get_uint(value, (unsigned int *) ptr);
			case SET_BOOL:
				return get_bool(value, (int *) ptr);
			}
		}
	}

	return t_strconcat("Unknown setting: ", key, NULL);
}

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

void settings_read(const char *path, settings_callback_t *callback,
		   void *context)
{
	struct istream *input;
	const char *errormsg;
	char *line, *key;
	int fd, linenum;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal("Can't open configuration file %s: %m", path);

	linenum = 0;
	input = i_stream_create_file(fd, default_pool, 2048, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		linenum++;

		/* @UNSAFE: line is modified */

		/* skip whitespace */
		while (IS_WHITE(*line))
			line++;

		/* ignore comments or empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		/* all lines must be in format "key = value" */
		key = line;
		while (!IS_WHITE(*line) && *line != '\0')
			line++;
		if (IS_WHITE(*line)) {
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;
		}

		if (*line != '=') {
			errormsg = "Missing value";
		} else {
			/* skip whitespace after '=' */
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;

			errormsg = callback(key, line, context);
		}

		if (errormsg != NULL) {
			i_fatal("Error in configuration file %s line %d: %s",
				path, linenum, errormsg);
		}
	};

	i_stream_unref(input);
}
