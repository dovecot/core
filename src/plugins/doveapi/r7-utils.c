/* Copyright (c) 2025 R7-Office owners, author Talipov Ilja
 * [https://github.com/GromySkynet] */

#include "lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #include <jansson.h>

char *execute(const char *path, const char *const argv[])
{
	FILE *fp;
	char *buffer = NULL;
	size_t buffer_size = 0;
	size_t total_size = 0;
	char chunk[4096];

	fp = popen(path "2>/dev/null", "r");

	(void)execv(path, argv_drop_const(argv));
	i_fatal_status(
		errno == ENOMEM ? FATAL_OUTOFMEM : FATAL_EXEC,
		"execv(%s) failed: %m",
		path);
}

char *execute_lsblk()
{
	FILE *fp;
	char *buffer = NULL;
	size_t buffer_size = 0;
	size_t total_size = 0;
	char chunk[4096];

	fp =
		popen("lsblk -JO"
	              "2>/dev/null",
	              "r");
	if (!fp) {
		fprintf(stderr, "Error: Failed to execute lsblk command\n");
		return NULL;
	}

	while (fgets(chunk, sizeof(chunk), fp) != NULL) {
		size_t chunk_size = strlen(chunk);
		char *new_buffer = realloc(buffer, total_size + chunk_size + 1);
		if (!new_buffer) {
			free(buffer);
			pclose(fp);
			return NULL;
		}
		buffer = new_buffer;
		memcpy(buffer + total_size, chunk, chunk_size);
		total_size += chunk_size;
	}

	if (buffer) {
		buffer[total_size] = '\0';
	}

	int status = pclose(fp);
	if (status != 0) {
		free(buffer);
		fprintf(stderr,
		        "Error: lsblk command failed with status %d\n",
		        status);
		return NULL;
	}

	return buffer;
}