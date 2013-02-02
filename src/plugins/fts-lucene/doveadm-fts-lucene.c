/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "doveadm-dump.h"
#include "doveadm-fts.h"
#include "lucene-wrapper.h"

#include <stdio.h>
#include <sys/stat.h>

const char *doveadm_fts_lucene_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_fts_lucene_plugin_init(struct module *module);
void doveadm_fts_lucene_plugin_deinit(void);

static void cmd_dump_fts_lucene(int argc ATTR_UNUSED, char *argv[])
{
	struct lucene_index *index;
	struct lucene_index_iter *iter;
	guid_128_t prev_guid;
	const struct lucene_index_record *rec;
	bool first = TRUE;

	memset(&prev_guid, 0, sizeof(prev_guid));
	index = lucene_index_init(argv[1], NULL, NULL);
	iter = lucene_index_iter_init(index);
	while ((rec = lucene_index_iter_next(iter)) != NULL) {
		if (memcmp(prev_guid, rec->mailbox_guid,
			   sizeof(prev_guid)) != 0) {
			if (first)
				first = FALSE;
			else
				printf("\n");
			memcpy(prev_guid, rec->mailbox_guid, sizeof(prev_guid));
			printf("%s: ", guid_128_to_string(prev_guid));
		}
		printf("%u,", rec->uid);
	}
	printf("\n");
	if (lucene_index_iter_deinit(&iter) < 0)
		i_error("Lucene index iteration failed");
	lucene_index_deinit(index);
}

static bool test_dump_fts_lucene(const char *path)
{
	struct stat st;

	path = t_strconcat(path, "/segments.gen", NULL);
	return stat(path, &st) == 0;
}

struct doveadm_cmd_dump doveadm_cmd_dump_fts_lucene = {
	"fts-lucene",
	test_dump_fts_lucene,
	cmd_dump_fts_lucene
};

void doveadm_fts_lucene_plugin_init(struct module *module ATTR_UNUSED)
{
	doveadm_dump_register(&doveadm_cmd_dump_fts_lucene);
}

void doveadm_fts_lucene_plugin_deinit(void)
{
}
