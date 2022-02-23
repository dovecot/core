/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "doveadm-dump.h"
#include "doveadm-print.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"
#include "doveadm-dump-flatcurve.h"

#define HEADER_TERMS TRUE
#define PAYLOAD_TERMS !HEADER_TERMS

ARRAY_DEFINE_TYPE(fts_flatcurve_dump_term, struct fts_flatcurve_dump_term *);
struct fts_flatcurve_dump_term {
	bool header;
	const char *term;
	unsigned int count;
};

static int
cmd_fts_flatcurve_dump_sort(struct fts_flatcurve_dump_term *const *p_lhs,
			    struct fts_flatcurve_dump_term *const *p_rhs)
{
	const struct fts_flatcurve_dump_term *lhs = *p_lhs;
	const struct fts_flatcurve_dump_term *rhs = *p_rhs;

	int ret;

	ret = (int)rhs->count - (int)lhs->count;
	if (ret != 0) return ret;

	ret = (int)rhs->header - (int)lhs->header;
	if (ret != 0) return ret;

	ret = strcmp(lhs->term, rhs->term);
	return ret;
}

static void
cmd_fts_flatcurve_dump_array_push(bool header,
				  HASH_TABLE_TYPE(term_counter) *hterms,
				  ARRAY_TYPE(fts_flatcurve_dump_term) *aterms)
{
	char *key;
	void *val;
	struct fts_flatcurve_dump_term *term;
	struct hash_iterate_context *iter = hash_table_iterate_init(*hterms);
	while (hash_table_iterate(iter, *hterms, &key, &val)) {
		term = t_new(struct fts_flatcurve_dump_term, 1);
		term->header = header;
		term->term   = key;
		term->count  = POINTER_CAST_TO(val, unsigned int);
		array_push_back(aterms, &term);
	}
	hash_table_iterate_deinit(&iter);
}

static int
cmd_dump_fts_flatcurve_dump_terms(bool headers, const char *path,
				  ARRAY_TYPE(fts_flatcurve_dump_term) *aterms,
				  const char **error_r)
{
	HASH_TABLE_TYPE(term_counter) hterms;
	hash_table_create(&hterms, pool_datastack_create(), 256, str_hash, strcmp);
	int ret = fts_flatcurve_database_terms(headers, path, &hterms, error_r);
	cmd_fts_flatcurve_dump_array_push(headers, &hterms, aterms);
	hash_table_destroy(&hterms);
	return ret;
}

static void
cmd_dump_fts_flatcurve_print_terms(ARRAY_TYPE(fts_flatcurve_dump_term) *terms)
{
	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("terms", "terms", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);

	struct fts_flatcurve_dump_term *term;
	array_foreach_elem(terms, term) {
		T_BEGIN {
			doveadm_print(t_strdup_printf(
				"%s(%u)\t%s",
				term->header ? "H": "P",
				term->count, term->term));
		} T_END;
	}
	doveadm_print_deinit();
}

static void
cmd_dump_fts_flatcurve_bundle(const char *arg_path,
			      const char *const *args ATTR_UNUSED)
{
	T_BEGIN {
		const char *index_path, *error;
		if (fts_flatcurve_database_locate_dir(
			arg_path, &index_path, &error) < 0)
			i_fatal("Can't use filename as FTS: %s - %s",
				arg_path, error);

		ARRAY_TYPE(fts_flatcurve_dump_term) terms;
		t_array_init(&terms, 256);

		if (cmd_dump_fts_flatcurve_dump_terms(
			HEADER_TERMS, index_path, &terms, &error) < 0)
			i_fatal("%s", error);

		if (cmd_dump_fts_flatcurve_dump_terms(
			PAYLOAD_TERMS, index_path, &terms, &error) < 0)
			i_fatal("%s", error);

		array_sort(&terms, cmd_fts_flatcurve_dump_sort);
		cmd_dump_fts_flatcurve_print_terms(&terms);
	} T_END;
}

static bool
test_dump_fts_flatcurve_bundle(const char *arg_path)
{
	bool located;
	T_BEGIN {
		const char *index_path, *error;
		located = fts_flatcurve_database_locate_dir(
				arg_path, &index_path, &error) == 0;
	} T_END;
	return located;
}

static const struct doveadm_cmd_dump doveadm_cmd_dump_fts_flatcurve_bundle = {
	FTS_FLATCURVE_LABEL,
	test_dump_fts_flatcurve_bundle,
	cmd_dump_fts_flatcurve_bundle
};

void doveadm_dump_flatcurve_init(void)
{
	doveadm_dump_register(&doveadm_cmd_dump_fts_flatcurve_bundle);
}
