/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "test-common.h"
#include "acl-api-private.h"

/* all_mailbox_rights[], sorted the way acl_right_names_parse() returns them */
#define TEST_ACL_RIGHTS_ALL_SORTED \
	"admin create delete expunge insert lookup post read write " \
	"write-deleted write-seen"
/* the same rights in acl_letter_map[] order */
#define TEST_ACL_LETTERS_ALL "lrwstipekxa"

/* NULL-terminated const char *const[] literal for table-driven tests */
#define TEST_RIGHTS(...) ((const char *const []){ __VA_ARGS__, NULL })

static const char *rights_str(const char *const *rights)
{
	return rights == NULL ? "(null)" : t_strarray_join(rights, " ");
}

static const char *test_strrepeat(char c, unsigned int count)
{
	char *str = t_malloc0(count + 1);

	memset(str, c, count);
	return str;
}

static void test_acl_identifier_parse(void)
{
	static const struct {
		const char *line;
		enum acl_id_type id_type;
		const char *identifier;
	} tests[] = {
		{ "anyone", ACL_ID_ANYONE, NULL },
		{ "anonymous", ACL_ID_ANYONE, NULL },
		{ "authenticated", ACL_ID_AUTHENTICATED, NULL },
		{ "owner", ACL_ID_OWNER, NULL },
		{ "user=foo", ACL_ID_USER, "foo" },
		{ "user=", ACL_ID_USER, "" },
		{ "group=g1", ACL_ID_GROUP, "g1" },
		{ "group-override=g2", ACL_ID_GROUP_OVERRIDE, "g2" },
	};
	static const char *const invalid_tests[] = {
		"", "foo", "Owner", "User=foo", "group_override=g",
		"owners", "anyones",
	};
	struct acl_rights rights;

	test_begin("acl_identifier_parse()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		i_zero(&rights);
		test_assert_idx(acl_identifier_parse(tests[i].line,
						     &rights) == 0, i);
		test_assert_cmp_idx(rights.id_type, ==, tests[i].id_type, i);
		test_assert_strcmp_idx(rights.identifier,
				       tests[i].identifier, i);
	}
	for (unsigned int i = 0; i < N_ELEMENTS(invalid_tests); i++) {
		i_zero(&rights);
		test_assert_idx(acl_identifier_parse(invalid_tests[i],
						     &rights) < 0, i);
	}
	test_end();
}

static void test_acl_right_names_parse(void)
{
	static const struct {
		const char *acl;
		const char *rights;
	} tests[] = {
		{ "", "" },
		{ "  ", "" },
		{ "l", "lookup" },
		{ "lr", "lookup read" },
		/* the result is sorted and deduplicated */
		{ "rl", "lookup read" },
		{ "lrl", "lookup read" },
		{ "\tlr  ", "lookup read" },
		{ TEST_ACL_LETTERS_ALL, TEST_ACL_RIGHTS_ALL_SORTED },
		/* named (non-standard) rights */
		{ ":custom", "custom" },
		{ "lr :b,a", "a b lookup read" },
		{ "l :x x", "lookup x" },
		{ "l :x\ty", "lookup x y" },
	};
	static const struct {
		const char *acl;
		const char *error;
	} error_tests[] = {
		{ "z", "Unknown ACL 'z'" },
		{ "lrz", "Unknown ACL 'z'" },
		{ "lr x", "Missing ':' prefix in ACL extensions" },
	};
	pool_t pool = pool_alloconly_create("test acl right names", 1024);
	const char *const *rights;
	const char *error;

	test_begin("acl_right_names_parse()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		error = NULL;
		rights = acl_right_names_parse(pool, tests[i].acl, &error);
		test_assert_idx(rights != NULL, i);
		if (rights != NULL)
			test_assert_strcmp_idx(rights_str(rights),
					       tests[i].rights, i);
	} T_END;
	for (unsigned int i = 0; i < N_ELEMENTS(error_tests); i++) T_BEGIN {
		error = NULL;
		rights = acl_right_names_parse(pool, error_tests[i].acl,
					       &error);
		test_assert_idx(rights == NULL, i);
		test_assert_strcmp_idx(error, error_tests[i].error, i);
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_right_names_write(void)
{
	const struct {
		const char *const *rights;
		const char *acl;
	} tests[] = {
		{ empty_str_array, "" },
		{ TEST_RIGHTS("lookup"), "l" },
		{ TEST_RIGHTS("lookup", "read"), "lr" },
		{ TEST_RIGHTS("read", "lookup"), "rl" },
		{ TEST_RIGHTS("lookup", "custom"), "l :custom" },
		{ TEST_RIGHTS("lookup", "c1", "c2"), "l :c1 c2" },
		{ TEST_RIGHTS(MAIL_ACL_ADMIN), "a" },
	};
	string_t *str = t_str_new(64);

	test_begin("acl_right_names_write()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		acl_right_names_write(str, tests[i].rights);
		test_assert_strcmp_idx(str_c(str), tests[i].acl, i);
	}
	test_end();
}

static void test_acl_right_names_roundtrip(void)
{
	static const char *const tests[] = {
		"", "l", "lr", TEST_ACL_LETTERS_ALL,
	};
	pool_t pool = pool_alloconly_create("test acl roundtrip", 1024);
	const char *const *rights;
	const char *error;
	string_t *str = t_str_new(64);

	test_begin("acl right names write/parse roundtrip");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		/* letters -> names -> letters. The second letter string is
		   sorted by right name, so parse it once more to compare
		   against a stable form. */
		error = NULL;
		rights = acl_right_names_parse(pool, tests[i], &error);
		test_assert_idx(rights != NULL, i);
		if (rights != NULL) {
			str_truncate(str, 0);
			acl_right_names_write(str, rights);

			const char *const *rights2 =
				acl_right_names_parse(pool, str_c(str), &error);
			test_assert_idx(rights2 != NULL, i);
			if (rights2 != NULL) {
				test_assert_strcmp_idx(rights_str(rights),
						       rights_str(rights2), i);
			}
		}
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_rights_parse_line(void)
{
	static const struct {
		const char *line;
		enum acl_id_type id_type;
		const char *identifier;
		const char *rights;
		const char *neg_rights;
	} tests[] = {
		{ "user=foo lr", ACL_ID_USER, "foo",
		  "lookup read", "(null)" },
		/* no rights at all is not the same as no rights entry */
		{ "user=foo", ACL_ID_USER, "foo", "", "(null)" },
		{ "owner "TEST_ACL_LETTERS_ALL, ACL_ID_OWNER, NULL,
		  TEST_ACL_RIGHTS_ALL_SORTED, "(null)" },
		{ "anyone l", ACL_ID_ANYONE, NULL, "lookup", "(null)" },
		{ "anonymous l", ACL_ID_ANYONE, NULL, "lookup", "(null)" },
		{ "authenticated lr", ACL_ID_AUTHENTICATED, NULL,
		  "lookup read", "(null)" },
		{ "group=g1 lr", ACL_ID_GROUP, "g1",
		  "lookup read", "(null)" },
		{ "group-override=g2 a", ACL_ID_GROUP_OVERRIDE, "g2",
		  "admin", "(null)" },
		/* '-' prefix makes the rights negative */
		{ "-user=foo lr", ACL_ID_USER, "foo",
		  "(null)", "lookup read" },
		/* identifiers with spaces are quoted */
		{ "\"user=foo bar\" lr", ACL_ID_USER, "foo bar",
		  "lookup read", "(null)" },
		{ "\"-user=foo bar\" lr", ACL_ID_USER, "foo bar",
		  "(null)", "lookup read" },
		{ "\"user=foo\\\\bar\" l", ACL_ID_USER, "foo\\bar",
		  "lookup", "(null)" },
		{ "\"user=foo\"", ACL_ID_USER, "foo", "", "(null)" },
		/* named rights */
		{ "user=foo lr :custom", ACL_ID_USER, "foo",
		  "custom lookup read", "(null)" },
	};
	pool_t pool = pool_alloconly_create("test acl parse line", 1024);
	struct acl_rights rights;
	const char *error;

	test_begin("acl_rights_parse_line()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		error = NULL;
		test_assert_idx(acl_rights_parse_line(tests[i].line, pool,
						      &rights, &error) == 0, i);
		test_assert_cmp_idx(rights.id_type, ==, tests[i].id_type, i);
		test_assert_strcmp_idx(rights.identifier,
				       tests[i].identifier, i);
		test_assert_strcmp_idx(rights_str(rights.rights),
				       tests[i].rights, i);
		test_assert_strcmp_idx(rights_str(rights.neg_rights),
				       tests[i].neg_rights, i);
		test_assert_idx(!rights.global, i);
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_rights_parse_line_errors(void)
{
	static const struct {
		const char *line;
		const char *error;
	} tests[] = {
		{ "", "Unknown ID ''" },
		{ "foo lr", "Unknown ID 'foo'" },
		{ "user=foo z", "Unknown ACL 'z'" },
		{ "user=foo lr x", "Missing ':' prefix in ACL extensions" },
		{ "\"user=foo lr", "Invalid quoted ID" },
		{ "\"user=foo\"x l", "Invalid quoted ID" },
	};
	pool_t pool = pool_alloconly_create("test acl parse errors", 1024);
	struct acl_rights rights;
	const char *error;

	test_begin("acl_rights_parse_line() errors");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		error = NULL;
		test_assert_idx(acl_rights_parse_line(tests[i].line, pool,
						      &rights, &error) < 0, i);
		test_assert_strcmp_idx(error, tests[i].error, i);
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_rights_get_id(void)
{
	static const struct {
		enum acl_id_type id_type;
		const char *identifier;
		const char *id;
	} tests[] = {
		{ ACL_ID_ANYONE, NULL, "anyone" },
		{ ACL_ID_AUTHENTICATED, NULL, "authenticated" },
		{ ACL_ID_OWNER, NULL, "owner" },
		{ ACL_ID_USER, "foo", "user=foo" },
		{ ACL_ID_GROUP, "g1", "group=g1" },
		{ ACL_ID_GROUP_OVERRIDE, "g2", "group-override=g2" },
	};
	test_begin("acl_rights_get_id()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		struct acl_rights rights = {
			.id_type = tests[i].id_type,
			.identifier = tests[i].identifier,
		};
		test_assert_strcmp_idx(acl_rights_get_id(&rights),
				       tests[i].id, i);
	} T_END;
	test_end();
}

static void test_acl_rights_export(void)
{
	const struct {
		const char *const *rights;
		const char *const *neg_rights;
		const char *str;
	} tests[] = {
		{ NULL, NULL, "" },
		{ empty_str_array, NULL, "" },
		{ NULL, empty_str_array, "" },
		{ TEST_RIGHTS("lookup", "read"), NULL, "lookup read" },
		{ NULL, TEST_RIGHTS("lookup"), "-lookup" },
		{ TEST_RIGHTS("insert"), TEST_RIGHTS("lookup", "read"),
		  "insert -lookup -read" },
	};
	test_begin("acl_rights_export()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		struct acl_rights rights = {
			.rights = tests[i].rights,
			.neg_rights = tests[i].neg_rights,
		};
		test_assert_strcmp_idx(acl_rights_export(&rights),
				       tests[i].str, i);
	} T_END;
	test_end();
}

static void test_acl_rights_update_import(void)
{
	const struct {
		const char *id;
		const char *const *rights;
		enum acl_id_type id_type;
		const char *out_rights;
		const char *out_neg_rights;
		enum acl_modify_mode modify_mode;
		enum acl_modify_mode neg_modify_mode;
	} tests[] = {
		{ "user=foo", TEST_RIGHTS("lookup", "read"), ACL_ID_USER,
		  "lookup read", "(null)",
		  ACL_MODIFY_MODE_REPLACE, ACL_MODIFY_MODE_CLEAR },
		{ "owner", TEST_RIGHTS("all"), ACL_ID_OWNER,
		  "lookup read write write-seen write-deleted insert post "
		  "expunge create delete admin", "(null)",
		  ACL_MODIFY_MODE_REPLACE, ACL_MODIFY_MODE_CLEAR },
		{ "user=foo", TEST_RIGHTS("-lookup"), ACL_ID_USER,
		  "(null)", "lookup",
		  ACL_MODIFY_MODE_CLEAR, ACL_MODIFY_MODE_REPLACE },
		{ "user=foo", TEST_RIGHTS("read", "-lookup"), ACL_ID_USER,
		  "read", "lookup",
		  ACL_MODIFY_MODE_REPLACE, ACL_MODIFY_MODE_REPLACE },
		/* ':' prefix allows non-standard rights */
		{ "user=foo", TEST_RIGHTS(":custom"), ACL_ID_USER,
		  "custom", "(null)",
		  ACL_MODIFY_MODE_REPLACE, ACL_MODIFY_MODE_CLEAR },
		/* NULL rights clears everything */
		{ "user=foo", NULL, ACL_ID_USER, "(null)", "(null)",
		  ACL_MODIFY_MODE_CLEAR, ACL_MODIFY_MODE_CLEAR },
		/* an empty list clears as well */
		{ "user=foo", empty_str_array, ACL_ID_USER,
		  "(null)", "(null)",
		  ACL_MODIFY_MODE_CLEAR, ACL_MODIFY_MODE_CLEAR },
	};
	const struct {
		const char *id;
		const char *const *rights;
		const char *error;
	} error_tests[] = {
		{ "foo", empty_str_array, "Invalid ID: foo" },
		{ "user=foo", TEST_RIGHTS("bogus"), "Invalid right 'bogus'" },
		{ "user=foo", TEST_RIGHTS("-bogus"), "Invalid right 'bogus'" },
	};
	test_begin("acl_rights_update_import()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		struct acl_rights_update update = {
			.modify_mode = ACL_MODIFY_MODE_REPLACE,
			.neg_modify_mode = ACL_MODIFY_MODE_REPLACE,
		};
		const char *error = NULL;

		test_assert_idx(acl_rights_update_import(&update, tests[i].id,
							 tests[i].rights,
							 &error) == 0, i);
		test_assert_cmp_idx(update.rights.id_type, ==,
				    tests[i].id_type, i);
		test_assert_strcmp_idx(rights_str(update.rights.rights),
				       tests[i].out_rights, i);
		test_assert_strcmp_idx(rights_str(update.rights.neg_rights),
				       tests[i].out_neg_rights, i);
		test_assert_cmp_idx(update.modify_mode, ==,
				    tests[i].modify_mode, i);
		test_assert_cmp_idx(update.neg_modify_mode, ==,
				    tests[i].neg_modify_mode, i);
	} T_END;
	for (unsigned int i = 0; i < N_ELEMENTS(error_tests); i++) T_BEGIN {
		struct acl_rights_update update = {
			.modify_mode = ACL_MODIFY_MODE_REPLACE,
			.neg_modify_mode = ACL_MODIFY_MODE_REPLACE,
		};
		const char *error = NULL;

		test_assert_idx(acl_rights_update_import(&update,
							 error_tests[i].id,
							 error_tests[i].rights,
							 &error) < 0, i);
		test_assert_strcmp_idx(error, error_tests[i].error, i);
	} T_END;
	test_end();
}

static void test_acl_right_names_merge(void)
{
	const struct {
		const char *const *dest;
		const char *const *src;
		const char *result;
	} tests[] = {
		{ NULL, NULL, "" },
		{ NULL, TEST_RIGHTS("b", "a"), "a b" },
		{ TEST_RIGHTS("a"), NULL, "a" },
		{ TEST_RIGHTS("a"), TEST_RIGHTS("b"), "a b" },
		/* duplicates are dropped */
		{ TEST_RIGHTS("a", "b"), TEST_RIGHTS("b", "c"),
		  "a b c" },
	};
	pool_t pool = pool_alloconly_create("test acl merge", 1024);

	test_begin("acl_right_names_merge()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		const char *const *dest = tests[i].dest;

		acl_right_names_merge(pool, &dest, tests[i].src, TRUE);
		test_assert_strcmp_idx(rights_str(dest), tests[i].result, i);
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_right_names_modify(void)
{
	const struct {
		const char *const *rights;
		const char *const *modify_rights;
		enum acl_modify_mode modify_mode;
		const char *result;
		bool changed;
	} tests[] = {
		{ NULL, TEST_RIGHTS("a"), ACL_MODIFY_MODE_ADD,
		  "a", TRUE },
		{ TEST_RIGHTS("a"), TEST_RIGHTS("b"),
		  ACL_MODIFY_MODE_ADD, "a b", TRUE },
		{ TEST_RIGHTS("a"), TEST_RIGHTS("a"),
		  ACL_MODIFY_MODE_ADD, "a", FALSE },
		{ TEST_RIGHTS("a", "b"), TEST_RIGHTS("a"),
		  ACL_MODIFY_MODE_REMOVE, "b", TRUE },
		{ TEST_RIGHTS("a"), TEST_RIGHTS("b"),
		  ACL_MODIFY_MODE_REMOVE, "a", FALSE },
		/* removing from a nonexistent set does nothing */
		{ NULL, TEST_RIGHTS("a"), ACL_MODIFY_MODE_REMOVE,
		  "(null)", FALSE },
		{ TEST_RIGHTS("a", "b"), TEST_RIGHTS("c"),
		  ACL_MODIFY_MODE_REPLACE, "c", TRUE },
		{ TEST_RIGHTS("a"), TEST_RIGHTS("a"),
		  ACL_MODIFY_MODE_REPLACE, "a", FALSE },
		{ TEST_RIGHTS("a"), NULL, ACL_MODIFY_MODE_CLEAR,
		  "(null)", TRUE },
		{ NULL, NULL, ACL_MODIFY_MODE_CLEAR, "(null)", FALSE },
		/* NULL modify_rights is a no-op unless clearing */
		{ TEST_RIGHTS("a"), NULL, ACL_MODIFY_MODE_ADD,
		  "a", FALSE },
		{ TEST_RIGHTS("a"), NULL, ACL_MODIFY_MODE_REMOVE,
		  "a", FALSE },
	};
	pool_t pool = pool_alloconly_create("test acl modify", 1024);

	test_begin("acl_right_names_modify()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		const char *const *rights = tests[i].rights;
		bool changed;

		changed = acl_right_names_modify(pool, &rights,
						 tests[i].modify_rights,
						 tests[i].modify_mode);
		test_assert_strcmp_idx(rights_str(rights), tests[i].result, i);
		test_assert_idx(changed == tests[i].changed, i);
	} T_END;
	pool_unref(&pool);
	test_end();
}

static void test_acl_rights_cmp(void)
{
	struct acl_rights local_anyone = { .id_type = ACL_ID_ANYONE };
	struct acl_rights local_user_a = {
		.id_type = ACL_ID_USER, .identifier = "a",
	};
	struct acl_rights local_user_b = {
		.id_type = ACL_ID_USER, .identifier = "b",
	};
	struct acl_rights global_anyone = {
		.id_type = ACL_ID_ANYONE, .global = TRUE,
	};

	test_begin("acl_rights_cmp()");
	/* locals sort before globals regardless of the id type */
	test_assert(acl_rights_cmp(&local_user_b, &global_anyone) < 0);
	test_assert(acl_rights_cmp(&global_anyone, &local_user_b) > 0);
	/* otherwise by id type */
	test_assert(acl_rights_cmp(&local_anyone, &local_user_a) < 0);
	test_assert(acl_rights_cmp(&local_user_a, &local_anyone) > 0);
	/* and finally by identifier */
	test_assert(acl_rights_cmp(&local_user_a, &local_user_b) < 0);
	test_assert(acl_rights_cmp(&local_user_a, &local_user_a) == 0);
	/* the rights themselves are not part of the comparison */
	struct acl_rights local_user_a2 = local_user_a;
	local_user_a2.rights = TEST_RIGHTS("lookup");
	test_assert(acl_rights_cmp(&local_user_a, &local_user_a2) == 0);
	test_end();
}

static void test_acl_rights_has_nonowner_lookup_changes(void)
{
	const struct {
		enum acl_id_type id_type;
		const char *const *rights;
		bool result;
	} tests[] = {
		/* owner's rights never affect non-owner lookups */
		{ ACL_ID_OWNER, TEST_RIGHTS("lookup"), FALSE },
		{ ACL_ID_USER, NULL, FALSE },
		{ ACL_ID_USER, empty_str_array, FALSE },
		{ ACL_ID_USER, TEST_RIGHTS("read"), FALSE },
		{ ACL_ID_USER, TEST_RIGHTS("lookup"), TRUE },
		{ ACL_ID_ANYONE, TEST_RIGHTS("read", "lookup"), TRUE },
	};
	test_begin("acl_rights_has_nonowner_lookup_changes()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		struct acl_rights rights = {
			.id_type = tests[i].id_type,
			.rights = tests[i].rights,
		};
		test_assert_idx(acl_rights_has_nonowner_lookup_changes(
					&rights) == tests[i].result, i);
	}
	test_end();
}

static void test_acl_id_is_valid(void)
{
	test_begin("acl_id_is_valid()");
	test_assert(acl_id_is_valid(""));
	test_assert(acl_id_is_valid("user=foo"));
	test_assert(acl_id_is_valid("user=foo bar"));
	/* valid UTF-8 is fine */
	test_assert(acl_id_is_valid("user=\xc3\xa4"));
	/* invalid UTF-8 is not */
	test_assert(!acl_id_is_valid("user=\xff"));
	/* control characters are not allowed */
	test_assert(!acl_id_is_valid("user=\x01"));
	test_assert(!acl_id_is_valid("user=foo\nbar"));
	/* length limit */
	test_assert(acl_id_is_valid(test_strrepeat('a', ACL_ID_MAX_LEN)));
	test_assert(!acl_id_is_valid(test_strrepeat('a', ACL_ID_MAX_LEN + 1)));
	test_end();
}

static void test_acl_rights_dup(void)
{
	pool_t pool = pool_alloconly_create("test acl dup", 1024);
	struct acl_rights src = {
		.id_type = ACL_ID_USER,
		.identifier = "foo",
		.rights = TEST_RIGHTS("lookup", "read"),
		.neg_rights = TEST_RIGHTS("insert"),
		.global = TRUE,
	};
	struct acl_rights dest;

	test_begin("acl_rights_dup()");
	acl_rights_dup(&src, pool, &dest);
	test_assert_cmp(dest.id_type, ==, src.id_type);
	test_assert(dest.identifier != src.identifier);
	test_assert_strcmp(dest.identifier, src.identifier);
	test_assert(dest.rights != src.rights);
	test_assert_strcmp(rights_str(dest.rights), "lookup read");
	test_assert_strcmp(rights_str(dest.neg_rights), "insert");
	test_assert(dest.global);

	/* NULL rights stay NULL */
	struct acl_rights src_null = { .id_type = ACL_ID_OWNER };
	acl_rights_dup(&src_null, pool, &dest);
	test_assert(dest.identifier == NULL);
	test_assert(dest.rights == NULL);
	test_assert(dest.neg_rights == NULL);
	test_assert(!dest.global);
	pool_unref(&pool);
	test_end();
}

static void test_acl_rights_sort(void)
{
	struct acl_rights rights1 = {
		.rights = t_strsplit("a b a c d b", " "),
		.neg_rights = t_strsplit("e d c a a d b e", " "),
	};
	struct acl_rights rights2 = {
		.rights = t_strsplit("a c x", " "),
		.neg_rights = t_strsplit("b c y", " "),
	};
	struct acl_object obj = {
		.rights_pool = pool_alloconly_create("acl rights", 256)
	};
	const struct acl_rights *rights;

	test_begin("acl_rights_sort");
	t_array_init(&obj.rights, 8);

	/* try with zero rights */
	acl_rights_sort(&obj);
	test_assert_cmp(array_count(&obj.rights), ==, 0);

	/* try with just one right */
	array_push_back(&obj.rights, &rights1);
	acl_rights_sort(&obj);
	test_assert_cmp(array_count(&obj.rights), ==, 1);
	rights = array_idx(&obj.rights, 0);
	test_assert(acl_rights_cmp(rights, &rights1) == 0);

	/* try with two rights that don't have equal ID */
	struct acl_rights rights1_id2 = rights1;
	rights1_id2.identifier = "id2";
	array_push_back(&obj.rights, &rights1_id2);
	acl_rights_sort(&obj);
	test_assert_cmp(array_count(&obj.rights), ==, 2);
	rights = array_idx(&obj.rights, 0);
	test_assert(acl_rights_cmp(&rights[0], &rights1) == 0);
	test_assert(acl_rights_cmp(&rights[1], &rights1_id2) == 0);

	/* try with 3 rights where first has equal ID */
	array_push_back(&obj.rights, &rights2);
	acl_rights_sort(&obj);
	test_assert_cmp(array_count(&obj.rights), ==, 2);
	rights = array_idx(&obj.rights, 0);
	test_assert_strcmp(t_strarray_join(rights[0].rights, " "), "a b c d x");
	test_assert_strcmp(t_strarray_join(rights[0].neg_rights, " "), "a b c d e y");

	pool_unref(&obj.rights_pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_acl_identifier_parse,
		test_acl_right_names_parse,
		test_acl_right_names_write,
		test_acl_right_names_roundtrip,
		test_acl_rights_parse_line,
		test_acl_rights_parse_line_errors,
		test_acl_rights_get_id,
		test_acl_rights_export,
		test_acl_rights_update_import,
		test_acl_right_names_merge,
		test_acl_right_names_modify,
		test_acl_rights_cmp,
		test_acl_rights_has_nonowner_lookup_changes,
		test_acl_id_is_valid,
		test_acl_rights_dup,
		test_acl_rights_sort,
		NULL
	};
	return test_run(test_functions);
}
