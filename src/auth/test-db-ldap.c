/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-auth.h"
#include "db-ldap.h"
#include <stdio.h>

void test_db_ldap_parse_attrs(void)
{
	struct vectors {
		const char *inp;
		const char *out;
	} vectors[] = {
		{ .inp = "",                  	.out = ""},
		{ .inp = "a",                 	.out = "a"},

		/* tests with leading/trailing/no spaces*/
		{ .inp = "a,b,c",     		.out = "a|b|c"},
		{ .inp = "a, b, c",     	.out = "a| b| c"},
		{ .inp = "a ,b ,c",     	.out = "a |b |c"},

		/* leading empty field */
		{ .inp = ",a,b",     		.out = "a|b"},
		/* trailing empty field */
		{ .inp = "a,b,",     		.out = "a|b"},
		/* middle empty field */
		{ .inp = "a,,b",     		.out = "a|b"},


		/* simple nesting at begining/end of field */
		{ .inp = "a,{b,c},d",   	.out = "a|{b,c}|d"},

		/* simple nesting in the middle of the field */
		{ .inp = "a,b{c,d}e,f",   	.out = "a|b{c,d}e|f"},

		/* multiple nesting, balanced, prefixed and suffixed */
		{ .inp = "a, {{b, c}, d}, e", 	.out = "a| {{b, c}, d}| e"},
		{ .inp = "a, {b, {c, d}}, e", 	.out = "a| {b, {c, d}}| e"},

		/* unbalanced nesting, excess of {s */
		{ .inp = "{",                 	.out = "{"},
		{ .inp = "a, {b, {c, d}, e",  	.out = "a| {b, {c, d}, e"},

		/* unbalanced nesting, excess of }s */
		{ .inp = "}",                 	.out = "}"},
		{ .inp = "a, {b, {c, d}}}, e",	.out = "a| {b, {c, d}}}| e"},

		{}
	};

	test_begin("db ldap parse attrs");
	unsigned int index = 0;
	for (struct vectors *vector = vectors; vector->inp != NULL; vector++, index++) {
		const char *const *array = db_ldap_parse_attrs(vector->inp);
		const char *out = t_strarray_join(array, "|");
		test_assert_strcmp_idx(vector->out, out, index);
	}
	test_end();
}
