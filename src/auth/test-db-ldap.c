/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "test-auth.h"
#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include "db-ldap.h"
#include <stdio.h>

void test_db_ldap_field_multi_expand_parse_data(void)
{
	struct vectors {
		const char *inp;
		const char *field;
		const char *sep;
		const char *defl;
	} vectors[] = {
		{.inp="",       .field="",  .sep=" ", .defl="" },
		{.inp="f",      .field="f", .sep=" ", .defl="" },
		{.inp="f:",     .field="f", .sep=" ", .defl="" },
		{.inp="f::",    .field="f", .sep=":", .defl="" },
		{.inp="f:::",   .field="f", .sep=":", .defl="" },
		{.inp="f:s",    .field="f", .sep="s", .defl="" },
		{.inp="f:s:",   .field="f", .sep="s", .defl="" },
		{.inp="f:s::",  .field="f", .sep="s", .defl=":" },
		{.inp="f::d",   .field="f", .sep=" ", .defl="d" },
		{.inp="f:::d",  .field="f", .sep=":", .defl="d" },
		{.inp="f::d:",  .field="f", .sep=" ", .defl="d:" },
		{.inp="f:::d:", .field="f", .sep=":", .defl="d:" },
		{}
	};

	test_begin("db ldap field multi expand parse data");
	unsigned int index = 0;
	for (struct vectors *vector = vectors; vector->inp != NULL; vector++, index++) {
		const char *field = NULL;
		const char *sep   = NULL;
		const char *defl  = NULL;

		db_ldap_field_multi_expand_parse_data(
			vector->inp, &field, &sep, &defl);

		test_assert_strcmp_idx(vector->field, field, index);
		test_assert_strcmp_idx(vector->sep,   sep,   index);
		test_assert_strcmp_idx(vector->defl,  defl,  index);
	}
	test_end();
}

#endif
