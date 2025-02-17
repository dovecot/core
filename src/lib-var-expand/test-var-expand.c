/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "cpu-count.h"
#include "str.h"
#include "hostpid.h"
#include "var-expand-private.h"
#include "expansion.h"
#include "dovecot-version.h"
#include "time-util.h"

#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

#include <time.h>
#include <unistd.h>

struct var_expand_test {
	const char *in;
	const char *out;
	int ret;
};

/* Run with -b to set TRUE */
static bool do_bench = FALSE;

static void run_var_expand_tests(const struct var_expand_params *params,
				 const struct var_expand_test tests[],
				 size_t test_count)
{
	string_t *dest= str_new(default_pool, 128);

	for (size_t i = 0; i < test_count; i++) {
		const struct var_expand_test *test = &tests[i];
		const char *error = NULL;

		str_truncate(dest, 0);
		int ret = var_expand(dest, test->in, params, &error);
		test_assert_cmp_idx(test->ret, ==, ret, i);

		if (ret < 0) {
			test_assert_idx(error != NULL, i);
			test_assert_idx(dest->used == 0,i );
			if (test->ret < 0) {
				i_assert(test->out != NULL && *test->out != '\0');
				const char *match = strstr(error, test->out);
				test_assert_idx(match != NULL, i);
				if (match == NULL) {
					i_debug("error '%s' does not contain '%s'",
						error, test->out);
				}
			}
			if (test->ret != ret) {
				i_debug("%s", test->in);
				i_error("<%zu> %s", i, error);
				continue;
			}
		} else if (ret == 0) {
			if (test->ret != ret) {
				i_debug("%s", test->in);
				i_error("<%zu> Unexpected success", i);
				continue;
			}
			test_assert_strcmp_idx(str_c(dest), test->out, i);
			if (strcmp(str_c(dest), test->out) != 0)
				i_debug("%s", test->in);
		}
	}

	str_free(&dest);

}

static void test_var_expand_builtin_filters(void) {
	test_begin("var_expand(buildin filters)");

	const struct var_expand_table table[] = {
		{ .key = "first", .value = "hello", },
		{ .key = "second", .value = "world", },
		{ .key = "third", .value = "pointer" },
		{ .key = "pointer", .value = "portal" },
		{ .key = "port", .value = "143", },
		{ .key = "three", .value = "3", },
		{ .key = "encoded", .value = "68656c6c6f" },
		{ .key = "domain", .value = "test.dovecot.org" },
		{ .key = "user", .value ="user@test@domain" },
		{ .key = "multivalue", .value = "one\ttwo\tthree" },
		{ .key = "uidvalidity", .value = "1727121943" },
		{ .key = "empty", .value = "" },
		{ .key = "\xce\xb8", .value = "is theta" },
		{ .key = "null", .value = NULL },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		/* basic lookup */
		{ .in = "%{first}", .out = "hello", .ret = 0 },
		{ .in = "%{lookup('first')}", .out = "hello", .ret = 0 },
		{ .in = "%{literal('hello')}", .out = "hello", .ret = 0 },
		{ .in = "%{lookup}", .out = "lookup: Missing name to lookup", .ret = -1 },
		{ .in = "%{literal}", .out = "literal: Missing parameters", .ret = -1 },
		/* lookup via variable */
		{ .in = "%{third}", .out = "pointer", .ret = 0 },
		{ .in = "%{lookup(third)}", .out = "portal", .ret = 0 },
		{ .in = "%{lookup(missing)}", .out = "lookup: Unknown variable 'missing'", .ret = -1 },
		/* default values */
		{ .in = "%{missing | default}", .out = "", .ret = 0 },
		{ .in = "%{missing | default(first)}", .out = "hello", .ret = 0 },
		{ .in = "%{missing | default('hello')}", .out = "hello", .ret = 0 },
		/* preserves first error */
		{ .in = "%{missing | default(missing)}", .out = "Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{first | default(second)}", .out = "hello", .ret = 0 },
		{ .in = "%{first | default('world')}", .out = "hello", .ret = 0 },
		{ .in = "%{default(first)}", .out = "hello", .ret = 0 },
		{ .in = "%{default(missing)}", .out = "default: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{empty | default('nonempty')}", .out = "nonempty", .ret = 0 },
		{ .in = "%{null}", .out = "", .ret = 0 },
		/* fail without default */
		{ .in = "%{missing}", .out = "Unknown variable 'missing'", .ret = -1 },
		/* casing */
		{ .in = "%{first | upper}", .out = "HELLO", .ret = 0 },
		{ .in = "%{first | upper | lower}", .out = "hello", .ret = 0 },
		/* substring */
		{ .in = "%{first | substr(0)}", .out = "hello", .ret = 0 },
		{ .in = "%{first | substr(5, 0)}", .out = "", .ret = 0 },
		{ .in = "%{first | substr(1, 2)}", .out = "el", .ret = 0 },
		{ .in = "%{first | substr(-2, 2)}", .out = "lo", .ret = 0 },
		{ .in = "%{first | substr(2, -2)}", .out = "l", .ret = 0 },
		{ .in = "%{first | substr(-1, -1)}", .out = "", .ret = 0 },
		{ .in = "%{first | substr(0, -1)}", .out = "hell", .ret = 0 },
		{ .in = "%{first | substr(-1)}", .out = "o", .ret = 0 },
		{ .in = "%{first | substr(-5)}", .out = "hello", .ret = 0 },
		{ .in = "%{first | substr(6)}", .out = "substr: Offset out of bounds", .ret = -1 },
		{ .in = "%{first | substr(-6)}", .out = "substr: Offset out of bounds", .ret = -1 },
		{ .in = "%{first | substr(1, 5)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(1, -5)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(-1, 5)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(-1, -5)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(5, 1)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(5, -1)}", .out = "substr: Length out of bounds", .ret = -1 },
		{ .in = "%{first | substr(-5, 1)}", .out = "h", .ret = 0 },
		{ .in = "%{first | substr(-5, -1)}", .out = "hell", .ret = 0 },
		{ .in = "%{first | substr(-6, 1)}", .out = "substr: Offset out of bounds", .ret = -1 },
		{ .in = "%{first | substr(-6, -1)}", .out = "substr: Offset out of bounds", .ret = -1 },
		{ .in = "%{substr}", .out = "substr: Missing parameters", .ret = -1 },
		{ .in = "%{substr(0,0)}", .out = "substr: No value to substring", .ret = -1 },
		/* reverse */
		{ .in = "%{first | reverse}", .out = "olleh", .ret = 0 },
		{ .in = "%{reverse}", .out = "reverse: No value to reverse", .ret = -1 },
		/* concatenate */
		{ .in = "%{first | concat(' ',second)}", .out = "hello world", .ret = 0 },
		{ .in = "%{concat(first,' ',second)}", .out = "hello world", .ret = 0 },
		{ .in = "%{concat}", .out = "Missing parameters", .ret = -1 },
		/* hash */
		{ .in = "%{first | sha1}", .out = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", .ret = 0 },
		{ .in = "%{first | sha1(rounds=1000)}", .out = "c0ddea212ee1af8d6401947d29c8bfab31f8ad93", .ret = 0 },
		{ .in = "%{first | sha1(salt='world')}", .out = "5715790a892990382d98858c4aa38d0617151575", .ret = 0 },
		{ .in = "%{first | sha1(rounds=1000,salt='world')}", .out = "a314ec3ef5103223a4c5bd285dbe4ea5534d4334", .ret = 0 },
		{ .in = "%{literal('1724925643') | hex}", .out = "66d046cb" },
		{ .in = "%{hash}", .out = "hash: Missing parameters", .ret = -1 },
		{ .in = "%{hash(rounds=1000)}", .out = "hash: No algorithm as first parameter", .ret = -1 },
		{ .in = "%{hash('md5',fail=1)}", .out = "hash: Unsupported key 'fail'", .ret = -1 },
		{ .in = "%{md5(fail=1)}", .out = "md5: Unsupported key 'fail'", .ret = -1 },
		/* hexlify */
		{ .in = "%{encoded | unhexlify | text}", .out = "hello", .ret = 0 },
		{ .in = "%{encoded | unhexlify}", .out = "68656c6c6f", .ret = 0 },
		{ .in = "%{three | hexlify(4)}", .out = "0033", .ret = 0 },
		{ .in = "%{hexlify(fail=1)}", .out = "hexlify: Unsupported key 'fail'", .ret = -1 },
		/* hex */
		{ .in = "%{three | hex | unhex}", .out = "3", .ret = 0 },
		{ .in = "%{uidvalidity | hex | unhex}", .out = "1727121943", .ret = 0 },
		{ .in = "%{three | hex(2)}", .out = "03", .ret = 0 },
		{ .in = "%{uidvalidity | hex(2)}",  .out = "17", .ret = 0 },
		{ .in = "%{uidvalidity | hex(-2)}",  .out = "66", .ret = 0 },
		{ .in = "%{uidvalidity | hex }", .out = "66f1ca17", .ret = 0 },
		/* base64 */
		{ .in = "%{first | base64}", .out = "aGVsbG8=", .ret = 0 },
		{ .in = "%{first | base64 | unbase64 | text}", .out = "hello", .ret = 0 },
		{ .in = "%{base64(0)}", .out = "base64: Too many positional parameters", .ret = -1 },
		{ .in = "%{base64(fail=1)}", .out = "base64: Unsupported key 'fail'", .ret = -1 },
		{ .in = "%{unbase64(0)}", .out = "unbase64: Too many positional parameters", .ret = -1 },
		{ .in = "%{unbase64(fail=1)}", .out = "unbase64: Unsupported key 'fail'", .ret = -1 },
		{ .in = "%{first | base64(pad=0)}", .out = "aGVsbG8", .ret = 0 },
		/* weird syntax to avoid trigraph ignored */
		{ .in = "%{literal('<<?""?""?>>') | base64(url=1)}", .out = "PDw_Pz8-Pg==", .ret = 0 },
		{ .in = "%{literal('<<?""?""?>>') | base64(pad=0,url=1)}", .out = "PDw_Pz8-Pg", .ret = 0 },
		/* truncate */
		{ .in = "%{first | truncate(3)}", .out = "hel", .ret = 0 },
		{ .in = "%{first | truncate(three)}", .out = "hel", .ret = 0 },
		{ .in = "%{first | truncate(bits=7)}", .out = "4", .ret = 0 },
		{ .in = "%{truncate}", .out = "truncate: Missing parameter", .ret = -1 },
		{ .in = "%{truncate('hello')}", .out = "truncate: 'hello' is not a number", .ret = -1 },
		{ .in = "%{truncate(first)}", .out = "truncate: 'hello' (in first) is not a number", .ret = -1 },
		{ .in = "%{truncate(3)}", .out = "truncate: No value to truncate", .ret = -1 },
		/* ldap dn */
		{ .in = "cn=%{first},ou=%{domain | ldap_dn}", .out = "cn=hello,ou=test,dc=dovecot,dc=org", .ret = 0 },
		/* regexp */
		{ .in = "%{literal('hello world') | regexp('(.*) (.*)', '\\\\2 \\\\1')}", .out = "world hello" },
		/* index */
		{ .in = "%{user | index('@',0)}", .out = "user", .ret = 0 },
		{ .in = "%{user | username}", .out = "user", .ret = 0 },
		{ .in = "%{user | domain}", .out = "test@domain", .ret = 0 },
		{ .in = "%{user | domain | domain}", .out = "domain", .ret = 0 },
		{ .in = "%{user | index('@',1)}", .out = "test", .ret = 0 },
		{ .in = "%{user | index('@',2)}", .out = "domain", .ret = 0 },
		{ .in = "%{user | index('@',3)}", .out = "index: Position out of bounds", .ret = -1 },
		{ .in = "%{user | index('@',-4)}", .out = "index: Position out of bounds", .ret = -1 },
		{ .in = "%{user | index('@',-5)}", .out = "index: Position out of bounds", .ret = -1 },
		{ .in = "%{user | index('@',-4) | default('hello')}", .out = "hello", .ret = 0 },
		{ .in = "%{user | index('@',-3)}", .out = "user", .ret = 0 },
		{ .in = "%{user | index('@',-2)}", .out = "test", .ret = 0 },
		{ .in = "%{user | index('@',-1)}", .out = "domain", .ret = 0 },
		{ .in = "%{user | username(0)}", .out = "username: Too many positional parameters", .ret = -1 },
		{ .in = "%{user | domain(0)}", .out = "domain: Too many positional parameters", .ret = -1 },
		{ .in = "%{literal('hello@') | domain }", .out = "", .ret = 0 },
		{ .in = "%{literal('@hello') | username }", .out = "", .ret = 0 },
		{ .in = "%{literal('@') | domain }", .out = "", .ret = 0 },
		{ .in = "%{literal('@') | username }", .out = "", .ret = 0 },
		{ .in = "%{literal('') | username }", .out = "", .ret = 0 },
		{ .in = "%{literal('') | domain }", .out = "", .ret = 0 },
		{ .in = "%{literal('username') | username }", .out = "username", .ret = 0 },
		{ .in = "%{literal('username') | domain }", .out = "", .ret = 0 },
		/* list */
		{ .in = "%{multivalue | list(',')}", .out = "one,two,three", .ret = 0 },
		/* fill */
		{ .in = "%{literal('1') | rfill(3)}", .out = "100", .ret = 0 },
		{ .in = "%{literal('1') | lfill(3)}", .out = "001", .ret = 0 },
		{ .in = "%{literal('1') | lfill(3, ' ')}", .out = "  1", .ret = 0 },
		/* %8Mu */
		{ .in = "%{first | md5 | hexlify(8)}", .out = "5d41402a", .ret = 0 },
		/* %N */
		{ .in = "%{first | md5 | substr(4,4) }", .out = "bc4b2a76", .ret = 0 },
		/* %2.256N */
		{ .in = "%{first | md5 | substr(0,8) % 256 | hex}", .out = "76", .ret = 0 },
		{ .in = "%{first | md5 | substr(0,8) % 30 | hex }", .out = "c", .ret = 0 },
		/* Modulo special case */
		{ .in = "%{first | md5 % 256 | hex}", .out = "92", .ret = 0 },
		{ .in = "%{first | sha512 % 256 | hex }", .out = "43", .ret = 0 },
		/* %N30 */
		{ .in = "%{first | md5 % 30 | hex }", .out = "16", .ret = 0 },
		{ .in = "%{first | md5 % 30 | hex(2) }", .out = "16", .ret = 0 },
		{ .in = "%{first | md5 % 30 | hex(4) }", .out = "0016", .ret = 0 },
		{ .in = "%{first | md5 % 30 | hex(-4) }", .out = "1600", .ret = 0 },
		{ .in = "%{\xce\xb8}", .out = "is theta", .ret = 0 },
		{ .in = "%{\xff\xfe\xff}", .out = "Invalid UTF-8 string", .ret = -1 },
	};

	const struct var_expand_params params = {
		.table = table,
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_math(void) {
	test_begin("var_expand(math)");

	const struct var_expand_table table[] = {
		{ .key = "first", .value = "1", },
		{ .key = "second", .value = "2", },
		{ .key = "third", .value = "pointer" },
		{ .key = "pointer", .value = "4" },
		{ .key = "port", .value = "143", },
		{ .key = "nan", .value = "nanana" },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		{ .in = "%{literal('1') + 1}", .out = "2", .ret = 0 },
		{ .in = "%{first + 1}", .out = "2", .ret = 0 },
		{ .in = "%{first * 10}", .out = "10", .ret = 0 },
		{ .in = "%{lookup(third) / 2}", .out = "2", .ret = 0 },
		{ .in = "%{nan - 1}", .out = "Input is not a number", .ret = -1 },
		{ .in = "%{literal('31') | unhexlify | text * 5}", .out = "5", .ret = 0 },
		{ .in = "%{literal('31') | unhex * 5}", .out = "245", .ret = 0 },
		{ .in = "%{port % 5}", .out = "3", .ret = 0 },
		{ .in = "%{port / 0}", .out = "calculate: Division by zero", .ret = -1 },
		{ .in = "%{port % 0}", .out = "calculate: Modulo by zero", .ret = -1 },
	};

	const struct var_expand_params params = {
		.table = table,
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_if(void)
{
	test_begin("var_expand(if)");

	const struct var_expand_table table[] = {
		{ .key = "alpha", .value = "alpha" },
		{ .key = "beta", .value = "beta" },
		{ .key = "one", .value = "1" },
		{ .key = "two", .value = "2" },
		{ .key = "evil1", .value = ";', ':" },
		{ .key = "evil2", .value = ";test;" },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		/* basic numeric operand test */
		{ .in = "%{if(1, '==', 1, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('1') | if('==', 2, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('<', 1, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('<', 2, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('1') | if('<=', 1, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('1') | if('<=', 2, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('1') | if('>', 1, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('>', 2, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('>=', 1, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('1') | if('>=', 2, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('!=', 1, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('1') | if('!=', 2, 'yes', 'no')}", .out = "yes", .ret = 0 },
		/* basic string operand test */
		{ .in = "%{if('a', 'eq', 'a', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('eq', 'b', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('lt', 'a', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('lt', 'b', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('le', 'a', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('le', 'b', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('gt', 'a', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('gt', 'b', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('ge', 'a', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('ge', 'b', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('ne', 'a', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('ne', 'b', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('*', 'a', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('*', 'b', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('*', '*a*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('*', '*b*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('*', '*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!*', 'a', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('!*', 'b', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!*', '*a*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('!*', '*b*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!*', '*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('~', 'a', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('~', 'b', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('~', '.*a.*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('~', '.*b.*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('~', '.*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!~', 'a', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('!~', 'b', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!~', '.*a.*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('a') | if('!~', '.*b.*', 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{literal('a') | if('!~', '.*', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('this is test') | if('~', '^test', 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{literal('this is test') | if('~', '.*test', 'yes', 'no')}", .out = "yes", .ret = 0 },
		/* variable expansion */
		{ .in = "%{alpha | if('eq', alpha, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{alpha | if('eq', beta, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{one | if('eq', one, 'yes', 'no')}", .out = "yes", .ret = 0 },
		{ .in = "%{one | if('eq', two, 'yes', 'no')}", .out = "no", .ret = 0 },
		{ .in = "%{one | if('eq', one, one, two)}", .out = "1", .ret = 0 },
		{ .in = "%{one | if('gt', two, one, two)}", .out = "2", .ret = 0 },
		{ .in = "%{evil1 | if('eq', ';\\', \\':', evil2, 'no')}", .out = ";test;", .ret = 0 },
		/* FIXME: add inner if support? */
/*		{ "%{if;%{if;%{one};eq;1;1;0};eq;%{if;%{two};eq;2;2;3};yes;no}", "no", 1 }, */
		/* Errors */
		{ .in = "%{if('gt', two, one, two)}", .out = "if: Missing parameters", .ret = -1 },
		{ .in = "%{if(1, '', 1, 'yes', 'no')}", .out = "if: Unsupported comparator ''", .ret = -1 },
		{ .in = "%{if(missing, '==', 1, 'yes', 'no')}", .out = "if: Left-hand side: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{if(1, missing, 1, 'yes', 'no')}", .out = "if: Comparator: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{if(1, '==', missing, 'yes', 'no')}", .out = "if: Right-hand side: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{if(1, '==', 1, missing, 'no')}", .out = "if: True branch: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{if(1, '==', 0, 'yes', missing)}", .out = "if: False branch: Unknown variable 'missing'", .ret = -1 },
		{ .in = "%{if(1, '==', 1, 'yes', 'no', 'maybe')}", .out = "if: Too many positional parameters", .ret = -1 },
		{ .in = "%{if(fail=1)}", .out = "if: Unsupported key 'fail'", .ret = -1 },
		{ .in = "%{alpha|if('==', two, one, two)}", .out = "if: Input is not a number", .ret = -1 },
	};

	const struct var_expand_params params = {
		.table = table,
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static int test_custom_provider(const char *key, const char **value_r, void *context,
			        const char **error_r)
{
	if (strcmp(key, "value") == 0)
		*value_r = context;
	else {
		test_assert_strcmp(key, "null");
		ERROR_UNSUPPORTED_KEY(key);
	}
	return 0;
}

static void test_var_expand_providers(void) {
	test_begin("var_expand(providers)");
	int ncpus;
	const char *error ATTR_UNUSED;
	const char *user = getenv("USER");
	struct timeval tv;
	struct tm tm;
	i_gettimeofday(&tv);
	if (localtime_r(&tv.tv_sec, &tm) == NULL)
		i_panic("localtime_r() failed: %m");

	int ret = cpu_count_get(&ncpus, &error);
	if (user == NULL)
		user = "";
	const struct var_expand_test tests[] = {
		{ .in = "%{process:pid}", .out = my_pid, },
		{ .in = "%{system:cpu_count}", .out = dec2str(ncpus), .ret = ret },
		{ .in = "%{dovecot:name}", .out = PACKAGE_NAME, .ret = 0 },
		{ .in = "%{dovecot:version}", .out = PACKAGE_VERSION, .ret = 0 },
		{ .in = "%{dovecot:support-url}", .out = PACKAGE_WEBPAGE, .ret = 0 },
		{ .in = "%{dovecot:support-email}", .out = PACKAGE_BUGREPORT, .ret = 0 },
		{ .in = "%{dovecot:revision}", .out = DOVECOT_REVISION, .ret = 0 },
		{ .in = "%{env:USER}", .out = user, .ret = 0 },
		{ .in = "%{env:missing}", .out = "", .ret = 0 },
		{ .in = "%{dovecot:invalid}", .out = "dovecot: Unsupported field 'invalid'", .ret = -1 },
		{ .in = "%{invalid:whatever}", .out = "Unsupported prefix 'invalid'", .ret = -1 },
		{ .in = "%{custom:value}", .out = "test", .ret = 0 },
		{ .in = "%{custom:null}", .out = "custom: Unsupported key 'null'", .ret = -1 },
		{ .in = "%{event:string}", .out = "event", .ret = 0 },
		{ .in = "%{event:missing}", .out = "event: No such field 'missing' in event", .ret = -1 },
		{ .in = "%{event:missing|default}", .out = "", .ret = 0 },
		{ .in = "%{event:magic}", .out = "42", .ret = 0 },
	};

	struct event *event = event_create(NULL);
	event_add_str(event, "string", "event");
	event_add_int(event, "magic", 42);

	const struct var_expand_params params = {
		.event = event,
		.providers = (const struct var_expand_provider[]) {
			{ .key = "custom", .func = test_custom_provider, },
			VAR_EXPAND_TABLE_END
		},
		.context = "test",
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	/* Test time expansion separately */
	const char *datetimetpl = "%{date:year}%{date:month}%{date:day}T"
				  "%{time:hour}%{time:min}%{time:sec}";
	const char *datetime;
	time_t t0 = time(NULL);
	ret = t_var_expand(datetimetpl, &params, &datetime, &error);
	test_out_reason_quiet("t_var_expand()", ret == 0, error);

	if (ret == 0) {
		/* try to parse result */
		struct tm tm;
		i_zero(&tm);
		/* get localtime to ensure we are in same timezone */
		time_t t = time(NULL);
		if (localtime_r(&t, &tm) == NULL)
			i_panic("localtime_r() failed: %m");
		if (strptime(datetime, "%Y%m%dT%H%M%S", &tm) == NULL) {
			test_failed(t_strdup_printf("strptime() failed: %m"));
		} else {
			/* Ensure the time is within 10 seconds */
			time_t t1 = mktime(&tm);
			test_assert_cmp(labs(t0 - t1), <, 10);
		}
	}

	/* Check the expansion of os/os-version depending on whether uname()
	    succeeds. */

	struct utsname utsname_result;
	if (uname(&utsname_result) == 0) {
		string_t *dest = t_str_new(32);
		str_truncate(dest, 0);
		test_assert(var_expand(dest, "%{system:os}", &params, &error) == 0);
		test_assert_strcmp(utsname_result.sysname, str_c(dest));

		str_truncate(dest, 0);
		test_assert(var_expand(dest, "%{system:os-version}", &params, &error) == 0);
		test_assert_strcmp(utsname_result.release, str_c(dest));
	}

	event_push_global(event);

	/* test with global event */
	const struct var_expand_test tests_global_event[] = {
		{ .in = "%{event:string}", .out = "event", .ret = 0 },
		{ .in = "%{event:missing}", .out = "No such field 'missing' in event", .ret = -1 },
		{ .in = "%{event:missing|default}", .out = "", .ret = 0 },
		{ .in = "%{event:magic}", .out = "42", .ret = 0 },
	};

	run_var_expand_tests(NULL, tests_global_event,
			     N_ELEMENTS(tests_global_event));

	event_pop_global(event);

	event_unref(&event);

	/* test without event */
	const struct var_expand_test tests_no_event[] = {
		{ .in = "%{event:anything}", .out = "No event available", .ret = -1 },
		{ .in = "%{event:anything|default}", .out = "", .ret = 0 },
	};

	run_var_expand_tests(NULL, tests_no_event, N_ELEMENTS(tests_no_event));

	test_end();
}

static void test_var_expand_provider_arr(void)
{
	test_begin("var_expand(provider arr)");
	const struct var_expand_test tests[] = {
		{ .in = "%{custom:value}", .out = "context1", .ret = 0 },
		{ .in = "%{custom2:value}", .out = "context2", .ret = 0 },
	};

	const struct var_expand_provider prov1[] = {
		{ .key = "custom", .func = test_custom_provider, },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_provider prov2[] = {
		{ .key = "custom2", .func = test_custom_provider, },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_params params = {
		.providers_arr = (const struct var_expand_provider*[]) {
			prov1,
			prov2,
			NULL,
		},
		.contexts = (void *const[]) {
			"context1",
			"context2",
			VAR_EXPAND_CONTEXTS_END
		},
		.event = NULL,
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));
	test_end();
}

static void test_var_expand_tables_arr(void)
{
	test_begin("var_expand(tables_arr)");

	const struct var_expand_table table1[] = {
		{ .key = "name", .value = "first" },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_table table2[] = {
		{ .key = "age", .value = "20" },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_table *const tables[] = {
		table1,
		table2,
		NULL
	};

	const struct var_expand_params params = {
		.tables_arr = tables,
	};

	string_t *dest = t_str_new(32);
	const char *error;
	int ret = var_expand(dest, "I am %{name} and %{age} years old",
				 &params, &error);

	test_assert(ret == 0);
	test_assert_strcmp(str_c(dest), "I am first and 20 years old");

	test_end();
}

static const char *test_escape(const char *str, void *context)
{
	const char *escape_chars = context;
	string_t *dest = t_str_new(strlen(str) + 2);
	str_append_c(dest, '\'');
	if (strpbrk(str, escape_chars) == NULL) {
		str_append(dest, str);
	} else {
		for (const char *ptr = str; *ptr != '\0'; ptr++) {
			if (strchr(escape_chars, *ptr) != NULL)
				str_append_c(dest, '\\');
			str_append_c(dest, *ptr);
		}
	}
	str_append_c(dest, '\'');
	return str_c(dest);
}

static void test_var_expand_escape(void)
{
	const struct var_expand_table table[] = {
		{ .key = "clean", .value = "hello world", },
		{ .key = "escape", .value = "'hello' \"world\"", },
		{ .key = "first", .value = "bobby" },
		{ .key = "nasty", .value = "\';-- SELECT * FROM bobby.tables" },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		{ .in = "%{clean}", .out = "'hello world'", .ret = 0, },
		{ .in = "%{escape}", .out = "'\\'hello\\' \"world\"'", .ret = 0 },
		{
			.in = "SELECT * FROM bobby.tables WHERE name = %{first}",
			.out = "SELECT * FROM bobby.tables WHERE name = 'bobby'",
			.ret = 0,
		},
		{
			.in = "SELECT * FROM bobby.tables WHERE name = %{nasty}",
			.out = "SELECT * FROM bobby.tables WHERE name = "
			       "'\\';-- SELECT * FROM bobby.tables'",
			.ret = 0,
		},
		{ .in = "no variables", .out = "no variables", .ret = 0 },
		{ .in = "%{literal('hello')}", .out = "'hello'", .ret = 0 },
		{ .in = "hello\\tworld", .out = "hello\\tworld", .ret = 0 },
		{ .in = "%{literal('hello\r\n\tworld')}", .out = "'hello\r\n\tworld'", .ret = 0 },
		/* Hello */
		{ .in = "\\110\\145\\154\\154\\157", .out = "\\110\\145\\154\\154\\157", .ret = 0},
		{ .in = "%{literal('\\110\\145\\154\\154\\157')}", .out = "'\110\145\154\154\157'", .ret = 0 },
		/* Hex / oct escapes */
		{ .in = "\\x20\\x21", .out = "\\x20\\x21", .ret = 0 },
		{ .in = "%{literal('\\x20\\x21')}", .out = "' !'", .ret = 0 },
		{ .in = "\\\\x20", .out = "\\\\x20", .ret = 0 },
		{ .in = "%{literal('\\\\x20')}", .out = "'\\x20'", .ret = 0 },
		/* Bad hex / oct */
		{ .in = "\\xgg", .out = "\\xgg", .ret = 0 },
		{ .in = "%{literal('\\xgg')}", .out = "Invalid character escape", .ret = -1 },
		{ .in = "\\999", .out = "\\999", .ret = 0 },
		{ .in = "%{literal('\\999')}", .out = "Invalid character escape", .ret = -1 },
		/* List test */
		{ .in = "%{literal('one\ttwo\tthree') | list}", .out="'one,two,three'", .ret = 0 },
		/* Escape escape */
		{ .in = "\\hello\\world", .out = "\\hello\\world", .ret = 0 },
		{ .in = "%{literal('\\'\\\\hello\\\\world\\'')}", .out = "'\\'\\hello\\world\\''", .ret = 0 },
		{ .in = "%{literal(\"\\\"\\\\hello\\\\world\\\"\")}", .out = "'\"\\hello\\world\"'", .ret = 0 },
		/* Unsupported escape sequence */
		{ .in = "%{literal('\\z')}", .out = "Invalid character escape", .ret = -1 },
	};

	const struct var_expand_params params = {
		.table = table,
		.escape_func = test_escape,
		.escape_context = "'",
	};

	test_begin("var_expand(escape)");

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static int test_value(const char *key, const char **value_r, void *context,
		      const char **error_r)
{
	const char *ctx = context;
	test_assert_strcmp(ctx, "test");

	if (strcmp(key, "third") == 0) {
		*error_r = "expected failure";
		return -1;
	}
	if (strcmp(key, "fourth") == 0) {
		*value_r = context;
		return 0;
	}
	test_assert_strcmp(key, "second");
	*value_r = "world";
	return 0;
}

static int test_value2(const char *key, const char **value_r, void *context,
		       const char **error_r)
{
	const char *ctx = context;
	test_assert_strcmp(ctx, "test2");

	if (strcmp(key, "third") == 0) {
		*error_r = "expected failure";
		return -1;
	}
	if (strcmp(key, "fourth") == 0) {
		*value_r = context;
		return 0;
	}
	test_assert_strcmp(key, "second");
	*value_r = "world";
	return 0;
}

static void test_var_expand_value_func(void)
{
	const struct var_expand_table table[] = {
		{ .key = "first", .value = "hello", },
		{ .key = "second", .func = test_value, },
		{ .key = "third", .func = test_value, },
		{ .key = "fourth", .func = test_value, },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		{ .in = "%{first} %{second}", .out = "hello world", .ret = 0, },
		{ .in = "%{first} %{third}", .out = "expected failure", .ret = -1 },
		{ .in = "%{first} %{fourth}", .out = "hello test", .ret = 0, },
	};

	const struct var_expand_params params = {
		.table = table,
		.context = "test",
	};

	test_begin("var_expand(value func)");

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_value_func_arr(void)
{
	const struct var_expand_table table[] = {
		{ .key = "first", .value = "hello", },
		{ .key = "second", .func = test_value, },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_table table2[] = {
		{ .key = "third", .func = test_value2, },
		{ .key = "fourth", .func = test_value2, },
		VAR_EXPAND_TABLE_END
	};

	const struct var_expand_test tests[] = {
		{ .in = "%{first} %{second}", .out = "hello world", .ret = 0, },
		{ .in = "%{first} %{third}", .out = "expected failure", .ret = -1 },
		{ .in = "%{first} %{fourth}", .out = "hello test2", .ret = 0, },
	};

	const struct var_expand_params params = {
		.table = NULL,
		.tables_arr = (const struct var_expand_table*[]) {
			table,
			table2,
			NULL
		},
		.contexts = (void *const[]) {
			"test",
			"test2",
			VAR_EXPAND_CONTEXTS_END
		},
		.event = NULL,
	};

	test_begin("var_expand(value func_arr)");

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_merge_tables(void)
{
	const struct var_expand_table one[] = {
		{ .key = "alpha", .value = "1" },
		{ .key = "beta", .value = "2" },
		VAR_EXPAND_TABLE_END
	},
	two[] = {
		{ .key = "theta", .value = "3" },
		{ .key = "phi", .value = "4" },
		VAR_EXPAND_TABLE_END
	},
	*merged = NULL;

	test_begin("var_expand_merge_tables");

	merged = var_expand_merge_tables(pool_datastack_create(), one, two);

	test_assert(var_expand_table_size(merged) == 4);
	for (unsigned int i = 0; i < var_expand_table_size(merged); i++) {
		if (i < 2) {
			test_assert_idx(merged[i].value == one[i].value || strcmp(merged[i].value, one[i].value) == 0, i);
			test_assert_idx(merged[i].key == one[i].key || strcmp(merged[i].key, one[i].key) == 0, i);
		} else if (i < 4) {
			test_assert_idx(merged[i].value == two[i-2].value || strcmp(merged[i].value, two[i-2].value) == 0, i);
			test_assert_idx(merged[i].key == two[i-2].key || strcmp(merged[i].key, two[i-2].key) == 0, i);
		} else {
			break;
		}
	}
	test_end();
}

static void test_var_expand_variables(void)
{
	test_begin("var_expand(variables)");

	/* build a program */
	struct var_expand_program *prog;
	const char *error;
	int ret = var_expand_program_create("%{foo} %{bar} %{baz} %{first} "
					    "%{env:foo} %{provider:value}",
					    &prog, &error);
	test_assert(ret == 0);
	if (ret != 0)
		i_error("%s", error);

	const char *const *variables = var_expand_program_variables(prog);
	test_assert_strcmp_idx(variables[0], "bar", 0);
	test_assert_strcmp_idx(variables[1], "baz", 1);
	test_assert_strcmp_idx(variables[2], "env:foo", 2);
	test_assert_strcmp_idx(variables[3], "first", 3);
	test_assert_strcmp_idx(variables[4], "foo", 4);
	test_assert_strcmp_idx(variables[5], "provider:value", 5);
	test_assert_idx(variables[6] == NULL, 6);

	var_expand_program_free(&prog);

	test_end();
}

/* test that keys are in correct order */
static int test_filter(const struct var_expand_statement *stmt,
		       struct var_expand_state *state,
		       const char **error_r ATTR_UNUSED)
{
	const struct var_expand_parameter *par = stmt->params;
	int previdx = -1;
	const char *prevkey = NULL;
	bool allow_idx = TRUE;

	for (; par != NULL; par = par->next) {
		test_assert(par->idx == -1 || (allow_idx && par->idx > previdx));
		test_assert(par->idx != -1 || prevkey == NULL ||
			    strcmp(par->key, prevkey) > 0);
		if (par->idx == -1) {
			allow_idx = FALSE;
			prevkey = par->key;
		} else
			previdx = par->idx;
	}

	var_expand_state_set_transfer(state, "done");

	return 0;
}


static void test_var_expand_parameter_sorted(void)
{
	const struct var_expand_test tests[] = {
		{ .in = "%{test_filter}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter(1, 2, 3)}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter('1', '2', '3')}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter(a='1', b='2', c='3')}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter(c='3', b='2', a='1')}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter('1', '2', '3', a='1', b='2', c='3')}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter(c='3', b='2', a='1', '1', '2', '3')}", .out ="done", .ret = 0 },
		{ .in = "%{test_filter(C='3', B='2', a='1', '1', '2', '3')}", .out ="done", .ret = 0 },
	};

	test_begin("var_expand(sorted parameters)");

	var_expand_register_filter("test_filter",test_filter);

	const struct var_expand_params params = {
	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_perc(void)
{
	test_begin("var_expand(percentage handling)");

	const struct var_expand_test tests[] = {
		{ .in = "%%{test}", .out = "%{test}", .ret = 0 },
		{ .in = "%Lu", .out = "%Lu", .ret = 0 },
		{ .in = "%%Lu", .out = "%%Lu", .ret = 0 },
		{ .in = "%{test}", .out = "value", .ret = 0 },
		{ .in = "%%Lu", .out = "%%Lu", .ret = 0 },
		{ .in = "%%", .out = "%%", .ret = 0 },
		{ .in = "%", .out = "%", .ret = 0 },
		{ .in = "%%-%%{test}-%%{test}", .out = "%%-%{test}-%{test}", .ret = 0 },
	};

	const struct var_expand_params params = {
		.table = (const struct var_expand_table[]){
			{ .key = "test", .value = "value" },
			VAR_EXPAND_TABLE_END
		},
		.event = NULL,

	};

	run_var_expand_tests(&params, tests, N_ELEMENTS(tests));

	test_end();
}

static void test_var_expand_set_copy(void)
{
	test_begin("var_expand(set, copy)");
	struct var_expand_table tab[] = {
		{ .key = "one", .value = NULL },
		{ .key = "two", .value = NULL },
		{ .key = "three", .value = NULL },
		{ .key = "four", .value = NULL },
		VAR_EXPAND_TABLE_END
	};

	var_expand_table_set_value(tab, "one", "value");
	var_expand_table_copy(tab, "two", "one");

	var_expand_table_set_func(tab, "three", test_value);
	var_expand_table_copy(tab, "four", "three");

	test_assert(tab[0].value == tab[1].value);
	test_assert(tab[2].func == tab[3].func);

	test_end();
}

static void test_var_expand_generate(void)
{
	const char *error;
	string_t *str = t_str_new(64);

	test_begin("var_expand(generate)");

	test_assert(var_expand(str, "%{generate:guid}", NULL, &error) == 0);
	test_assert(strstr(str_c(str), my_hostname) != NULL);

	str_truncate(str, 0);
	test_assert(var_expand(str, "%{generate:guid128}", NULL, &error) == 0);
	test_assert(str_len(str) == 32 && strspn(str_c(str), "0123456789abcdef") == 32);

	str_truncate(str, 0);
	test_assert(var_expand(str, "%{generate:uuid}", NULL, &error) == 0);
	test_assert(str_len(str) == 36 && strspn(str_c(str), "0123456789abcdef-") == 36);

	str_truncate(str, 0);
	test_assert(var_expand(str, "%{generate:uuid:record}", NULL, &error) == 0);
	test_assert(str_len(str) == 36 && strspn(str_c(str), "0123456789abcdef-") == 36);

	str_truncate(str, 0);
	test_assert(var_expand(str, "%{generate:uuid:compact}", NULL, &error) == 0);
	test_assert(str_len(str) == 32 && strspn(str_c(str), "0123456789abcdef") == 32);

	str_truncate(str, 0);
	test_assert(var_expand(str, "%{generate:uuid:microsoft}", NULL, &error) == 0);
	test_assert(str_len(str) == 38 && str_c(str)[0] == '{' &&
		    strspn(str_c(str)+1, "0123456789abcdef-") == 36 &&
		    str_c(str)[37] == '}');

	test_end();
}

static void test_var_expand_export_import(void)
{
	test_begin("var_expand(export/import)");

	const struct var_expand_params params = {
		.table = (const struct var_expand_table[]) {
			{ .key = "variable", .value = "1234567890" },
			{ .key = "this", .value = "isht" },
			{ .key = "a", .value = "b" },
			{ .key = "test", .value = "tset" },
			VAR_EXPAND_TABLE_END
		},
		.event = NULL,
	};

	const struct test_case {
		const char *prog_in;
		const char *export;
	} test_cases[] = {
		{ "", "\x02\t" },
		{ "literal", "\x01literal\r" },
		{ "\x01\x02\r\t", "\x01\x01""1\x02\x01r\x01t\r" },
		{ "%{variable}", "\x02variable\x01\t\tvariable\x01\t" },
		{ "%{lookup('variable')}", "\x02lookup\x01\x01svariable\r\t\t\t" },
		{
			"%{this} is %{a} simple %{test}",
			"\x02this\x01\t\ta\x01test\x01this"
			"\x01\t\x01 is \r\x02"
			"a\x01\t\t\t\x01 simple \r\x02"
			"test\x01\t\t\t"
		},
		{
			"%{variable | substr(0,1) % 32}",
			"\x02variable\x01\t\x01substr\x01\x01i\x01\x01\x01i\x02"
			"\t\x01""calculate\x01\x01i\x05\x01\x01i!\t\tvariable"
			"\x01\t"
		},
		{
			"%{variable | substr(0,1) % 32} / %{variable | substr(1,1) % 32}",
			"\x02variable\x01\t\x01substr\x01\x01i\x01\x01\x01i\x02"
			"\t\x01""calculate\x01\x01i\x05\x01\x01i!\t\tvariable"
			"\x01\t\x01 / \r\x02variable\x01\t\x01substr\x01\x01i"
			"\x02\x01\x01i\x02\t\x01""calculate\x01\x01i\x05\x01"
			"\x01i!\t\t\t"
		},
#if UINT32_MAX < INTMAX_MAX
		{
			"%{variable + 4294967296}",
			"\x02variable\x01\t\x01""calculate\x01\x01i\x01\x01\x01"
			"i\xab\x80\x80\x80\x80\x10\t\tvariable\x01\t"
		},
#endif
		{
			"%{variable + -100}",
			"\x02variable\x01\t\x01""calculate\x01\x01i\x01\x01\x01"
			"i\xad""d\t\tvariable\x01\t"
		},
		{
			"%{variable + 126}",
			"\x02variable\x01\t\x01""calculate\x01\x01i\x01\x01\x01i"
			"\x7f\t\tvariable\x01\t"
		},
		{
			"%{variable + 127}",
			"\x02variable\x01\t\x01""calculate\x01\x01i\x01\x01\x01i"
			"\xab\x7f\t\tvariable\x01\t"
		},
	};

	string_t *dest = t_str_new(64);

	string_t *result_a = t_str_new(64);
	string_t *result_b = t_str_new(64);

	for(size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const char *error;
		const struct test_case *t = &test_cases[i];
		struct var_expand_program *prog;
		str_truncate(dest, 0);
		str_truncate(result_a, 0);
		str_truncate(result_b, 0);

		/* We test two things, that we can export & import the program
		   and that the result of the imported program matches the
		   original program. */
		if (var_expand_program_create(t->prog_in, &prog, &error) <0)
			i_error("var_expand_program_create(): %s", error);
		if (var_expand_program_execute(result_a, prog, &params, &error) < 0)
			i_error("var_expand_program_execute(a): %s", error);
		var_expand_program_dump(prog, dest);
		str_truncate(dest, 0);
		var_expand_program_export_append(dest, prog);
		var_expand_program_free(&prog);
		test_assert_strcmp_idx(str_c(dest), t->export, i);
		if (var_expand_program_import(str_c(dest), &prog, &error) < 0)
			i_error("var_expand_program_import(): %s", error);
		if (var_expand_program_execute(result_b, prog, &params, &error) < 0)
			i_error("var_expand_program_execute(b): %s", error);
		test_assert_strcmp_idx(str_c(result_a), str_c(result_b), i);
		str_truncate(dest, 0);
		var_expand_program_dump(prog, dest);
		var_expand_program_free(&prog);
	}

	const struct test_case_err {
		const char *input;
		const char *error;
	} test_cases_err[] = {
		{ "", "Too short" },
		{ "\x01literal", "Missing end of string" },
		{ "\x03literal", "Unknown input" },
		{ "\x02literal\x01", "Premature end of data" },
		{ "\x02literal\x01text\x01", "Unsupported parameter type" },
		{ "\x02literal\x01\x01stext\t", "Missing end of string" },
		{ "\x02literal\x01\x01i\xa1", "Unknown number" },
		{ "\x02literal\x01\x01i\xab\xf0\t", "Missing parameter end" },
		{
			"\x02literal\x01\x01i\xab\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0\xf0",
			"Unfinished number"
		},
		{ "\x02literal\x01\x01stext\r", "Missing parameter end" },
		{ "\x02literal\x01\x01stext\r\t", "Missing statement end" },
		{ "\x02literal\x01\x01stext\r\t\t", "Missing variables end" },
	};

	for(size_t i = 0; i < N_ELEMENTS(test_cases_err); i++) {
		struct var_expand_program *prog;
		const char *error;
		const struct test_case_err *t = &test_cases_err[i];
		int ret = var_expand_program_import(t->input, &prog, &error);
		test_assert_cmp(ret, ==, -1);
		if (ret == 0) {
			var_expand_program_free(&prog);
			continue;
		}

		test_assert_strcmp(error, t->error);
	}

	test_end();
}

#define BENCH_ROUNDS 200000
static void test_var_expand_bench(void)
{
	if (!do_bench)
		return;
	struct test_cases {
		const char *program;
		const char *exported;
	} test_cases[] = {
		{ "literal", NULL },
		{ "%{variable}", NULL },
		{ "%{lookup('variable')}", NULL },
		{ "%{this} is %{a} simple %{test}", NULL },
		{ "%{variable | substr(0,1) % 32}", NULL },
		{ "%{variable | substr(0,1) % 32} / %{variable | substr(1,1) % 32}", NULL },
		{ "%{variable + 4294967296}", NULL },
	};
	test_begin("var_expand(export benchmark)");

	/* prepare exports */
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		const char *error ATTR_UNUSED;
		struct var_expand_program *prog;
		if (var_expand_program_create(test_cases[i].program, &prog,
					      &error) < 0)
			i_error("%s", error);
		test_cases[i].exported = var_expand_program_export(prog);
		var_expand_program_free(&prog);
	}

	struct timespec ts0, ts1;
	int ret;
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		i_debug("%s", test_cases[i].program);
		/* do speedtest */
		ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts0);
		i_assert(ret == 0);

		for (int rounds = 0; rounds < BENCH_ROUNDS; rounds++) {
			const char *error ATTR_UNUSED;
			struct var_expand_program *prog;
			if (var_expand_program_create(test_cases[i].program,
						      &prog, &error) < 0)
				i_error("%s", error);
			var_expand_program_free(&prog);
		}
		ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts1);
		i_assert(ret == 0);
		unsigned long long diff = (ts1.tv_sec - ts0.tv_sec) * 1000000000 + (ts1.tv_nsec - ts0.tv_nsec);
		i_debug("var_expand_program_create: %llu ns total, %llu ns / program",
			diff, diff / BENCH_ROUNDS);

		ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts0);
		i_assert(ret == 0);
		for (int rounds = 0; rounds < BENCH_ROUNDS; rounds++) {
			const char *error ATTR_UNUSED;
			struct var_expand_program *prog;
			if (var_expand_program_import(test_cases[i].exported,
						      &prog, &error) < 0)
				i_error("%s", error);
			var_expand_program_free(&prog);
		}
		ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts1);
		i_assert(ret == 0);
		diff = (ts1.tv_sec - ts0.tv_sec) * 1000000000 + (ts1.tv_nsec - ts0.tv_nsec);
		i_debug("var_expand_program_import: %llu ns total, %llu ns / program",
			diff, diff / BENCH_ROUNDS);
	}
	test_end();
}

int main(int argc, char *const argv[])
{
	void (*const tests[])(void) = {
		test_var_expand_merge_tables,
		test_var_expand_builtin_filters,
		test_var_expand_math,
		test_var_expand_if,
		test_var_expand_providers,
		test_var_expand_provider_arr,
		test_var_expand_tables_arr,
		test_var_expand_escape,
		test_var_expand_value_func,
		test_var_expand_value_func_arr,
		test_var_expand_variables,
		test_var_expand_parameter_sorted,
		test_var_expand_perc,
		test_var_expand_set_copy,
		test_var_expand_generate,
		test_var_expand_export_import,
		test_var_expand_bench,
		NULL
	};

	int opt;
	while ((opt = getopt(argc, argv, "b")) != -1) {
		if (opt == 'b')
			do_bench = TRUE;
		else
			i_fatal("Usage: %s [-b]", argv[0]);
	}

	return test_run(tests);
}
