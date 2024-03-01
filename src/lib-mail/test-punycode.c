/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "punycode.h"
#include "str.h"
#include "test-common.h"

static void test_punycode_decode(void)
{
        const char *data[] = {
                /* has ASCII, appends */
                "gr-zia", "grå",
                /* has ASCII, inserts */
                "bl-yia", "bål",
                /* has ASCII, inserts AND appends */
                "stlbl-nrad", "stålblå",
                /* has no ASCII, appends */
                "--7sbabjsrp6aymef", "актриса-весна",
                /* broken */
                "zz-zzzz", "zz-zzzz"
        };
        unsigned int i;

        test_begin("punycode decoding");
        for (i = 0; i < N_ELEMENTS(data); i += 2) {
                string_t *t = t_str_new(42);
                str_append(t, data[i]);
                test_assert_strcmp_idx(data[i+1], str_c(punycode_decode(t)), i/2);
        }
        test_end();
}

int main(void)
{
        static void (*const test_functions[])(void) = {
                test_punycode_decode,
                NULL
        };
        return test_run(test_functions);
}
