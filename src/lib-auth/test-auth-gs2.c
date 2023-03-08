/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "auth-gs2.h"

struct test_gs2_header_valid {
	const char *in;

	struct auth_gs2_header hdr;
	size_t hdr_len;

	bool expect_nonstd;
};

static const struct test_gs2_header_valid gs2_header_valid_tests[] = {
	{
		.in = "n,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
		},
	},
	{
		.in = "y,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT,
			},
		},
	},
	{
		.in = "p=frop,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "frop",
			},
		},
	},
	{
		.in = "p=tls-exporter,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "tls-exporter",
			},
		},
	},
	{
		.in = "p=frop2,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "frop2",
			},
		},
	},
	{
		.in = "p=vnd.example.com-frop,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "vnd.example.com-frop",
			},
		},
	},
	{
		.in = "n,a=frop,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = "frop",
		},
	},
	{
		.in = "y,a=frop,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT,
			},
			.authzid = "frop",
		},
	},
	{
		.in = "p=frop,a=frop,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "frop",
			},
			.authzid = "frop",
		},
	},
	{
		.in = "n,a=frop=2Cfriep=3Dfrml,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = "frop,friep=frml",
		},
	},
	{
		.in = "n,a==2Cfrop=2C,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = ",frop,",
		},
	},
	{
		.in = "n,a==3Dfrop=3D,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = "=frop=",
		},
	},
	{
		.in = "n,a==2C=3D,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = ",=",
		},
	},
	{
		.in = "n,a==2C=3D=2C=3D=2C=3D,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = ",=,=,=",
		},
	},
	{
		.in = "n,a==2C=2C=2C=3D=3D=3D,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = ",,,===",
		},
	},
	{
		.in = "n,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "y,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT,
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "p=frop,,",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "frop",
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,n,,",
		.hdr = {
			.nonstd = TRUE,
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,y,,",
		.hdr = {
			.nonstd = TRUE,
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_SERVER_SUPPORT,
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,p=frop,,",
		.hdr = {
			.nonstd = TRUE,
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_PROVIDED,
				.name = "frop",
			},
		},
		.expect_nonstd = TRUE,
	},
	{
		.in = "n,a=frop=2Cfriep=3Dfrml,n=user",
		.hdr = {
			.cbind = {
				.status = AUTH_GS2_CBIND_STATUS_NO_CLIENT_SUPPORT,
			},
			.authzid = "frop,friep=frml",
		},
		.hdr_len = 24,
	},
	{
		.in = "n,a=fr,p,",
		.hdr = {
			.authzid = "fr",
		},
		.hdr_len = 7,
	},
};

static void test_gs2_header_valid(void)
{
	unsigned int i;
	buffer_t *buf;
	int ret;

	buf = t_buffer_create(128);
	for (i = 0; i < N_ELEMENTS(gs2_header_valid_tests); i++) {
		const struct test_gs2_header_valid *test =
			&gs2_header_valid_tests[i];
		size_t test_hdr_len = (test->hdr_len == 0 ?
				       strlen(test->in) : test->hdr_len);
		struct auth_gs2_header hdr;
		const unsigned char *hdr_end = NULL;
		const char *error;

		test_begin(t_strdup_printf("auth gs2 header valid [%u]",
					   i + 1));

		ret = auth_gs2_header_decode((unsigned char *)test->in,
					     strlen(test->in),
					     test->expect_nonstd, &hdr,
					     &hdr_end, &error);
		test_out_reason("decode success", ret >= 0, error);
		if (ret < 0)
			continue;

		test_assert(hdr.cbind.status == test->hdr.cbind.status);
		test_assert_strcmp(hdr.cbind.name, test->hdr.cbind.name);
		test_assert_strcmp(hdr.authzid, test->hdr.authzid);
		test_assert(hdr.nonstd == test->hdr.nonstd);
		test_assert(hdr_end ==
			    (unsigned char *)(test->in + test_hdr_len));

		auth_gs2_header_encode(&hdr, buf);

		test_assert_strcmp(t_strndup(test->in, test_hdr_len),
				   str_c(buf));

		test_end();
		buffer_clear(buf);
	}

}

struct test_gs2_header_invalid {
	const char *in;
	size_t nul_at;

	bool expect_nonstd;
};

static const struct test_gs2_header_invalid gs2_header_invalid_tests[] = {
	{
		.in = "",
	},
	{
		.in = ",",
	},
	{
		.in = ",,",
	},
	{
		.in = "F,n",
	},
	{
		.in = "F,n",
		.nul_at = 2,
	},
	{
		.in = "F,n",
		.nul_at = 3,
	},
	{
		.in = "F,n",
		.nul_at = 2,
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,n",
		.nul_at = 3,
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,n,",
	},
	{
		.in = "F,n,,",
	},
	{
		.in = "Fn,",
		.expect_nonstd = TRUE,
	},
	{
		.in = "Fn,,",
		.expect_nonstd = TRUE,
	},
	{
		.in = "q,,",
	},
	{
		.in = "F,q",
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,q,",
		.expect_nonstd = TRUE,
	},
	{
		.in = "F,q,,",
		.expect_nonstd = TRUE,
	},
	{
		.in = "nn,",
	},
	{
		.in = "n,,",
		.nul_at = 1,
	},
	{
		.in = "n,,",
		.nul_at = 2,
	},
	{
		.in = "p,,",
	},
	{
		.in = "p=,",
	},
	{
		.in = "p=,,",
	},
	{
		.in = "p=_frop,,",
	},
	{
		.in = "p=frop_,,",
	},
	{
		.in = "p=fr_p,,",
	},
	{
		.in = "p=frop,,",
		.nul_at = 5,
	},
	{
		.in = "p=frop,,",
		.nul_at = 3,
	},
	{
		.in = "p=frop,,",
		.nul_at = 6,
	},
	{
		.in = "p=frop,,",
		.nul_at = 7,
	},
	{
		.in = "p=frop",
	},
	{
		.in = "n,,",
		.nul_at = 3,
	},
	{
		.in = "n,a",
	},
	{
		.in = "n,a,",
	},
	{
		.in = "n,a=",
	},
	{
		.in = "n,a=,",
	},
	{
		.in = "n,a=frop,",
		.nul_at = 7,
	},
	{
		.in = "n,a=frop,",
		.nul_at = 5,
	},
	{
		.in = "n,a=frop,",
		.nul_at = 8,
	},
	{
		.in = "n,a=frop,",
		.nul_at = 9,
	},
	{
		.in = "n,a=fr=p,",
	},
	{
		.in = "n,a==rop,",
	},
	{
		.in = "n,a=fro=,",
	},
	{
		.in = "n,a=fr=20p,",
	},
	{
		.in = "n,a==20rop,",
	},
	{
		.in = "n,a=fro=20,",
	},
	{
		.in = "n,a=fr=32p,",
	},
	{
		.in = "n,a==32rop,",
	},
	{
		.in = "n,a=fro=32,",
	},
	{
		.in = "n,a=frop",
	},
	{
		.in = "p=frop,",
	},
};

static void test_gs2_header_invalid(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < N_ELEMENTS(gs2_header_invalid_tests); i++) {
		const struct test_gs2_header_invalid *test =
			&gs2_header_invalid_tests[i];
		const unsigned char *test_hdr = (unsigned char *)test->in;
		size_t test_hdr_len = strlen(test->in);
		struct auth_gs2_header hdr;
		const unsigned char *hdr_end = NULL;
		const char *error;

		test_begin(t_strdup_printf("auth gs2 header invalid [%u]",
					   i + 1));

		if (test->nul_at > 0) {
			unsigned char *test_hdr_nul;

			i_assert((test->nul_at - 1) < test_hdr_len);
			test_hdr_nul =
				(unsigned char *)t_strdup_noconst(test->in);
			test_hdr_nul[test->nul_at - 1] = '\0';
			test_hdr = test_hdr_nul;
		}

		ret = auth_gs2_header_decode(test_hdr, test_hdr_len,
					     test->expect_nonstd, &hdr,
					     &hdr_end, &error);
		test_out_reason("decode failure", ret < 0, error);

		test_end();
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_gs2_header_valid,
		test_gs2_header_invalid,
		NULL
	};
	return test_run(test_functions);
}
