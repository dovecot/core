/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "http-url.h"
#include "test-common.h"

struct valid_http_url_test {
	const char *url;
	enum http_url_parse_flags flags;
	struct http_url url_base;

	struct http_url url_parsed;
};

/* Valid HTTP URL tests */
static struct valid_http_url_test valid_url_tests[] = {
	/* Generic tests */
	{
		.url = "http://localhost",
		.url_parsed = {
			.host_name = "localhost" }
	},{
		.url = "http://www.%65%78%61%6d%70%6c%65.com",
		.url_parsed = {
			.host_name = "www.example.com" }
	},{
		.url = "http://www.dovecot.org:8080",
		.url_parsed = {
			.host_name = "www.dovecot.org",
			.port = 8080, .have_port = TRUE }
	},{
		.url = "http://127.0.0.1",
		.url_parsed = {
			.host_name = "127.0.0.1",
			.have_host_ip = TRUE }
#ifdef HAVE_IPV6
	},{
		.url = "http://[::1]",
		.url_parsed = {
			.host_name = "[::1]",
			.have_host_ip = TRUE }
	},{
		.url = "http://[::1]:8080",
		.url_parsed = {
			.host_name = "[::1]",
			.have_host_ip = TRUE,
			.port = 8080, .have_port = TRUE }
#endif
	},{
		.url = "http://www.example.com/"
			"?question=What%20are%20you%20doing%3f&answer=Nothing.",
		.url_parsed = {
			.path = "/",
			.host_name = "www.example.com",
			.enc_query = "question=What%20are%20you%20doing%3f&answer=Nothing." }
	},{
		.url = "http://www.example.com/#Status%20of%20development",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_parsed = {
			.path = "/",
			.host_name = "www.example.com",
			.enc_fragment = "Status%20of%20development" }

	
	/* RFC 3986, Section 5.4. Reference Resolution Examples 
	 *
	 * Within a representation with a well defined base URI of
	 *
	 *  http://a/b/c/d;p?q
	 *
	 * a relative reference is transformed to its target URI as follows.
	 *
	 * 5.4.1. Normal Examples
	 */
	},{ // "g"             =  "http://a/b/c/g"
		.url = "g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g" }
	},{ // "./g"           =  "http://a/b/c/g"
		.url = "./g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g" }
	},{ // "g/"            =  "http://a/b/c/g/"
		.url = "g/",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g/" }
	},{ // "/g"            =  "http://a/g"
		.url = "/g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }
	},{ // "//g"           =  "http://g"
		.url = "//g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "g" }
	},{ // "?y"            =  "http://a/b/c/d;p?y"
		.url = "?y",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "y" }
	},{ // "g?y"           =  "http://a/b/c/g?y"
		.url = "g?y",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g", .enc_query = "y" }
	},{ // "#s"            =  "http://a/b/c/d;p?q#s"
		.url = "#s",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q",
			.enc_fragment = "s" }
	},{ // "g#s"           =  "http://a/b/c/g#s"
		.url = "g#s",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g", .enc_fragment = "s" }

	},{ // "g?y#s"         =  "http://a/b/c/g?y#s"
		.url = "g?y#s",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g", .enc_query = "y",
			.enc_fragment = "s" }
	},{ // ";x"            =  "http://a/b/c/;x"
		.url = ";x",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/;x" }
	},{ // "g;x"           =  "http://a/b/c/g;x"
		.url = "g;x",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g;x" }

	},{ // "g;x?y#s"       =  "http://a/b/c/g;x?y#s"
		.url = "g;x?y#s",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g;x", .enc_query = "y",
			.enc_fragment = "s" }
	},{ // ""              =  "http://a/b/c/d;p?q"
		.url = "",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" }
	},{ // "."             =  "http://a/b/c/"
		.url = ".",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/" }
	},{ // "./"            =  "http://a/b/c/"
		.url = "./",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/" }
	},{ // ".."            =  "http://a/b/"
		.url = "..",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/" }
	},{ // "../"           =  "http://a/b/"
		.url = "../",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/" }
	},{ // "../g"          =  "http://a/b/g"
		.url = "../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/g" }
	},{ // "../.."         =  "http://a/"
		.url = "../..",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/" }
	},{ // "../../"        =  "http://a/"
		.url = "../../",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/" }
	},{ // "../../g"       =  "http://a/g"
		.url = "../../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }

	/* 5.4.2. Abnormal Examples
	 */
	},{ // "../../../g"    =  "http://a/g"
		.url = "../../../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }
	},{ // "../../../../g" =  "http://a/g"
		.url = "../../../../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }
	},{ // "/./g"          =  "http://a/g"
		.url = "/./g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }
	},{ // "/../g"         =  "http://a/g"
		.url = "/../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/g" }
	},{ // "g."            =  "http://a/b/c/g."
		.url = "g.",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g." }
	},{ // ".g"            =  "http://a/b/c/.g"
		.url = ".g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/.g" }
	},{ // "g.."           =  "http://a/b/c/g.."
		.url = "g..",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g.." }
	},{ // "..g"           =  "http://a/b/c/..g"
		.url = "..g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/..g" }
	},{ // "./../g"        =  "http://a/b/g"
		.url = "./../g",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/g" }
	},{ // "./g/."         =  "http://a/b/c/g/"
		.url = "./g/.",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g/" }
	},{ // "g/./h"         =  "http://a/b/c/g/h"
		.url = "g/./h",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g/h" }
	},{ // "g/../h"        =  "http://a/b/c/h"
		.url = "g/../h",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/h" }
	},{ // "g;x=1/./y"     =  "http://a/b/c/g;x=1/y"
		.url = "g;x=1/./y",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g;x=1/y" }
	},{ // "g;x=1/../y"    =  "http://a/b/c/y"
		.url = "g;x=1/../y",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/y" }
	},{ // "g?y/./x"       =  "http://a/b/c/g?y/./x"
		.url = "g?y/./x",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g", .enc_query = "y/./x" }
	},{ // "g?y/../x"      =  "http://a/b/c/g?y/../x"
		.url = "g?y/../x",
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed = { .host_name = "a", .path = "/b/c/g", .enc_query = "y/../x" }
	},{ // "g#s/./x"       =  "http://a/b/c/g#s/./x"
		.url = "g#s/./x",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed =
			{ .host_name = "a", .path = "/b/c/g", .enc_fragment = "s/./x" }
	},{ // "g#s/../x"      =  "http://a/b/c/g#s/../x"	
		.url = "g#s/../x",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART,
		.url_base = { .host_name = "a", .path = "/b/c/d;p", .enc_query = "q" },
		.url_parsed =
			{ .host_name = "a", .path = "/b/c/g", .enc_fragment = "s/../x" }
	}
};

static unsigned int valid_url_test_count = N_ELEMENTS(valid_url_tests);

static void test_http_url_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_url_test_count; i++) T_BEGIN {
		const char *url = valid_url_tests[i].url;
		enum http_url_parse_flags flags = valid_url_tests[i].flags;
		struct http_url *urlt = &valid_url_tests[i].url_parsed;
		struct http_url *urlb = &valid_url_tests[i].url_base;
		struct http_url *urlp;
		const char *error = NULL;

		test_begin(t_strdup_printf("http url valid [%d]", i));

		if (urlb->host_name == NULL) urlb = NULL;
		if (http_url_parse(url, urlb, flags, pool_datastack_create(), &urlp, &error) < 0)
			urlp = NULL;

		test_out_reason(t_strdup_printf("http_url_parse(%s)",
			valid_url_tests[i].url), urlp != NULL, error);
		if (urlp != NULL) {
			if (urlp->host_name == NULL || urlt->host_name == NULL) {
				test_out(t_strdup_printf("url->host_name = %s", urlp->host_name),
					urlp->host_name == urlt->host_name);
			} else {
				test_out(t_strdup_printf("url->host_name = %s", urlp->host_name),
					strcmp(urlp->host_name, urlt->host_name) == 0);
			}
			if (!urlp->have_port) {
				test_out("url->port = (unspecified)",
					urlp->have_port == urlt->have_port);
			} else {
				test_out(t_strdup_printf("url->port = %u", urlp->port),
					urlp->have_port == urlt->have_port && urlp->port == urlt->port);
			}
			if (!urlp->have_host_ip) {
				test_out("url->host_ip = (unspecified)",
					urlp->have_host_ip == urlt->have_host_ip);
			} else {
				test_out("url->host_ip = (valid)",
					urlp->have_host_ip == urlt->have_host_ip);
			}
			if (urlp->path == NULL || urlt->path == NULL) {
				test_out(t_strdup_printf("url->path = %s", urlp->path),
					urlp->path == urlt->path);
			} else {
				test_out(t_strdup_printf("url->path = %s", urlp->path),
					strcmp(urlp->path, urlt->path) == 0);
			}
			if (urlp->enc_query == NULL || urlt->enc_query == NULL) {
				test_out(t_strdup_printf(
						"url->enc_query = %s", urlp->enc_query),
					urlp->enc_query == urlt->enc_query);
			} else {
				test_out(t_strdup_printf(
						"url->enc_query = %s", urlp->enc_query),
					strcmp(urlp->enc_query, urlt->enc_query) == 0);
			}
			if (urlp->enc_fragment == NULL || urlt->enc_fragment == NULL) {
				test_out(t_strdup_printf(
						"url->enc_fragment = %s", urlp->enc_fragment),
					urlp->enc_fragment == urlt->enc_fragment);
			} else {
				test_out(t_strdup_printf(
						"url->enc_fragment = %s", urlp->enc_fragment),
					strcmp(urlp->enc_fragment, urlt->enc_fragment) == 0);
			}
		}

		test_end();
	} T_END;
}

struct invalid_http_url_test {
	const char *url;
	enum http_url_parse_flags flags;
	struct http_url url_base;
};

static struct invalid_http_url_test invalid_url_tests[] = {
	{
		.url = "imap://example.com/INBOX"
	},{
		.url = "http:/www.example.com"
	},{
		.url = ""
	},{
		.url = "/index.html"
	},{
		.url = "http://www.example.com/index.html\""
	},{
		.url = "http:///dovecot.org"
	},{
		.url = "http://[]/index.html"
	},{
		.url = "http://[v08.234:232:234:234:2221]/index.html"
#ifdef HAVE_IPV6
	},{
		.url = "http://[1::34a:34:234::6]/index.html"
#endif
	},{
		.url = "http://example%a.com/index.html"
	},{
		.url = "http://example.com%/index.html"
	},{
		.url = "http://example%00.com/index.html"
	},{
		.url = "http://example.com:65539/index.html"
	},{
		.url = "http://example.com/settings/%00/"
	},{
		.url = "http://example.com/settings/%0r/"
	},{
		.url = "http://example.com/settings/misc/%/"
	},{
		.url = "http://example.com/?%00"
	},{
		.url = "http://www.example.com/network.html#IMAP_Server"
	},{
		.url = "http://example.com/#%00",
		.flags = HTTP_URL_ALLOW_FRAGMENT_PART
	}
};

static unsigned int invalid_url_test_count = N_ELEMENTS(invalid_url_tests);

static void test_http_url_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_url_test_count; i++) T_BEGIN {
		const char *url = invalid_url_tests[i].url;
		enum http_url_parse_flags flags = invalid_url_tests[i].flags;
		struct http_url *urlb = &invalid_url_tests[i].url_base;
		struct http_url *urlp;
		const char *error = NULL;

		if (urlb->host_name == NULL)
			urlb = NULL;

		test_begin(t_strdup_printf("http url invalid [%d]", i));

		if (http_url_parse(url, urlb, flags,
				   pool_datastack_create(), &urlp, &error) < 0)
			urlp = NULL;
		test_out_reason(t_strdup_printf("parse %s", url), urlp == NULL, error);

		test_end();
	} T_END;

}

static const char *parse_create_url_tests[] = {
	"http://www.example.com/",
	"http://10.0.0.1/",
#ifdef HAVE_IPV6
	"http://[::1]/",
#endif
	"http://www.example.com:993/",
	"http://www.example.com/index.html",
	"http://www.example.com/settings/index.html",
	"http://ww.%23example.com/",
	"http://www.example.com/%23shared/news",
	"http://www.example.com/query.php?name=Hendrik%20Visser",
	"http://www.example.com/network.html#IMAP%20Server",
};

static unsigned int
parse_create_url_test_count = N_ELEMENTS(parse_create_url_tests);

static void test_http_url_parse_create(void)
{
	unsigned int i;

	for (i = 0; i < parse_create_url_test_count; i++) T_BEGIN {
		const char *url = parse_create_url_tests[i];
		struct http_url *urlp;
		const char *error = NULL;

		test_begin(t_strdup_printf("http url parse/create [%d]", i));

		if (http_url_parse
			(url, NULL, HTTP_URL_ALLOW_FRAGMENT_PART,
			 pool_datastack_create(), &urlp, &error) < 0)
			urlp = NULL;
		test_out_reason(t_strdup_printf("parse  %s", url), urlp != NULL, error);
		if (urlp != NULL) {
			const char *urlnew = http_url_create(urlp);
			test_out(t_strdup_printf
				("create %s", urlnew), strcmp(url, urlnew) == 0);
		}

		test_end();
	} T_END;

}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_url_valid,
		test_http_url_invalid,
		test_http_url_parse_create,
		NULL
	};
	return test_run(test_functions);
}

