/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "solr-response.h"
#include "test-common.h"

#include <unistd.h>

static bool debug = FALSE;

struct solr_response_test_result {
	const char *box_id;
	struct fts_score_map *scores;
};

struct solr_response_test {
	const char *input;

	struct solr_response_test_result *results;
};

struct fts_score_map test_results1_scores[] = {
	{ .score = 0.042314477,	.uid = 1 },
	{ .score = 0.06996078, .uid = 2, },
	{ .score = 0.020381179, .uid = 3 },
	{ .score = 0.020381179,	.uid = 4 },
	{ .score = 5.510487E-4,	.uid = 6 },
	{ .score = 0.0424253, .uid = 7 },
	{ .score = 0.04215967, .uid = 8 },
	{ .score = 0.02470572, .uid = 9 },
	{ .score = 0.05936369, .uid = 10 },
	{ .score = 0.048221838,	.uid = 11 },
	{ .score = 7.793006E-4,	.uid = 12 },
	{ .score = 2.7900032E-4, .uid = 13 },
	{ .score = 0.02088323, .uid = 14 },
	{ .score = 0.011646388, .uid = 15 },
	{ .score = 1.3776218E-4, .uid = 17 },
	{ .score = 2.386111E-4, .uid = 19 },
	{ .score = 2.7552436E-4, .uid = 20 },
	{ .score = 4.772222E-4, .uid = 23 },
	{ .score = 4.772222E-4, .uid = 24 },
	{ .score = 5.965277E-4, .uid = 25 },
	{ .score = 0.0471366, .uid = 26 },
	{ .score = 0.0471366, .uid = 50 },
	{ .score = 0.047274362, .uid = 51 },
	{ .score = 0.053303234, .uid = 56 },
	{ .score = 5.445528E-4, .uid = 62 },
	{ .score = 2.922377E-4, .uid = 66 },
	{ .score = 0.02623833, .uid = 68 },
	{ .score = 3.4440547E-4, .uid = 70 },
	{ .score = 2.922377E-4, .uid = 74 },
	{ .score = 2.7552436E-4, .uid = 76 },
	{ .score = 1.3776218E-4, .uid = 77 },
	{ .score = 0, .uid = 0 },
};

struct solr_response_test_result test_results1[] = {
	{
		.box_id = "",
		.scores = test_results1_scores,
	},
	{
		.box_id = NULL
	}
};

static const struct solr_response_test tests[] = {
	{
		.input =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<response>\n"
			"<lst name=\"responseHeader\"><int name=\"status\""
			">0</int><int name=\"QTime\">3</int><lst name=\"pa"
			"rams\"><str name=\"wt\">xml</str><str name=\"fl\""
			">uid,score</str><str name=\"rows\">4023</str><str"
			" name=\"sort\">uid asc</str><str name=\"q\">{!luc"
			"ene q.op=AND}subject:pierreserveur OR from:pierre"
			"serveur OR to:pierreserveur OR cc:pierreserveur O"
			"R bcc:pierreserveur OR body:pierreserveur</str><s"
			"tr name=\"fq\">+box:fa74101044cb607d5f0900001de14"
			"712 +user:jpierreserveur</str></lst></lst><result"
			" name=\"response\" numFound=\"31\" start=\"0\" ma"
			"xScore=\"0.06996078\"><doc><float name=\"score\">"
			"0.042314477</float><long name=\"uid\">1</long></d"
			"oc><doc><float name=\"score\">0.06996078</float><"
			"long name=\"uid\">2</long></doc><doc><float name="
			"\"score\">0.020381179</float><long name=\"uid\">3"
			"</long></doc><doc><float name=\"score\">0.0203811"
			"79</float><long name=\"uid\">4</long></doc><doc><"
			"float name=\"score\">5.510487E-4</float><long nam"
			"e=\"uid\">6</long></doc><doc><float name=\"score\""
			">0.0424253</float><long name=\"uid\">7</long></do"
			"c><doc><float name=\"score\">0.04215967</float><l"
			"ong name=\"uid\">8</long></doc><doc><float name=\""
			"score\">0.02470572</float><long name=\"uid\">9</l"
			"ong></doc><doc><float name=\"score\">0.05936369</"
			"float><long name=\"uid\">10</long></doc><doc><flo"
			"at name=\"score\">0.048221838</float><long name=\""
			"uid\">11</long></doc><doc><float name=\"score\">7"
			".793006E-4</float><long name=\"uid\">12</long></d"
			"oc><doc><float name=\"score\">2.7900032E-4</float"
			"><long name=\"uid\">13</long></doc><doc><float na"
			"me=\"score\">0.02088323</float><long name=\"uid\""
			">14</long></doc><doc><float name=\"score\">0.0116"
			"46388</float><long name=\"uid\">15</long></doc><d"
			"oc><float name=\"score\">1.3776218E-4</float><lon"
			"g name=\"uid\">17</long></doc><doc><float name=\""
			"score\">2.386111E-4</float><long name=\"uid\">19<"
			"/long></doc><doc><float name=\"score\">2.7552436E"
			"-4</float><long name=\"uid\">20</long></doc><doc>"
			"<float name=\"score\">4.772222E-4</float><long na"
			"me=\"uid\">23</long></doc><doc><float name=\"scor"
			"e\">4.772222E-4</float><long name=\"uid\">24</lon"
			"g></doc><doc><float name=\"score\">5.965277E-4</f"
			"loat><long name=\"uid\">25</long></doc><doc><floa"
			"t name=\"score\">0.0471366</float><long name=\"ui"
			"d\">26</long></doc><doc><float name=\"score\">0.0"
			"471366</float><long name=\"uid\">50</long></doc><"
			"doc><float name=\"score\">0.047274362</float><lon"
			"g name=\"uid\">51</long></doc><doc><float name=\""
			"score\">0.053303234</float><long name=\"uid\">56<"
			"/long></doc><doc><float name=\"score\">5.445528E-"
			"4</float><long name=\"uid\">62</long></doc><doc><"
			"float name=\"score\">2.922377E-4</float><long nam"
			"e=\"uid\">66</long></doc><doc><float name=\"score"
			"\">0.02623833</float><long name=\"uid\">68</long>"
			"</doc><doc><float name=\"score\">3.4440547E-4</fl"
			"oat><long name=\"uid\">70</long></doc><doc><float"
			" name=\"score\">2.922377E-4</float><long name=\"u"
			"id\">74</long></doc><doc><float name=\"score\">2."
			"7552436E-4</float><long name=\"uid\">76</long></d"
			"oc><doc><float name=\"score\">1.3776218E-4</float"
			"><long name=\"uid\">77</long></doc></result>\n"
			"</response>\n",
		.results = test_results1,
	},
};

static const unsigned tests_count = N_ELEMENTS(tests);

static void
test_solr_result(const struct solr_response_test_result *test_results,
		 struct solr_result **parse_results)
{
	unsigned int rcount, i;

	for (i = 0; test_results[i].box_id != NULL; i++);
	rcount = i;

	for (i = 0; parse_results[i] != NULL; i++);

	test_out_quiet("result count equal", i == rcount);
	if (test_has_failed())
		return;

	for (i = 0; i < rcount && parse_results[i] != NULL; i++) {
		unsigned int scount, j;
		const struct fts_score_map *tscores = test_results[i].scores;
		const struct fts_score_map *pscores =
			array_get(&parse_results[i]->scores, &scount);

		test_out_quiet(t_strdup_printf("box id equal[%u]", i),
			       strcmp(test_results[i].box_id,
				      parse_results[i]->box_id) == 0);

		for (j = 0; tscores[j].uid != 0; j++);
		test_out_quiet(t_strdup_printf("scores count equal[%u]", i),
			       j == scount);
		if (j != scount)
			continue;

		for (j = 0; j < scount; j++) {
			test_out_quiet(
				t_strdup_printf("score uid equal[%u/%u]", i, j),
				pscores[j].uid == tscores[j].uid);
			test_out_quiet(
				t_strdup_printf("score value equal[%u/%u]", i, j),
				pscores[j].score == tscores[j].score);
		}
	}
}

static void test_solr_response_parser(void)
{
	unsigned int i;

	for (i = 0; i < tests_count; i++) T_BEGIN {
		const struct solr_response_test *test;
		const char *text;
		unsigned int pos, text_len;
		struct istream *input;
		struct solr_response_parser *parser;
		struct solr_result **box_results;
		const char *error = NULL;
		pool_t pool;
		int ret = 0;

		test = &tests[i];
		text = test->input;
		text_len = strlen(text);

		test_begin(t_strdup_printf("solr response [%d]", i));

		input = test_istream_create_data(text, text_len);
		pool = pool_alloconly_create("solr response", 4096);
		parser = solr_response_parser_init(pool, input);

		ret = solr_response_parse(parser, &box_results);

		test_out_reason("parse ok (buffer)", ret > 0, error);
		if (ret > 0)
			test_solr_result(test->results, box_results);

		solr_response_parser_deinit(&parser);
		pool_unref(&pool);
		i_stream_unref(&input);

		input = test_istream_create_data(text, text_len);
		pool = pool_alloconly_create("solr response", 4096);
		parser = solr_response_parser_init(pool, input);

		ret = 0;
		for (pos = 0; pos <= text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = solr_response_parse(parser, &box_results);
		}

		test_out_reason("parse ok (trickle)", ret > 0, error);
		if (ret > 0)
			test_solr_result(test->results, box_results);

		solr_response_parser_deinit(&parser);
		pool_unref(&pool);
		i_stream_unref(&input);

		test_end();

	} T_END;
}

static void test_solr_response_file(const char *file)
{
	pool_t pool;
	struct istream *input;
	struct solr_response_parser *parser;
	struct solr_result **box_results;
	int ret = 0;

	pool = pool_alloconly_create("solr response", 4096);
	input = i_stream_create_file(file, 1024);
	parser = solr_response_parser_init(pool, input);

	while ((ret = solr_response_parse(parser, &box_results)) == 0);

	if (ret < 0)
		i_fatal("Failed to read response");

	solr_response_parser_deinit(&parser);
	i_stream_unref(&input);
	pool_unref(&pool);
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_solr_response_parser,
		NULL
	};

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0) {
		test_solr_response_file(argv[0]);
		return 0;
	}

	return test_run(test_functions);
}


