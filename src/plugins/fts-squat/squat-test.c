/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "file-lock.h"
#include "istream.h"
#include "time-util.h"
#include "unichar.h"
#include "squat-trie.h"
#include "squat-uidlist.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

static void result_print(ARRAY_TYPE(seq_range) *result)
{
	const struct seq_range *range;
	unsigned int i, count;

	range = array_get(result, &count);
	for (i = 0; i < count; i++) {
		if (i != 0)
			printf(",");
		printf("%u", range[i].seq1);
		if (range[i].seq1 != range[i].seq2)
			printf("-%u", range[i].seq2);
	}
	printf("\n");
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	const char *trie_path = "/tmp/squat-test-index.search";
	const char *uidlist_path = "/tmp/squat-test-index.search.uids";
	struct squat_trie *trie;
	struct squat_trie_build_context *build_ctx;
	struct istream *input;
	struct stat trie_st, uidlist_st;
	ARRAY_TYPE(seq_range) definite_uids, maybe_uids;
	char *line, *str, buf[4096];
	buffer_t *valid;
	int ret, fd;
	unsigned int last = 0, seq = 1, node_count, uidlist_count;
	size_t len;
	enum squat_index_type index_type;
	bool data_header = TRUE, first = TRUE, skip_body = FALSE;
	bool mime_header = TRUE;
	size_t trie_mem, uidlist_mem;
	clock_t clock_start, clock_end;
	struct timeval tv_start, tv_end;
	double cputime;

	lib_init();
	i_unlink_if_exists(trie_path);
	i_unlink_if_exists(uidlist_path);
	trie = squat_trie_init(trie_path, time(NULL),
			       FILE_LOCK_METHOD_FCNTL, 0, 0600, (gid_t)-1);

	clock_start = clock();
	gettimeofday(&tv_start, NULL);

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		return 1;

	if (squat_trie_build_init(trie, &build_ctx) < 0)
		return 1;

	valid = buffer_create_dynamic(default_pool, 4096);
	input = i_stream_create_fd(fd, (size_t)-1);
	ret = 0;
	while (ret == 0 && (line = i_stream_read_next_line(input)) != NULL) {
		if (last != input->v_offset/(1024*100)) {
			fprintf(stderr, "\r%ukB", (unsigned)(input->v_offset/1024));
			fflush(stderr);
			last = input->v_offset/(1024*100);
		}
		if (str_begins(line, "From ")) {
			if (!first)
				seq++;
			data_header = TRUE;
			skip_body = FALSE;
			mime_header = TRUE;
			continue;
		}
		first = FALSE;

		if (str_begins(line, "--")) {
			skip_body = FALSE;
			mime_header = TRUE;
		}

		if (mime_header) {
			if (*line == '\0') {
				data_header = FALSE;
				mime_header = FALSE;
				continue;
			}

			if (strncasecmp(line, "Content-Type:", 13) == 0 &&
			    strncasecmp(line, "Content-Type: text/", 19) != 0 &&
			    strncasecmp(line, "Content-Type: message/", 22) != 0)
				skip_body = TRUE;
			else if (strncasecmp(line, "Content-Transfer-Encoding: base64", 33) == 0)
				skip_body = TRUE;
		} else if (skip_body)
			continue;
		if (*line == '\0')
			continue;

		/* we're actually indexing here headers as bodies and bodies
		   as headers. it doesn't really matter in this test, and
		   fixing it would require storing headers temporarily
		   elsewhere and index them only after the body */
		index_type = !data_header ? SQUAT_INDEX_TYPE_HEADER :
			SQUAT_INDEX_TYPE_BODY;

		buffer_set_used_size(valid, 0);
		len = strlen(line);
		if (uni_utf8_get_valid_data((const unsigned char *)line,
					    len, valid)) {
			ret = squat_trie_build_more(build_ctx, seq, index_type,
						    (const void *)line, len);
		} else if (valid->used > 0) {
			ret = squat_trie_build_more(build_ctx, seq, index_type,
						    valid->data, valid->used);
		}
	}
	buffer_free(&valid);
	if (squat_trie_build_deinit(&build_ctx, NULL) < 0)
		ret = -1;
	if (ret < 0) {
		printf("build broken\n");
		return 1;
	}

	clock_end = clock();
	(void)gettimeofday(&tv_end, NULL);

	cputime = (double)(clock_end - clock_start) / CLOCKS_PER_SEC;
	fprintf(stderr, "\n - Index time: %.2f CPU seconds, "
		"%.2f real seconds (%.02fMB/CPUs)\n", cputime,
		timeval_diff_msecs(&tv_end, &tv_start)/1000.0,
		input->v_offset / cputime / (1024*1024));

	if (stat(trie_path, &trie_st) < 0)
		i_error("stat(%s) failed: %m", trie_path);
	if (stat(uidlist_path, &uidlist_st) < 0)
		i_error("stat(%s) failed: %m", uidlist_path);

	trie_mem = squat_trie_mem_used(trie, &node_count);
	uidlist_mem = squat_uidlist_mem_used(squat_trie_get_uidlist(trie),
					     &uidlist_count);
	fprintf(stderr, " - memory: %uk for trie, %uk for uidlist\n",
		(unsigned)(trie_mem/1024), (unsigned)(uidlist_mem/1024));
	fprintf(stderr, " - %"PRIuUOFF_T" bytes in %u nodes (%.02f%%)\n",
		trie_st.st_size, node_count,
		trie_st.st_size / (float)input->v_offset * 100.0);
	fprintf(stderr, " - %"PRIuUOFF_T" bytes in %u UID lists (%.02f%%)\n",
		uidlist_st.st_size, uidlist_count,
		uidlist_st.st_size / (float)input->v_offset * 100.0);
	fprintf(stderr, " - %"PRIuUOFF_T" bytes total of %"
		PRIuUOFF_T" (%.02f%%)\n",
		(trie_st.st_size + uidlist_st.st_size), input->v_offset,
		(trie_st.st_size + uidlist_st.st_size) /
		(float)input->v_offset * 100.0);

	i_stream_unref(&input);
	i_close_fd(&fd);

	i_array_init(&definite_uids, 128);
	i_array_init(&maybe_uids, 128);
	while ((str = fgets(buf, sizeof(buf), stdin)) != NULL) {
		ret = strlen(str)-1;
		str[ret] = 0;

		gettimeofday(&tv_start, NULL);
		ret = squat_trie_lookup(trie, str, SQUAT_INDEX_TYPE_HEADER |
					SQUAT_INDEX_TYPE_BODY,
					&definite_uids, &maybe_uids);
		if (ret < 0)
			printf("error\n");
		else {
			gettimeofday(&tv_end, NULL);
			printf(" - Search took %.05f CPU seconds\n",
			       timeval_diff_usecs(&tv_end, &tv_start)/1000000.0);
			printf(" - definite uids: ");
			result_print(&definite_uids);
			printf(" - maybe uids: ");
			result_print(&maybe_uids);
		}
	}
	return 0;
}
