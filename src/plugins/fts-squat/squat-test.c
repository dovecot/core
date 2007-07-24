/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "file-lock.h"
#include "istream.h"
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

int main(int argc __attr_unused__, char *argv[])
{
	struct squat_trie *trie;
	struct squat_trie_build_context *build_ctx;
	struct istream *input;
	ARRAY_TYPE(seq_range) result;
	char *line, *str, buf[4096];
	int fd;
	ssize_t ret;
	unsigned int last = 0, seq = 0, leaves, uid_lists_mem, uid_lists_count;
	uint32_t last_uid;
	size_t mem;
	clock_t clock_start, clock_end;
	struct timeval tv_start, tv_end;
	double cputime;

	lib_init();
	(void)unlink("/tmp/squat-test-index.search");
	(void)unlink("/tmp/squat-test-index.search.uids");
	trie = squat_trie_open("/tmp/squat-test-index.search", time(NULL),
			       FILE_LOCK_METHOD_FCNTL, FALSE);

	clock_start = clock();
	gettimeofday(&tv_start, NULL);

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		return 1;

	build_ctx = squat_trie_build_init(trie, &last_uid);
	input = i_stream_create_file(fd, 0, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (last != input->v_offset/(1024*100)) {
			fprintf(stderr, "\r%ukB", (unsigned)(input->v_offset/1024));
			fflush(stderr);
			last = input->v_offset/(1024*100);
		}
		if (strncmp(line, "From ", 5) == 0) {
			seq++;
			continue;
		}

		if (squat_trie_build_more(build_ctx, seq,
					  (const void *)line, strlen(line)) < 0)
			break;
	}
	squat_trie_build_deinit(build_ctx);

	clock_end = clock();
	gettimeofday(&tv_end, NULL);

	cputime = (double)(clock_end - clock_start) / CLOCKS_PER_SEC;
	fprintf(stderr, "\n - Index time: %.2f CPU seconds, "
		"%.2f real seconds (%.02fMB/CPUs)\n", cputime,
		(tv_end.tv_sec - tv_start.tv_sec) +
		(tv_end.tv_usec - tv_start.tv_usec)/1000000.0,
		input->v_offset / cputime / (1024*1024));

	mem = squat_trie_mem_used(trie, &leaves);
	uid_lists_mem = squat_uidlist_mem_used(_squat_trie_get_uidlist(trie),
					       &uid_lists_count);
	fprintf(stderr, " - %u bytes in %u nodes (%.02f%%)\n"
		" - %u bytes in %u uid_lists (%.02f%%)\n"
		" - %u bytes total of %"PRIuUOFF_T" (%.02f%%)\n",
		(unsigned)mem, leaves, mem / (float)input->v_offset * 100.0,
		uid_lists_mem, uid_lists_count,
		uid_lists_mem / (float)input->v_offset * 100.0,
		(unsigned)(uid_lists_mem + mem), input->v_offset,
		(uid_lists_mem + mem) / (float)input->v_offset * 100.0);

	i_stream_unref(&input);
	close(fd);

	i_array_init(&result, 128);
	while ((str = fgets(buf, sizeof(buf), stdin)) != NULL) {
		ret = strlen(str)-1;
		str[ret] = 0;

		array_clear(&result);
		gettimeofday(&tv_start, NULL);
		if (!squat_trie_lookup(trie, &result, str))
			printf("No matches\n");
		else {
			gettimeofday(&tv_end, NULL);
			printf(" - Search took %.05f CPU seconds\n",
			       (tv_end.tv_sec - tv_start.tv_sec) +
			       (tv_end.tv_usec - tv_start.tv_usec)/1000000.0);
			result_print(&result);
		}
	}
	return 0;
}
