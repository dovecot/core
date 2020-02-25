/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "randgen.h"
#include "time-util.h"
#include "strnum.h"
#include "compression.h"

#include <stdio.h>
#include <unistd.h>
#include <time.h>

/**
 * Generates semi-compressible data in blocks of given size, to mimic emails
 * remotely and then compresses and decompresses it using each algorithm.
 * It measures the time spent on this giving some estimate how well the data
 * compressed and how long it took.
 */

static void bench_compression_speed(const struct compression_handler *handler,
				    unsigned int level, unsigned long block_count)
{
	struct istream *is = i_stream_create_file("decompressed.bin", 1024);
	struct ostream *os = o_stream_create_file("compressed.bin", 0, 0644, 0);
	struct ostream *os_compressed = handler->create_ostream(os, level);
	o_stream_unref(&os);

	const unsigned char *data;
	uint64_t ts_0, ts_1;
	size_t siz;
	double compression_speed, decompression_speed;

	ts_0 = i_nanoseconds();

	while (i_stream_read_more(is, &data, &siz) > 0) {
		o_stream_nsend(os_compressed, data, siz);
		i_stream_skip(is, siz);
	}

	if (is->stream_errno != 0)
		printf("Error: %s\n", i_stream_get_error(is));

	i_assert(o_stream_finish(os_compressed) == 1);
	o_stream_unref(&os_compressed);
	i_stream_unref(&is);

	ts_1 = i_nanoseconds();

	/* check ratio */
	struct stat st_1, st_2;
	if (stat("decompressed.bin", &st_1) != 0)
		i_fatal("stat(decompressed.bin): %m");
	if (stat("compressed.bin", &st_2) != 0)
		i_fatal("stat(compressed.bin): %m");

	double ratio = (double)st_2.st_size / (double)st_1.st_size;

	compression_speed = ((double)(ts_1-ts_0))/((double)block_count);
	compression_speed /= 1000.0L;

	is = i_stream_create_file("compressed.bin", 1024);
	os = o_stream_create_file("decompressed.bin", 0, 0644, 0);
	struct istream *is_decompressed = handler->create_istream(is, FALSE);
	i_stream_unref(&is);

	ts_0 = i_nanoseconds();

	while (i_stream_read_more(is_decompressed, &data, &siz) > 0) {
		o_stream_nsend(os, data, siz);
		i_stream_skip(is_decompressed, siz);
	}

	if (is_decompressed->stream_errno != 0)
		printf("Error: %s\n", i_stream_get_error(is_decompressed));

	i_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
	i_stream_unref(&is_decompressed);

	ts_1 = i_nanoseconds();

	decompression_speed = ((double)(ts_1 - ts_0))/((double)block_count);
	decompression_speed /= 1000.0L;

	printf("%s\n", handler->name);
	printf("\tCompression: %0.02lf us/block\n\tSpace Saving: %0.02lf%%\n",
	       compression_speed, (1.0-ratio)*100.0);
	printf("\tDecompression: %0.02lf us/block\n\n", decompression_speed);

}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s block_size count level\n", prog);
	fprintf(stderr, "Runs with 1000 8k blocks using level 6 if nothing given\n");
	exit(1);
}

int main(int argc, const char *argv[])
{
	unsigned int level = 6;
	lib_init();

	unsigned long block_size = 8192UL;
	unsigned long block_count = 1000UL;

	if (argc >= 3) {
		if (str_to_ulong(argv[1], &block_size) < 0 ||
		    str_to_ulong(argv[2], &block_count) < 0) {
			fprintf(stderr, "Invalid parameters\n");
			print_usage(argv[0]);
		}
		if (argc == 4 &&
		    str_to_uint(argv[3], &level) < 0) {
			fprintf(stderr, "Invalid parameters\n");
			print_usage(argv[0]);
		}
		if (argc > 4) {
			print_usage(argv[0]);
		}
	} else if (argc != 1) {
		print_usage(argv[0]);
	}

	unsigned char buf[block_size];
	printf("Input data is %lu blocks of %lu bytes\n\n", block_count, block_size);

	time_t t0 = time(NULL);

	/* create plaintext file */
	struct ostream *os = o_stream_create_file("decompressed.bin", 0, 0644, 0);
	for (unsigned long r = 0; r < block_count; r++) {
		time_t t1 = time(NULL);
		if (t1 - t0 >= 1) {
			printf("Building block %8lu / %-8lu\r", r, block_count);
			fflush(stdout);
			t0 = t1;
		}
		for (size_t i = 0; i < sizeof(buf); i++) {
			if (i_rand_limit(3) == 0)
				buf[i] = i_rand_limit(4);
			else
				buf[i] = i;
		}
		o_stream_nsend(os, buf, sizeof(buf));
	}

	i_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);

	printf("Input data constructed          \n");

	for (unsigned int i = 0; compression_handlers[i].name != NULL; i++) T_BEGIN {
		if (compression_handlers[i].create_istream != NULL) {
			bench_compression_speed(&compression_handlers[i], level,
						block_count);
		}
	} T_END;

	i_unlink("decompressed.bin");
	i_unlink("compressed.bin");

	lib_deinit();
}
