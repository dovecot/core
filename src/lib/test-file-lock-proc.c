/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "array.h"
#include "istream.h"
#include "file-lock-proc.h"

static const char *test_proc_locks_input =
"1: POSIX  ADVISORY  WRITE 1000 00:3f:4873188 100 EOF\n"
"2: POSIX  ADVISORY  READ 1001 00:3f:4873188 10 19\n"
"3: FLOCK  ADVISORY  WRITE 1002 fd:01:1234 0 EOF\n"
"3: -> FLOCK  ADVISORY  WRITE 1003 fd:01:1234 0 EOF\n"
"3:  -> FLOCK  ADVISORY  WRITE 1004 fd:01:1234 0 EOF\n"
"4: OFDLCK ADVISORY  WRITE -1 00:3f:100 0 EOF\n"
"5: POSIX  ADVISORY  WRITE 0 00:3f:101 0 EOF\n"
"6: LEASE  ACTIVE    READ  1005 00:3f:102 0 EOF\n"
"7: POSIX  ADVISORY  READ 1006 <none>:0 0 EOF\n"
"8: POSIX  ADVISORY\n"
"garbage\n";

static void test_file_lock_proc_parse_line(void)
{
	struct proc_lock lock;

	test_begin("file_lock_proc_parse_line()");

	test_assert(file_lock_proc_parse_line(
		"1: POSIX  ADVISORY  WRITE 1000 00:3f:4873188 100 EOF",
		&lock) == 0);
	test_assert(lock.id == 1);
	test_assert(lock.lock_class == PROC_LOCK_CLASS_POSIX);
	test_assert(lock.dev_major == 0 && lock.dev_minor == 0x3f);
	test_assert(lock.ino == 4873188);
	test_assert(lock.start == 100 && lock.end == UOFF_T_MAX);
	test_assert(lock.pid == 1000);
	test_assert(lock.write);
	test_assert(!lock.waiter);

	/* read lock with an explicit end offset */
	test_assert(file_lock_proc_parse_line(
		"2: POSIX  ADVISORY  READ 1001 00:3f:4873188 10 19",
		&lock) == 0);
	test_assert(lock.start == 10 && lock.end == 19);
	test_assert(!lock.write);

	/* waiter, and a waiter of a waiter */
	test_assert(file_lock_proc_parse_line(
		"3: -> FLOCK  ADVISORY  WRITE 1003 fd:01:1234 0 EOF",
		&lock) == 0);
	test_assert(lock.id == 3);
	test_assert(lock.lock_class == PROC_LOCK_CLASS_FLOCK);
	test_assert(lock.dev_major == 0xfd && lock.dev_minor == 0x01);
	test_assert(lock.pid == 1003);
	test_assert(lock.waiter);

	test_assert(file_lock_proc_parse_line(
		"3:  -> FLOCK  ADVISORY  WRITE 1004 fd:01:1234 0 EOF",
		&lock) == 0);
	test_assert(lock.pid == 1004);
	test_assert(lock.waiter);

	/* OFD locks have no owner process */
	test_assert(file_lock_proc_parse_line(
		"4: OFDLCK ADVISORY  WRITE -1 00:3f:100 0 EOF",
		&lock) == 0);
	test_assert(lock.lock_class == PROC_LOCK_CLASS_OFD);
	test_assert(lock.pid == -1);

	/* owner isn't visible in our PID namespace */
	test_assert(file_lock_proc_parse_line(
		"5: POSIX  ADVISORY  WRITE 0 00:3f:101 0 EOF", &lock) == 0);
	test_assert(lock.pid == 0);

	/* lock types we don't know about are still parsed */
	test_assert(file_lock_proc_parse_line(
		"6: LEASE  ACTIVE    READ  1005 00:3f:102 0 EOF",
		&lock) == 0);
	test_assert(lock.lock_class == PROC_LOCK_CLASS_UNKNOWN);

	/* unparseable lines */
	test_assert(file_lock_proc_parse_line(
		"7: POSIX  ADVISORY  READ 1006 <none>:0 0 EOF", &lock) < 0);
	test_assert(file_lock_proc_parse_line("8: POSIX  ADVISORY", &lock) < 0);
	test_assert(file_lock_proc_parse_line("garbage", &lock) < 0);
	test_assert(file_lock_proc_parse_line("", &lock) < 0);
	test_assert(file_lock_proc_parse_line("9:", &lock) < 0);

	test_end();
}

static void test_file_lock_proc_parse(void)
{
	ARRAY_TYPE(proc_lock) locks;
	struct istream *input;
	const struct proc_lock *lock;

	test_begin("file_lock_proc_parse()");

	input = i_stream_create_from_data(test_proc_locks_input,
					  strlen(test_proc_locks_input));
	t_array_init(&locks, 16);
	test_assert(file_lock_proc_parse(input, &locks) == 0);
	i_stream_destroy(&input);

	/* the last 3 lines aren't parseable */
	test_assert(array_count(&locks) == 8);

	lock = array_idx(&locks, 0);
	test_assert(lock->id == 1 && lock->pid == 1000 && !lock->waiter);
	lock = array_idx(&locks, 3);
	test_assert(lock->id == 3 && lock->pid == 1003 && lock->waiter);
	lock = array_idx(&locks, 4);
	test_assert(lock->id == 3 && lock->pid == 1004 && lock->waiter);
	lock = array_idx(&locks, 7);
	test_assert(lock->lock_class == PROC_LOCK_CLASS_UNKNOWN);

	test_end();
}

static const char *test_proc_locks_deadlock_input =
/* pid 100 holds file A, pid 200 is waiting for it */
"1: FLOCK  ADVISORY  WRITE 100 00:01:10 0 EOF\n"
"1: -> FLOCK  ADVISORY  WRITE 200 00:01:10 0 EOF\n"
/* pid 200 holds file B, pid 300 is waiting for it */
"2: FLOCK  ADVISORY  WRITE 200 00:01:20 0 EOF\n"
"2: -> FLOCK  ADVISORY  WRITE 300 00:01:20 0 EOF\n"
/* pid 300 holds file C, pid 100 is waiting for it */
"3: FLOCK  ADVISORY  WRITE 300 00:01:30 0 EOF\n"
"3: -> FLOCK  ADVISORY  WRITE 100 00:01:30 0 EOF\n"
/* pid 400 holds file D and isn't waiting for anything */
"4: FLOCK  ADVISORY  WRITE 400 00:01:40 0 EOF\n";

static void test_file_lock_proc_find_deadlock(void)
{
	const char *data = test_proc_locks_deadlock_input;
	ARRAY_TYPE(proc_lock) locks;
	ARRAY_TYPE(proc_lock_link) chain;
	struct istream *input;
	const struct proc_lock_link *link;

	test_begin("file_lock_proc_find_deadlock()");

	input = i_stream_create_from_data(data, strlen(data));
	t_array_init(&locks, 16);
	test_assert(file_lock_proc_parse(input, &locks) == 0);
	i_stream_destroy(&input);
	test_assert(array_count(&locks) == 7);

	/* pid 200 is directly blocking pid 100 */
	t_array_init(&chain, 8);
	test_assert(file_lock_proc_find_deadlock(&locks, 200, 100, &chain));
	test_assert(array_count(&chain) == 1);
	link = array_idx(&chain, 0);
	test_assert(link->waiter->pid == 200 && link->waiter->ino == 10);
	test_assert(link->holder->pid == 100);

	/* pid 300 blocks pid 100 via pid 200 */
	array_clear(&chain);
	test_assert(file_lock_proc_find_deadlock(&locks, 300, 100, &chain));
	test_assert(array_count(&chain) == 2);
	link = array_idx(&chain, 0);
	test_assert(link->waiter->pid == 300 && link->holder->pid == 200);
	link = array_idx(&chain, 1);
	test_assert(link->waiter->pid == 200 && link->holder->pid == 100);

	/* pid 400 isn't waiting for anything */
	array_clear(&chain);
	test_assert(!file_lock_proc_find_deadlock(&locks, 400, 100, &chain));
	test_assert(array_count(&chain) == 0);

	/* nothing is blocking a pid that isn't in the list */
	array_clear(&chain);
	test_assert(!file_lock_proc_find_deadlock(&locks, 300, 999, &chain));
	test_assert(array_count(&chain) == 0);

	test_end();
}

void test_file_lock_proc(void)
{
	test_file_lock_proc_parse_line();
	test_file_lock_proc_parse();
	test_file_lock_proc_find_deadlock();
}
