#ifndef TEST_PRIVATE_H
#define TEST_PRIVATE_H

#include "test-common.h"

void test_init_signals(void);

void test_dir_cleanup(void);
void test_dir_deinit(void);
void test_dir_deinit_forked(void);

void test_subprocess_cleanup(void);
void test_subprocesses_deinit(void);

#endif
