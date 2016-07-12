#ifndef TEST_LIB
#define TEST_LIB

#include "lib.h"
#include "test-common.h"

#define TEST(x) TEST_DECL(x)
#define FATAL(x) FATAL_DECL(x)
#include "test-lib.inc"
#undef TEST
#undef FATAL

#endif
