/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "istream-zlib.h"

#ifdef HAVE_BZLIB
#include <stdio.h>
#include <bzlib.h>

#define BZLIB_INCLUDE

#define gzFile BZFILE
#define gzdopen BZ2_bzdopen
#define gzclose BZ2_bzclose
#define gzread BZ2_bzread
#define gzseek BZ2_bzseek
#define gzerror BZ2_bzerror
#define Z_ERRNO BZ_IO_ERROR

#define i_stream_create_zlib i_stream_create_bzlib
#include "istream-zlib.c"
#endif
