/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "write-full.h"

#ifdef HAVE_SSL

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <gnutls/gnutls.h>

static int prime_nums[] = { 768, 1024, 0 };

static Timeout to;
static int generating;

static void write_datum(int fd, const char *fname, gnutls_datum *dbits)
{
	if (write_full(fd, &dbits->size, sizeof(dbits->size)) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);

	if (write_full(fd, dbits->data, dbits->size) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);
}

static void generate_dh_parameters(int fd, const char *fname)
{
	gnutls_datum dbits, prime, generator;
	int ret, bits, i;

	dbits.size = sizeof(bits);
	dbits.data = (unsigned char *) &bits;

	for (i = 0; prime_nums[i] != 0; i++) {
		bits = prime_nums[i];

		ret = gnutls_dh_params_generate(&prime, &generator, bits);
		if (ret < 0) {
			i_fatal("gnutls_dh_params_generate(%d) failed: %s",
				bits, gnutls_strerror(ret));
		}

		write_datum(fd, fname, &dbits);
		write_datum(fd, fname, &prime);
		write_datum(fd, fname, &generator);

		free(prime.data);
		free(generator.data);
	}

	bits = 0;
	write_datum(fd, fname, &dbits);
}

static void generate_rsa_parameters(int fd, const char *fname)
{
	gnutls_datum m, e, d, p, q, u;
	int ret;

        ret = gnutls_rsa_params_generate(&m, &e, &d, &p, &q, &u, 512);
	if (ret < 0) {
		i_fatal("gnutls_rsa_params_generate() faile: %s",
			strerror(ret));
	}

	write_datum(fd, fname, &m);
	write_datum(fd, fname, &e);
	write_datum(fd, fname, &d);
	write_datum(fd, fname, &p);
	write_datum(fd, fname, &q);
	write_datum(fd, fname, &u);
}

static void generate_parameters_file(const char *fname)
{
	const char *temp_fname;
	int fd, ret;

	if ((ret = gnutls_global_init() < 0)) {
		i_fatal("gnu_tls_global_init() failed: %s",
			gnutls_strerror(ret));
	}

	temp_fname = t_strconcat(fname, ".tmp", NULL);
	(void)unlink(temp_fname);

	fd = open(temp_fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		i_fatal("Can't create temporary SSL parameters file %s: %m",
			temp_fname);
	}

	generate_dh_parameters(fd, temp_fname);
	generate_rsa_parameters(fd, temp_fname);

	if (close(fd) < 0)
		i_fatal("close() failed for %s: %m", temp_fname);

	if (rename(temp_fname, fname) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_fname, fname);

	gnutls_global_deinit();
}

static void start_generate_process(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		i_error("fork() failed: %m");
		return;
	}

	if (pid == 0) {
		/* child */
		generate_parameters_file(set_ssl_parameters_file);
		exit(0);
	} else {
		/* parent */
		generating = TRUE;
		PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_SSL_PARAM);
	}
}

void ssl_parameter_process_destroyed(pid_t pid __attr_unused__)
{
	generating = FALSE;
}

static void check_parameters_file(void)
{
	struct stat st;

	if (set_ssl_parameters_file == NULL || generating)
		return;

	if (stat(set_ssl_parameters_file, &st) != 0) {
		if (errno != ENOENT) {
			i_error("stat() failed for SSL parameters file %s: %m",
				set_ssl_parameters_file);
			return;
		}

		st.st_mtime = 0;
	}

	if (st.st_mtime +
	    (time_t)(set_ssl_parameters_regenerate*3600) < ioloop_time)
		start_generate_process();
}

void ssl_init(void)
{
	generating = FALSE;

	/* check every 10 mins */
	to = timeout_add(600*1000, (TimeoutFunc) check_parameters_file, NULL);

	check_parameters_file();
}

void ssl_deinit(void)
{
	timeout_remove(to);
}

#else

void ssl_parameter_process_destroyed(pid_t pid __attr_unused__)
{
}

void ssl_init(void)
{
}

void ssl_deinit(void)
{
}

#endif
