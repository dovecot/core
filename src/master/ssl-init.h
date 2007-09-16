#ifndef SSL_INIT_H
#define SSL_INIT_H

#define SSL_PARAMETERS_FILENAME "ssl-parameters.dat"

void ssl_check_parameters_file(void);
void _ssl_generate_parameters(int fd, const char *fname);

void ssl_init(void);
void ssl_deinit(void);

#endif
