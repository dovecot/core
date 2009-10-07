#ifndef SSL_BUILD_PARAMS_H
#define SSL_BUILD_PARAMS_H

struct ssl_params_settings;

typedef void ssl_params_callback_t(const unsigned char *data, size_t size);

struct ssl_params *
ssl_params_init(const char *path, ssl_params_callback_t *callback,
		const struct ssl_params_settings *set);
void ssl_params_deinit(struct ssl_params **param);

void ssl_params_refresh(struct ssl_params *param);

void ssl_generate_parameters(int fd, const char *fname);

#endif
