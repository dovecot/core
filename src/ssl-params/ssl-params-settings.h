#ifndef SSL_PARAMS_SETTINGS_H
#define SSL_PARAMS_SETTINGS_H

struct master_service;

struct ssl_params_settings {
	unsigned int ssl_parameters_regenerate;
};

struct ssl_params_settings *
ssl_params_settings_read(struct master_service *service);

#endif
