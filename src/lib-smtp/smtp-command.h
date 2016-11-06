#ifndef SMTP_COMMAND_H
#define SMTP_COMMAND_H

#define SMTP_COMMAND_DEFAULT_MAX_PARAMETERS_SIZE  4*1024
#define SMTP_COMMAND_DEFAULT_MAX_AUTH_SIZE        8*1024
#define SMTP_COMMAND_DEFAULT_MAX_DATA_SIZE        40*1024*1024

struct smtp_command_limits {
	/* Maximum size of command parameters, starting after first space */
	uoff_t max_parameters_size;
	/* Maximum size of authentication response */
	uoff_t max_auth_size;
	/* Absolute maximum size of command data, beyond which the parser yields
	   a fatal error; i.e. closing the connection in the server. This should
	   be higher than a normal message size limit, which would return a
	   normal informative error. The limit here just serves to protect
	   against abuse. */
	uoff_t max_data_size;
};

struct smtp_command {
	const char *name;
	const char *parameters;
};

static inline void
smtp_command_limits_merge(struct smtp_command_limits *limits,
			  const struct smtp_command_limits *new_limits)
{
	if (new_limits->max_parameters_size > 0)
		limits->max_parameters_size = new_limits->max_parameters_size;
	if (new_limits->max_auth_size > 0)
		limits->max_auth_size = new_limits->max_auth_size;
	if (new_limits->max_data_size > 0)
		limits->max_data_size = new_limits->max_data_size;
}

#endif
