#ifndef MECH_OTP_SKEY_COMMON_H
#define MECH_OTP_SKEY_COMMON_H

struct otp_auth_request {
	struct auth_request auth_request;

	pool_t pool;

	int lock;

	struct otp_state state;
};

void otp_lock_init(void);
int otp_try_lock(struct auth_request *auth_request);
void otp_unlock(struct auth_request *auth_request);

void otp_set_credentials_callback(bool success,
				  struct auth_request *auth_request);
void mech_otp_skey_auth_free(struct auth_request *auth_request);

#endif
