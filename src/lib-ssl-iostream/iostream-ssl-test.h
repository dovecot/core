#ifndef IOSTREAM_SSL_TEST_H
#define IOSTREAM_SSL_TEST_H

struct ssl_iostream_settings;

void ssl_iostream_test_settings_server(struct ssl_iostream_settings *test_set);
struct ssl_iostream_settings *ssl_iostream_test_settings_client(void);

#endif
