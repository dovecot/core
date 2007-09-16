#ifndef MYCRYPT_H
#define MYCRYPT_H

/* A simple wrapper to crypt(). Problem with it is that it requires
   _XOPEN_SOURCE define which breaks other things. */
char *mycrypt(const char *key, const char *salt);

#endif
