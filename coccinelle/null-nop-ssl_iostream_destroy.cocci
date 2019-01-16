@@
expression E;
@@

- if (E != NULL) {
- 	ssl_iostream_destroy(&E);
- }
+ ssl_iostream_destroy(&E);
