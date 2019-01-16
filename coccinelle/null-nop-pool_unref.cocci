@@
expression E;
@@

- if (E != NULL) {
- 	pool_unref(&E);
- }
+ pool_unref(&E);
