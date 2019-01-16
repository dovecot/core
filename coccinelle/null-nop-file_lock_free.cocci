@@
expression E;
@@

- if (E != NULL) {
- 	file_lock_free(&E);
- }
+ file_lock_free(&E);
