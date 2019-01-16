@@
expression E;
@@

- if (E != NULL) {
- 	buffer_free(&E);
- }
+ buffer_free(&E);
