@@
expression E;
@@

- if (E != NULL) {
- 	io_remove_closed(&E);
- }
+ io_remove_closed(&E);
