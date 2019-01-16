@@
expression E;
@@

- if (hash_table_is_created(E)) {
- 	hash_table_destroy(&E);
- }
+ hash_table_destroy(&E);
