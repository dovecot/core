@@
expression E;
@@

- if (E != NULL) {
- 	dict_transaction_rollback(&E);
- }
+ dict_transaction_rollback(&E);
