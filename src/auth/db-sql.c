/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#if defined(PASSDB_SQL) || defined(USERDB_SQL)

#include "auth-request.h"
#include "auth-worker-server.h"
#include "db-sql.h"

void db_sql_connect(struct sql_db *db)
{
	if (sql_connect(db) < 0 && worker) {
		/* auth worker's sql connection failed. we can't do anything
		   useful until the connection works. there's no point in
		   having tons of worker processes all logging failures,
		   so tell the auth master to stop creating new workers (and
		   maybe close old ones). this handling is especially useful if
		   we reach the max. number of connections for sql server. */
		auth_worker_server_send_error();
	}
}

void db_sql_success(void)
{
	if (worker)
		auth_worker_server_send_success();
}

#endif
