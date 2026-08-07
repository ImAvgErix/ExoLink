# Exocord SQLx compatibility facade

This is a narrow compatibility facade derived from the public re-export
surface of SQLx 0.8.6. Exocord uses PostgreSQL only and does not use SQLx's
compile-time query macros.

The upstream optional MySQL and macro dependencies were removed so an
uncompiled RSA dependency with an unfixed timing advisory does not enter the
release lockfile. The underlying `sqlx-core` and `sqlx-postgres` crates remain
the unmodified upstream 0.8.6 releases.

SQLx is distributed under the MIT or Apache-2.0 licenses.
