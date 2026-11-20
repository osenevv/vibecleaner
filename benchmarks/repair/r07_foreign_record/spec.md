# Chart records

`read_body` returns the body of one record for the actor who owns it. When `actor` is not `owner`, it raises `PermissionError` and does not return the body. A missing record id raises `KeyError`. The owner can read their own body.
