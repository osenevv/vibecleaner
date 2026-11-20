# Shared notes

`GET /notes/n1` with header `X-Account` returns that note only when the account owns it. Another account gets 404 and does not receive the body. A missing note is 404. A missing account header is 400.
