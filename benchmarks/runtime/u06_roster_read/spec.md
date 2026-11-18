# Shift roster

`GET /shifts?account=ada` returns 200 and only that account's shifts, each with `id` and `title`. One read is enough. The handler does not write. A missing account is 400. Another account's title is absent. Any other method or path is 404.
