# Workshop notes

`POST /notes` with header `X-Account` and JSON `{"title": "dock", "body": "north"}` returns 201 and an id. A body that is not JSON returns 400. A missing title returns 400. `GET /notes/<id>` with the owning account returns 200 and the note. A different account gets 404 and does not receive the body. GET does not write.
