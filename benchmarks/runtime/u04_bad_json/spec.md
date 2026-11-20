# Booking form

`POST /bookings` with a JSON object `{"name": "Ada"}` returns 201 and that name. A body that is not JSON returns 400. A JSON object without a non-empty name returns 400. The handler does not crash.
