# Workshop enrollment

`enroll` accepts a name and a seat count. The name is text, and the stored name is stripped. A blank name raises `ValueError`. Seats are a whole number of at least 1; zero, fractions, and non-numeric values raise `ValueError`. A missing field, or a name that is not text, raises `ValueError` rather than `KeyError` or `AttributeError`.

`{"name": " Ada ", "seats": "2"}` stores `Ada` and `2`.
