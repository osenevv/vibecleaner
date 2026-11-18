# Shift clock

`still_on_shift` is true only when `now` is strictly before `shift_end`. Both values are timezone-aware instants. Compare the instants, not the wall-clock numbers. Equal instants are not still on shift. A naive datetime raises `ValueError`.

22:00 UTC is still on a shift that ends at 18:30 in America/New_York on the same calendar date, because that close is 23:30 UTC.
