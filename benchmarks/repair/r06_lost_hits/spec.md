# Turnstile hits

`HitCounter.hit` counts every call, including a call made by a listener before the outer call returns. Listeners run after that hit has been added, so a listener that reads `total` sees the new value. Two plain calls and no listeners leave `total` at 2. One call whose listener makes one more `hit` leaves `total` at 2.
