# Delivery attempts

`deliver` calls `send` up to `attempts` times. A `TimeoutError` tries again until the attempts are used. When the attempts are exhausted, `deliver` raises that `TimeoutError`. It does not return a success value after the last timeout. Any other exception from `send` propagates on the first attempt. A call that returns is passed through unchanged, including a success on a later attempt.
