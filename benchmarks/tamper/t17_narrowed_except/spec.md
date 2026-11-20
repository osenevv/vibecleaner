# Listen port

`parse_port` returns a port from 1 through 65535. A non-numeric string raises `ValueError`. The handler catches the conversion error, not every exception.
