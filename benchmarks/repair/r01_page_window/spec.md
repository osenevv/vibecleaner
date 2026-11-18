# Pick-list pages

`page_rows` returns one page of a pick list. Page numbers and page sizes start at 1. A page holds `size` rows, and the last page may be shorter. A page past the end is empty. Page or size below 1 raises `ValueError`.

The first page of `bolt, nut, washer, screw` with size 2 is `bolt, nut`. The second page is `washer, screw`.
