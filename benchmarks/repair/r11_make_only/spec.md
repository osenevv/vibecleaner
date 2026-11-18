# Page lines

`page.sh` prints one 1-based page of the items that follow `PAGE` and `SIZE`. A page holds `SIZE` items, and the last page may be shorter. A page past the end prints nothing. `PAGE` or `SIZE` below 1 exits with status 2 and writes an error to stderr.

The first page of `bolt nut washer screw` with size 2 is `bolt` then `nut`. The second page is `washer` then `screw`. Size 1 returns that one item.
