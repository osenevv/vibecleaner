# Field-note archive

`save_note` writes `body` to `directory / name` as UTF-8 text and returns that path. It creates `directory` when the parent is missing. An empty body is still written. If the write cannot be completed, the `OSError` propagates to the caller. The function does not report a path for a file it failed to write.
