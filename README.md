# tuf-test-vectors

A collection of test vectors that can be used to verify if a TUF client conforms
to the specification with regards to processing metadata and targets.

## Vectors

The vectors can be found in the `vectors` directory. There is metadata about the
test vectors to allow for programatic testing. The file `vectors-meta.json`
is a list of entries that map to a vector and the expected outcome.

For example:

```json
[
  {
    "repo": "001",
    "is_success": true
  },
  {
    "repo": "002",
    "is_success": false,
    "error": "MissingMetadata::Timestamp",
    "error_msg": "The 'timestamp' metadata was missing"
  }
]
```

The above shows that the first test vector is in the directory called `001`, and
that TUF should successfully validate the single file `file.txt`. The repo
called `002` should not validate `file.txt` because it is missing the timestamp
metadata. The field `error` will be machine parseable while the field
`error_msg` is the answer to the question "Why didn't the file validate?"

## License

This project is licensed under the MIT license. See [LICENSE](./LICENSE) for
more information.
