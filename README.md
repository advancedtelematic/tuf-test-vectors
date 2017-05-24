# tuf-test-vectors

A collection of test vectors that can be used to verify if a TUF or Uptane 
client conforms to the specification with regards to processing metadata and
targets.

## Vectors

The vectors can be found in the `tuf` and `uptane` directories. There is
metadata about the test vectors to allow for programatic testing. The file
`vectors-meta.json` is a list of entries that map to a vector and the expected
outcome.

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
    "error": "TargetHashMismatch",
    "error_msg": "The target's calculated hash did not match the hash in the metadata."
  }
]
```

The above shows that the first test vector is in the directory called `001`, and
that TUF should successfully validate the single file `file.txt`. The repo
called `002` should not validate `file.txt` because the hash in the metadata
should not match the hash that is calculated. The field `error` will be machine
parseable while the field `error_msg` is the answer to the question "Why didn't
the file validate?"

### Notes

- All signatures and hashes are hex encoded.

## License

This project is licensed under the MIT license. See [LICENSE](./LICENSE) for
more information.
