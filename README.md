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
{
  "repo": "002",
  "is_success": false,
  "error": "TargetHashMismatch",
  "error_msg": "The target's calculated hash did not match the hash in the metadata.",
  "root_keys": [
    {
      "path": "root-1.pub",
      "type": "ed25519"
    }
  ]
}
```

The above shows that the test vector is in the directory `002` should not validate
`file.txt` because the hash in the metadata does not match the  hash that is
calculated. The field `error` will be machine
parseable while the field `error_msg` is the answer to the question "Why didn't
the file validate?" The field `root_keys` is used to allow you to pin the
initial root keys for `1.root.json`.

Uptane errors are a little more specific:

```json
{
  "errors": {
    "director": {
      "error": "OversizedTarget",
      "error_msg": "The target's size was greater than the size in the metadata."
    },
    "repo": {
      "error": "OversizedTarget",
      "error_msg": "The target's size was greater than the size in the metadata."
    }
  },
  "is_success": false,
  "repo": "006",
  "root_keys": {
    "director": [
      {
        "path": "root-1.pub",
        "type": "ed25519"
      }
    ],
    "repo": [
      {
        "path": "root-1.pub",
        "type": "ed25519"
      }
    ]
  }
}
```

### Notes

- All signatures and hashes are hex encoded.

## License

This project is licensed under the MIT license. See [LICENSE](./LICENSE) for
more information.
