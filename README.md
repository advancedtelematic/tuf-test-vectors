# tuf-test-vectors

A collection of test vectors that can be used to verify if a TUF or Uptane
client conforms to the specification with regards to processing metadata and
targets.

## Vectors

This repo contains `server.py` which provides an interactive API that directs
clients on how to perform updates. A client should use the following steps to
run through all the test vectors.

### List Vectors

Client does a `GET` on `/` to receive a JSON array of strings naming the rest of
the vectors.

```bash
$ curl localhost:8080/
["vector_1", "another_vector", ... ]
```

### Initialize the Vector

Because the vectors need to simulate time (via a "step"), each vector needs to
be intialized with a `POST`.

```bash
$ curl -X POST localhost:8080/$vector_name/step
{
  "update": {
    "is_success": true
  },
  "targets": {
    "file.txt": {
        "is_success": true
     }
  }
}
```

The response will tell you what the result of an update cycle should be as well
as what targets to download and whether or not they should validate. If there
are errors, both the `update` and `target` object will have `err` and `err_msg`
along with `is_success`. `err` will be machine parseable and attempts to
enumerate common types and `err_msg` is a plain English sentance.

### Update the Local Metadata

The client should attempt to do a full update of all metadata as defined in the
spec, and the success of this update should match `update.is_success`.

### Download and Verify Targets

The client should download and verify the target. The success of this should
match `targets.$target_name.is_success`.

### Step

The client should `POST` to the same endpoint `/$vector_name/step` and repeate.
If the call to "step" returns `HTTP 204`, then the client is done.

### Reset

To reset the vector, the client may `POST` to `/$vector_name/reset`. The client
may run tests in parallel, but the client may not run many tests against the
same one vector in parallel.

## License

This code is licensed under the [MIT license](COPYING.MIT), a copy of which can be found in this repository. All code is copyright HERE Europe B.V., 2017-2020.

We require that contributors accept the terms of Linux Foundation's [Developer Certificate of Origin](https://developercertificate.org/). Please see the [contribution instructions of aktualizr](https://github.com/advancedtelematic/aktualizr/blob/master/CONTRIBUTING.md) for more information.
