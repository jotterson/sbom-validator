# sbom-validator

## Purpose

This project uses checksum (really sha256) values to validate the
integrity of files in a software package release.

## Use Cases

The intended use cases are as follows:

1. a SBOM is initially created using the `bootstrapper.py` script.
2. at build time, the build output is validated using the `validate.py` script.
3. the same `validate.py` script can be used to validate the integrity of the application release's file once installed on a customer environment.

## What's Here

* bootstrapper.py -- create the initial SBOM.  Though this could be used later in the build process (e.g. post-build) that is not the intention.  The use case for this utility is to run it once, then edit the SBOM file as the dependencies change.
* validator.py -- this validates an application's files on disk by comparing file presence and sha256 hash values.  Missing/extra files are detected and reported, as are hash mis-matches.

## Caveats

The tools-python 'spdx' library on which this depends does not comply
with the SPDX-2.1 standard, there is no support for multiple file types, and no support for multiple file checksums.  Consequently, this currently uses a patched library.  The patched library is currently at https://github.com/jotterson/tools-python