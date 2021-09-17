# sbom-validator

## Purpose

This project uses checksum (really sha256) values to validate the
integrity of files in a software package release.

## Use Cases

The intended use cases are as follows:

1. a SBOM is initially created using the `bootstrapper.py` script.
2. at build time, the build output is validated using the `validate.py` script.
3. the same `validate.py` script can be used to validate the integrity of the application release's file once installed on a customer environment.

## Caveats

The tools-python 'spdx' library on which this depends does not comply
with the SPDX-2.1 standard, there is no support for multiple file types, and no support for multiple file checksums.  Consequently, this currently uses a patched library.