# sbom-validator

## Purpose

This project uses cryptographic hashes in a Software Bill Of Materials values to validate the integrity of files in a software package release.

## Use Cases

The intended use cases are as follows:

1. A 'bootstrap' SBOM is initially created using the 
   `create-sbom.py` from the build output.
1. `create-sbom.py` is also used to create a list of 'approved'
   third-party components.
1. The `edit-sbom.py` script is used to set license information on
   the third-party components.
1. `merge-by-sha256` is used to merge the third-party component data
   into the 'bootstrap' SBOM to create the 'ideal' SBOM
3. `merge-and-test.py` is used at the end
   of the build process to compare the build output to the 
   ideal SBOM.  If files that were not identified as build
   outputs in the edit phase have a different hash then a
   warning is raised.  Build outputs get their hashes
   calculated, and the build output SBOM is produced. This step
   will detect mis-matched third-party components.
4. the `validate-sbom.py` script is used to validate the
   integrity of the application release's file once
   installed on a runtime environment.

## What's Here

* `create-sbom.py` -- create sbom by scanning a directory
  tree or a zip file.  This is used to create an initial
  'bootstrap' SBOM, or to create intermediate SBOMs
  during the build process.
* `edit-sbom.py` -- a simple TUI edit tool allows the CRUD operations
  on SBOM files.  The add/edit functionality will allow copyright
  and other metadata to be easily manipulated.
* `merge-and-test.py` -- This is used to test and create a 'release'
  SBOM to accompany a package release.  The third-party dependencies
  are all validated by comparing the hashes.
* `merge-by-sha256.py`-- Used to merge SBOM file metadata based on
  the sha256 'checksums' on the files.  In this case, it is used to
  find and mark the 'blessed' third-party components into an 'ideal'
  SBOM
* `validate-sbom.py` -- this validates an application's
  files on disk by comparing file presence and sha256 
  hash values.  Missing/extrafiles are detected and
  reported, as are hash mis-matches.

## Caveats

The tools-python 'spdx' library on which this depends does
not fully comply with the SPDX-2.1 standard, there is no support
for multiple file types, and no support for multiple file
checksums.  Consequently, this currently uses a patched
library.  The patched library is currently at
https://github.com/jotterson/tools-python -- you can install it like this:

```shell
pip install git+https://github.com/jotterson/tools-python.git@checksums_final#egg=spdx-tools
```

J.B. Otterson 20211206
