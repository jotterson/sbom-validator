# sbom-validator

## Purpose

This project uses cryptographic hashes in a Software Bill Of Materials values to validate the integrity of files in a software package release.

## Use Cases

The intended use cases are as follows:

1. a SBOM is initially created using the `create-sbom.py`
   script.
2. the initial SBOM is 'edited' to mark components that
   are produced by the build.
3. merge and test.  not built yet.  This happens at the end
   of the build process, to compare the build output to the 
   ideal SBOM.  If files that were not identified as build
   outputs in the edit phase have a different hash then a
   warning is raised.  build outputs get their hashes
   calculated, and the build output SBOM is produced.
4. the `validate-sbom.py` script is used to validate the
   integrity of the application release's file once
   installed on a runtime environment.

## What's Here

* `crete-sbom.py` -- create sbom by scanning a directory
  tree or a zip file.  This is used to create an initial
  'bootstrap' SBOM, or to create intermediate SBOMs
  during the build process.
* `edit-sbom.py` -- a simple TUI edit tool allows the 
  BUILD OUTPUT" option to be set on SBOM files.  
  Perhaps more features will be added later, this is 
  what I needed right now.
* `validate-sbom.py` -- this validates an application's
  files on disk by comparing file presence and sha256 
  hash values.  Missing/extrafiles are detected and
  reported, as are hash mis-matches.

## Caveats

The tools-python 'spdx' library on which this depends does
not comply with the SPDX-2.1 standard, there is no support
for multiple file types, and no support for multiple file
checksums.  Consequently, this currently uses a patched
library.  The patched library is currently at
https://github.com/jotterson/tools-python

J.B. Otterson 20211001
