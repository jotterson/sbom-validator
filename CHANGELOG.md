# Changes to sbom_validator

## v1.0.0 2021-12-09 Initial release.
Released as part of my CS6767 Cybersecurity Practicum.

I took a problem that made me nervous at work and designed and implemented software to help mitigate this problem.
See the paper at [jotterson6_cs6727_project_report_20211212.docx-compressed.pdf](jotterson6_cs6727_project_report_20211212.docx-compressed.pdf)

# v 1.1.0 2023-06-11 Support SPDX tools-python v0.7.x

Support for latest SPDX tools-python, and, in theory, SPDX version 2.3.

This code no longer needs my fork of tools-python, but works with 'official' support for 
more than one 'checksum' and more than one 'file type'.

JSON storage mode is selected based on specified command line arguments file extension.  If you specify a file name 
that ends with '.json' then JSON format will be used, else SPDX tagged-value format will be used.

# V 1.2.0 2023-08-12 Support SPDX tools-python V0.8.0

Support for latest SPDX tools-python v0.8.0

Minimally tested with zip package inputs.

