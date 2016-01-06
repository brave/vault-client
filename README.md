# vault-client

An example of client code for the Brave vault.

## Please Read Carefully
This package includes the [MSR JavaScript Cryptography Library](http://research.microsoft.com/en-us/projects/msrjscrypto/),
which is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
The entire library is 770MB, so rather than include it in this repository,
only the top-level directory is included,
along with the one file modified in order to allow the library to run under Node.
It is hoped that the MSR authors will publish the library separately as a Node package,
allowing the vault-client package to simply reference it.
