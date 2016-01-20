# vault-client

An example of client code for the Brave vault.

## Please Read Carefully
This package includes the [MSR JavaScript Cryptography Library](http://research.microsoft.com/en-us/projects/msrjscrypto/),
which is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
The entire library is 770MB, so rather than include it in this repository,
only the top-level directory is included,
along with the one file modified in order to allow the library to run under Node.
(In the `minimized` branch, only a minified version of the modified file is present.)
It is hoped that the MSR authors will publish the library separately as a Node package,
allowing the vault-client package to simply reference it.

## API

To begin:

- The client must maintain a secure, persistent storage in which it can store a JSON object.

- There are two kinds of data: persona-global data and session-specific data:

    - The api will manage a "default" `sessionId`; however, the client is free to supply any `sessionId` it wishes.

    - To access (read/write/remove) session-specific data, both a `sessionId` and a `type` string must be specified
    (by convention, a `sessionId` of `true` indicates the "default" `sessionId`).

### Creating an Endpoint

        var client = require('vault-client')
        this.client = new client(options, state, function (err, result) { ... })

where `options` is:

        { server   :   'http://vault-staging.brave.com'
        , verboseP : false
        }

and `state` is whatever was previously stored in persistent storage, or `{}`, or a URL string from a decoded QRcode.

The  client endpoint should not be referenced until the callback is invoked.
When the callback is invoked, if `err` is `null`, and `result` is defined, then `result` must be put into persistent storage.
(If `err` is `null`,
then the operation has succeeded,
regardless of whether `result` is defined or not.)

### Reading Persona Data

        this.client.read(options, function (err, result) { ... })

where `options` is:

        { sessionId : true || string || undefined
        , type      :         string || undefined
        }

If `options.sessionId` is defined, then `options.type` must also be defined (and vice-versa) -- if either is defined, then
session-specific data is returned; otherwise persona-global data is returned.

If `err` is `null`, then result is:

        { object1 : { ... }
        , object2 : { ... }
        }

where `object1` contains those properties that are stored at the vault in plaintext,
and `object2` contains those properties that are stored at the vault in ciphertext.

### Writing Persona Data

        this.client.write(options, object1, object2, function (err) { ... })

where `options` is the same as with `this.client.read`,
`object1` will be stored in the vault as plaintext,
and `object2` will be encrypted and then stored in the vault as ciphertext.

### Removing Persona Data

        this.client.remove(options, function (err) { ... })

where `options` is the same as with `this.client.read`.
If `options.sessionId` is not defined, then the entire persona is deleted, and the client object is now invalid.

### Listing Session-Specific data for a Persona

        this.client.list(options, function (err, result) { ... })

where `options` is the same as with `this.client.read` _except_ that either (or both) `sessionId` or `type` may be `undefined`.

If `err` is `null`, then result is:

        [ { sessionId : string
          , type      : string
          , object1   : { ... }
          , object2   : { ... }
          }
        , ...
        ]

### Generating a URL string for QRcodes

        this.client.qrcodeURL(options, function (err, result) { ... })

where `options` is currently ignored.

The result given to the callback (a string) may be passed to a QRcode generation routine to be scanned by another client.
The second client should (after parsing the QRcode) use the resulting URL string as the `state` parameter to `new client()`.


## Examples

        var client = require('vault-client')
        var state = /* retrieved from secure, persistent storage or {} */
        var readyP = false
        this.client = new client({}, state, function (err, result) {
          if (err) return ...

          readyP = true
          if (result) /* store into secure, persistent storage */
        })

        ...

        // save this client's history
        this.client.write({ sessionId: true, type: 'history' }, null, { ... }, function(err) {
            if (err) return ...
        })

        // get session-specific history for all clients
        this.client.list({ type: 'history' }, null, { ... }, function(err) {
            if (err) return ...
        })

        // get all session-specific data for the default sessionId
        this.client.list({ sessionId: true }, null, { ... }, function(err) {
            if (err) return ...
        })

        // get all session-specific data for a particular session
        this.client.list({ sessionId: sessionId }, null, { ... }, function(err) {
            if (err) return ...
        })

You can also take a look at the file `example.js`.