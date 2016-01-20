#!/usr/bin/env node

var fs = require('fs')
var path = require('path')
var url = require('url')

/*
 *
 * parse the command arguments
 *
 */

var usage = function (command) {
  if (typeof command !== 'string') command = 'get|put|rm [ args... ]'
  console.log('usage: node ' + path.basename(process.argv[1]) + ' [ -f file ] [ [ -s https://... ] | [-u personaURL] ] [ -v ]' +
              command)
  process.exit(1)
}

usage.get = function () {
  usage('get [ -s \'*\' | -s sessionId ] [ -t type ]')
}

usage.put = function () {
  usage('put [ -t type [ -s sessionID ] ] [ JSON.stringify(...) ]')
}

usage.qr = function () {
  usage('qr')
}

usage.rm = function () {
  usage('rm [ -t type [ -s sessionID ] ]')
}

var personaURL, server
var argv = process.argv.slice(2)
var configFile = process.env.CONFIGFILE || 'config.json'
var verboseP = process.env.VERBOSE || false

while (argv.length > 0) {
  if (argv[0].indexOf('-') !== 0) break

  if (argv[0] === '-v') {
    verboseP = true
    argv = argv.slice(1)
    continue
  }

  if (argv.length === 1) usage()

  if (argv[0] === '-f') configFile = argv[1]
  else if (argv[0] === '-s') server = argv[1]
  else if (argv[0] === '-u') personaURL = argv[1]
  else usage()

  argv = argv.slice(2)
}
if (personaURL) {
  if (server) usage()
} else {
  if (!server) server = process.env.SERVER || 'https://vault-staging.brave.com'
  if (server.indexOf('http') !== 0) server = 'https://' + server
  server = url.parse(server)
}

/*
 *
 * create/recover state
 *
 */

var client

fs.readFile(personaURL ? '/dev/null' : configFile, { encoding: 'utf8' }, function (err, data) {
  var state = personaURL || (err ? null : JSON.parse(data))

  client = require('./index.js')({ server: server, verboseP: verboseP }, state, function (err, result) {
    if (err) oops('client', err)

    if (!result) return run()

    fs.writeFile(configFile, JSON.stringify(result, null, 2), { encoding: 'utf8', mode: parseInt('644', 8) }, function (err) {
      if (err) oops(configFile, err)

      run()
    })
  })
})

/*
 *
 * process the command
 *
 */

var run = function () {
  var argv0

  if (argv.length === 0) argv = [ 'get' ]
  argv0 = argv[0]
  argv = argv.slice(1)

  try {
    ({ get: get,
       put: put,
       qr: qr,
       rm: rm
     }[argv0] || usage)(argv)
  } catch (err) {
    oops(argv0, err)
  }
}

var done = function (command) {
  if (typeof command !== 'string') command = ''
  else command += ' '
  if (verboseP) console.log(command + 'done.')

  process.exit(0)
}

/*
 *
 * read/list persona/session data
 *
 */

var get = function (argv) {
  var sessionId, type, uuid

  while (argv.length > 0) {
    if ((argv[0].indexOf('-') !== 0) || (argv.length === 1)) return usage.get()

    if (argv[0] === '-s') sessionId = argv[1]
    else if (argv[0] === '-t') type = argv[1]
    else return usage.get()

    argv = argv.slice(2)
  }

  if ((type) && (!sessionId)) sessionId = true
  if (sessionId) {
    if (sessionId !== '*') {
      uuid = sessionId.split('-').join('')
      if ((uuid.length !== 32) || (uuid.substr(12, 1) !== '4')) oops('get', new Error('invalid sessionId: ' + sessionId))
    }
  }

  if ((sessionId !== '*') && (((sessionId) && (type)) || (!sessionId) && (!type))) {
    return client.read({ sessionId: sessionId, type: type }, function (err, result) {
      if (err) oops('read', err)

      console.log(JSON.stringify(result, null, 2))
      done('get')
    })
  }

  if (sessionId === '*') sessionId = undefined
  client.list({ sessionId: sessionId, type: type }, function (err, result) {
    if (err) oops('list', err)

    result.forEach(function (entry) {
      console.log(JSON.stringify(entry, null, 2))
    })
    done('get')
  })
}

/*
 *
 * write persona/session data
 *
 */

var put = function (argv) {
  var argv0, object1, object2, sessionId, type, uuid

  while (argv.length > 1) {
    if (argv[0].indexOf('-') !== 0) return usage.put()

    if (argv[0] === '-s') sessionId = argv[1]
    else if (argv[0] === '-t') type = argv[1]
    else return usage.put()

    argv = argv.slice(2)
  }
  argv0 = argv[0] || JSON.stringify({ hello: 'i must be going...' })
  if (argv0.indexOf('-') === 0) return usage.put()

  if (type) {
    if (!sessionId) sessionId = true
  } else if (sessionId) return usage.put()

  if (sessionId) {
    uuid = sessionId.split('-').join('')
    if ((uuid.length !== 32) || (uuid.substr(12, 1) !== '4')) oops('put', new Error('invalid sessionId: ' + sessionId))
  }

  try { object2 = JSON.parse(argv0) } catch (err) { oops('put', err) }
  client.write({ sessionId: sessionId, type: type }, object1, object2, function (err) {
    if (err) oops('write', err)

    done('put')
  })
}

/*
 *
 * generate a persona QR code
 *
 */

var qr = function (argv) {
  if (argv.length > 0) return usage.qr()

  client.qrcodeURL({ }, function (err, result) {
    if (err) oops('qrcodeURL', err)

    console.log(result)

    done('qr')
  })
}

/*
 *
 * remove persona/session data
 *
 */

var rm = function (argv) {
  var sessionId, type

  while (argv.length > 0) {
    if (argv[0].indexOf('-') !== 0) return usage.rm()

    if (argv[0] === '-s') sessionId = argv[1]
    else if (argv[0] === '-t') type = argv[1]
    else return usage.rm()

    argv = argv.slice(2)
  }

  if (type) {
    if (!sessionId) sessionId = true
  } else if (sessionId) return usage.rm()

  client.remove({ sessionId: sessionId, type: type }, function (err) {
    if (err) oops('remote', err)

    if (sessionId) return done('rm')

    fs.unlink(configFile, function (err) {
      if (err) oops(configFile, err)

      done('rm')
    })
  })
}

var oops = function (s, err) {
  console.log(s + ': ' + err.toString())
  console.log(err.stack)
  process.exit(1)
}
