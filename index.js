'use strict';

var nacl = require('tweetnacl')

var base64ToString = nacl.util.encodeBase64
var stringToBase64 = nacl.util.decodeBase64
var utf8ToString = nacl.util.encodeUTF8
var stringToUtf8 = nacl.util.decodeUTF8

// {
//   publicKey: 'HXbBUOqgrrbwqTvru9dmJ2WuNJGwj6/RHWzfBzn3CBg=7a9gRZHMtKPOppOF3ADJFYhmX23vBCS25hR0Z1Q15pw=',
//   secretKey: 'waZruVMkTFMCxRd8ubGN3ZpmdMGBNuaO7wIcFH+4RoU='
// }

function cbTick (result, callback) {
  process.nextTick(function () {
    callback(null, result)
  })
}

exports.keys = function (a, b) {
  var secretKey, callback, box

  if (typeof a === 'function') {
    callback = a
    box = nacl.box.keyPair()
  } else {
    secretKey = stringToBase64(a)
    callback = b
    box = nacl.box.keyPair.fromSecretKey(secretKey)
  }

  var sign = nacl.sign.keyPair.fromSeed(box.secretKey)

  var result = {
    publicKey: base64ToString(box.publicKey) + base64ToString(sign.publicKey),
    secretKey: base64ToString(box.secretKey)
  }

  cbTick(result, callback)
}

exports.makeNonce = function (callback) {
  cbTick(
    base64ToString(nacl.randomBytes(24)),
    callback
  )
}

exports.box = function (string, nonce, theirPublicKey, mySecretKey, callback) {
  string = stringToUtf8(string)
  nonce = stringToBase64(nonce)
  theirPublicKey = stringToBase64(theirPublicKey.slice(0, 44))
  mySecretKey = stringToBase64(mySecretKey)

  cbTick(
    base64ToString(nacl.box(string, nonce, theirPublicKey, mySecretKey)),
    callback
  )
}

exports.box.open = function (box, nonce, theirPublicKey, mySecretKey, callback) {
  box = stringToBase64(box)
  nonce = stringToBase64(nonce)
  theirPublicKey = stringToBase64(theirPublicKey.slice(0, 44))
  mySecretKey = stringToBase64(mySecretKey)

  cbTick(
    utf8ToString(nacl.box.open(box, nonce, theirPublicKey, mySecretKey)),
    callback
  )
}

exports.sign = function (string, secretKey, callback) {
  string = stringToUtf8(string)
  secretKey = nacl.sign.keyPair.fromSeed(
    stringToBase64(secretKey)
  ).secretKey

  cbTick(
    base64ToString(nacl.sign.detached(string, secretKey)),
    callback
  )
}

exports.sign.verify = function (string, signature, publicKey, callback) {
  string = stringToUtf8(string)
  signature = stringToBase64(signature)
  publicKey = stringToBase64(publicKey.slice(44))

  cbTick(
    nacl.sign.detached.verify(string, signature, publicKey),
    callback
  )
}

exports.secretbox = function (string, nonce, secretKey, callback) {
  string = stringToUtf8(string)
  nonce = stringToBase64(nonce)
  secretKey = stringToBase64(secretKey)

  cbTick(
    base64ToString(nacl.secretbox(string, nonce, secretKey)),
    callback
  )
}

exports.secretbox.open = function (box, nonce, secretKey, callback) {
  box = stringToBase64(box)
  nonce = stringToBase64(nonce)
  secretKey = stringToBase64(secretKey)

  cbTick(
    utf8ToString(nacl.secretbox.open(box, nonce, secretKey)),
    callback
  )
}

exports.hash = function (string, callback) {
  string = stringToUtf8(string)
debugger
  cbTick(
    base64ToString(nacl.hash(string)),
    callback
  )
}
