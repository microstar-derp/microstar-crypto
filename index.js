'use strict';

var nacl = require('tweetnacl')

var base64ToString = nacl.util.encodeBase64
var stringToBase64 = nacl.util.decodeBase64
var utf8ToString = nacl.util.encodeUTF8
var stringToUtf8 = nacl.util.decodeUTF8

// {
//   public_key: 'HXbBUOqgrrbwqTvru9dmJ2WuNJGwj6/RHWzfBzn3CBg=7a9gRZHMtKPOppOF3ADJFYhmX23vBCS25hR0Z1Q15pw=',
//   secret_key: 'waZruVMkTFMCxRd8ubGN3ZpmdMGBNuaO7wIcFH+4RoU='
// }

function cbTick (result, callback) {
  process.nextTick(function () {
    callback(null, result)
  })
}

exports.keys = function (a, b) {
  var secret_key, callback, box

  if (typeof a === 'function') {
    callback = a
    box = nacl.box.keyPair()
  } else {
    secret_key = stringToBase64(a)
    callback = b
    box = nacl.box.keyPair.fromSecretKey(secret_key)
  }

  var sign = nacl.sign.keyPair.fromSeed(box.secretKey)

  var result = {
    public_key: base64ToString(box.publicKey) + base64ToString(sign.publicKey),
    secret_key: base64ToString(box.secretKey)
  }

  cbTick(result, callback)
}

exports.makeNonce = function (callback) {
  cbTick(
    base64ToString(nacl.randomBytes(24)),
    callback
  )
}

exports.box = function (string, nonce, their_public_key, my_secret_key, callback) {
  string = stringToUtf8(string)
  nonce = stringToBase64(nonce)
  their_public_key = stringToBase64(their_public_key.slice(0, 44))
  my_secret_key = stringToBase64(my_secret_key)

  cbTick(
    base64ToString(nacl.box(string, nonce, their_public_key, my_secret_key)),
    callback
  )
}

exports.box.open = function (box, nonce, their_public_key, my_secret_key, callback) {
  box = stringToBase64(box)
  nonce = stringToBase64(nonce)
  their_public_key = stringToBase64(their_public_key.slice(0, 44))
  my_secret_key = stringToBase64(my_secret_key)

  cbTick(
    utf8ToString(nacl.box.open(box, nonce, their_public_key, my_secret_key)),
    callback
  )
}

exports.sign = function (string, secret_key, callback) {
  string = stringToUtf8(string)
  secret_key = nacl.sign.keyPair.fromSeed(
    stringToBase64(secret_key)
  ).secretKey

  cbTick(
    base64ToString(nacl.sign.detached(string, secret_key)),
    callback
  )
}

exports.sign.verify = function (string, signature, public_key, callback) {
  string = stringToUtf8(string)
  signature = stringToBase64(signature)
  public_key = stringToBase64(public_key.slice(44))

  cbTick(
    nacl.sign.detached.verify(string, signature, public_key),
    callback
  )
}

exports.secretbox = function (string, nonce, secret_key, callback) {
  string = stringToUtf8(string)
  nonce = stringToBase64(nonce)
  secret_key = stringToBase64(secret_key)

  cbTick(
    base64ToString(nacl.secretbox(string, nonce, secret_key)),
    callback
  )
}

exports.secretbox.open = function (box, nonce, secret_key, callback) {
  box = stringToBase64(box)
  nonce = stringToBase64(nonce)
  secret_key = stringToBase64(secret_key)

  cbTick(
    utf8ToString(nacl.secretbox.open(box, nonce, secret_key)),
    callback
  )
}

exports.hash = function (string, callback) {
  string = stringToUtf8(string)

  cbTick(
    base64ToString(nacl.hash(string)),
    callback
  )
}
