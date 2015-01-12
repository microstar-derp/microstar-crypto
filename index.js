'use strict';

var nacl = require('tweetnacl')

exports.base64ToString = nacl.util.encodeBase64
exports.stringToBase64 = nacl.util.decodeBase64
exports.utf8ToString = nacl.util.encodeUTF8
exports.stringToUtf8 = nacl.util.decodeUTF8

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
    secret_key = exports.stringToBase64(a)
    callback = b
    box = nacl.box.keyPair.fromSecretKey(secret_key)
  }

  var sign = nacl.sign.keyPair.fromSeed(box.secretKey)

  var result = {
    public_key: exports.base64ToString(box.publicKey) + exports.base64ToString(sign.publicKey),
    secret_key: exports.base64ToString(box.secretKey)
  }

  cbTick(result, callback)
}

exports.makeNonce = function (callback) {
  cbTick(
    exports.base64ToString(nacl.randomBytes(24)),
    callback
  )
}

exports.box = function (string, nonce, their_public_key, my_secret_key, callback) {
  string = exports.stringToUtf8(string)
  nonce = exports.stringToBase64(nonce)
  their_public_key = exports.stringToBase64(their_public_key.slice(0, 44))
  my_secret_key = exports.stringToBase64(my_secret_key)

  cbTick(
    exports.base64ToString(nacl.box(string, nonce, their_public_key, my_secret_key)),
    callback
  )
}

exports.box.open = function (box, nonce, their_public_key, my_secret_key, callback) {
  box = exports.stringToBase64(box)
  nonce = exports.stringToBase64(nonce)
  their_public_key = exports.stringToBase64(their_public_key.slice(0, 44))
  my_secret_key = exports.stringToBase64(my_secret_key)

  cbTick(
    exports.utf8ToString(nacl.box.open(box, nonce, their_public_key, my_secret_key)),
    callback
  )
}

exports.sign = function (string, secret_key, callback) {
  string = exports.stringToUtf8(string)
  secret_key = nacl.sign.keyPair.fromSeed(
    exports.stringToBase64(secret_key)
  ).secretKey

  cbTick(
    exports.base64ToString(nacl.sign.detached(string, secret_key)),
    callback
  )
}

exports.sign.verify = function (string, signature, public_key, callback) {
  string = exports.stringToUtf8(string)
  signature = exports.stringToBase64(signature)
  public_key = exports.stringToBase64(public_key.slice(44))

  cbTick(
    nacl.sign.detached.verify(string, signature, public_key),
    callback
  )
}

exports.secretbox = function (string, nonce, secret_key, callback) {
  string = exports.stringToUtf8(string)
  nonce = exports.stringToBase64(nonce)
  secret_key = exports.stringToBase64(secret_key)

  cbTick(
    exports.base64ToString(nacl.secretbox(string, nonce, secret_key)),
    callback
  )
}

exports.secretbox.open = function (box, nonce, secret_key, callback) {
  box = exports.stringToBase64(box)
  nonce = exports.stringToBase64(nonce)
  secret_key = exports.stringToBase64(secret_key)

  cbTick(
    exports.utf8ToString(nacl.secretbox.open(box, nonce, secret_key)),
    callback
  )
}

exports.hash = function (string, callback) {
  string = exports.stringToUtf8(string)

  cbTick(
    exports.base64ToString(nacl.hash(string)),
    callback
  )
}
