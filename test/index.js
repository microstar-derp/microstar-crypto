'use strict';

var test = require('tape')
var async = require('async')
var mCrypto = require('../')

test('keys', function (t) {
  mCrypto.keys(function (err, keys) {
    t.ok(typeof keys.public_key === 'string', 'public_key is string')
    t.ok(keys.public_key.length === 88, 'public_key length is 88')
    t.ok(typeof keys.secret_key === 'string', 'secret_key is string')
    t.ok(keys.secret_key.length === 44, 'secret_key length is 44')

    mCrypto.keys(keys.secret_key, function (err, new_keys) {
      t.deepEqual(keys, new_keys)
      t.end()
      console.log(new_keys)
    })
  })
})

test('box', function (t) {
  var message = 'hello'

  async.parallel({
    bob: async.apply(mCrypto.keys),
    alice: async.apply(mCrypto.keys),
    nonce: async.apply(mCrypto.makeNonce)
  }, cryption)

  function cryption (err, r) {
    mCrypto.box(message, r.nonce, r.bob.public_key, r.alice.secret_key, function (err, boxed) {
      mCrypto.box.open(boxed, r.nonce, r.alice.public_key, r.bob.secret_key, function (err, opened) {
        t.equal(typeof boxed, 'string')
        t.equal(boxed.length, 28)
        t.equal(message, opened)
        t.end()
      })
    })
  }
})

test('sign', function (t) {
  var message = 'hello'

  mCrypto.keys(function (err, keys) {
    mCrypto.sign(message, keys.secret_key, function (err, signature) {
      mCrypto.sign.verify(message, signature, keys.public_key, function (err, success) {
        t.ok(success)
        t.end()
      })
    })
  })
})

test('secretbox', function (t) {
  var message = 'hello'

  async.parallel({
    keys: async.apply(mCrypto.keys),
    nonce: async.apply(mCrypto.makeNonce)
  }, cryption)

  function cryption (err, r) {
    mCrypto.secretbox(message, r.nonce, r.keys.secret_key, function (err, boxed) {
      mCrypto.secretbox.open(boxed, r.nonce, r.keys.secret_key, function (err, opened) {
        t.equal(boxed.length, 28)
        t.equal(message, opened)
        t.end()
      })
    })
  }
})

test('hash', function (t) {
  var message = 'hello'

  mCrypto.hash(message, function (err, hashed) {
    t.equal('m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==', hashed)
    t.end()
  })
})