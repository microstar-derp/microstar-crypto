'use strict';

var test = require('tape')
var async = require('async')
var mCrypto = require('../')

test('keys', function (t) {
  mCrypto.keys(function (err, keys) {
    t.ok(typeof keys.publicKey === 'string', 'publicKey is string')
    t.ok(keys.publicKey.length === 88, 'publicKey length is 88')
    t.ok(typeof keys.secretKey === 'string', 'secretKey is string')
    t.ok(keys.secretKey.length === 44, 'secretKey length is 44')

    mCrypto.keys(keys.secretKey, function (err, new_keys) {
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
    mCrypto.box(message, r.nonce, r.bob.publicKey, r.alice.secretKey, function (err, boxed) {
      mCrypto.box.open(boxed, r.nonce, r.alice.publicKey, r.bob.secretKey, function (err, opened) {
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
    mCrypto.sign(message, keys.secretKey, function (err, signature) {
      mCrypto.sign.verify(message, signature, keys.publicKey, function (err, success) {
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
    mCrypto.secretbox(message, r.nonce, r.keys.secretKey, function (err, boxed) {
      mCrypto.secretbox.open(boxed, r.nonce, r.keys.secretKey, function (err, opened) {
        debugger
        t.equal(boxed.length, 28)
        t.equal(message, opened)
        t.end()
      })
    })
  }
})