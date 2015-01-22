#### If this documentation is at all unclear, please do not hestitate to file an issue. Clarity is the primary goal of this project.

# microstar-crypto

This library wraps [tweetnacl](https://github.com/dchest/tweetnacl-js), doing a few things.

- Performs type conversion on the UTF8 and Base64 encodings used in tweetnacl. All methods take and return strings.
- Wraps synchronous methods into a callback API using process.nextTick. This is to make it easier to switch to different algorithms in the future, or offload processing to workers.
- Simplifies key management. Tweetnacl provides `box` (public key encryption), `secretbox` (symmetric encryption), and `sign` (cryptographic signatures). Each of these takes a different kind of key, but they can all be generated from a `box` secret key. Microstar-crypto does this generation automatically so that you only need to handle and store one private key. Additionally, `box` and `sign` use separate public keys. Microstar-crypto concatenates these into one string, and then extracts the correct public key depending on method.

Using `tweetnacl` by itself:
```javascript
var keys = {
  box: {
    secretKey: Uint8Array, // 32 bytes
    publicKey: Uint8Array // 32 bytes
  },
  sign: {
    secretKey: Uint8Array, // 32 bytes
    publicKey: Uint8Array // 64 bytes
  },
  secretbox: {
    secretKey: Uint8Array // 32 bytes
  }
}
```

Using microstar-crypto;
```javascript
var keys = {
  publicKey: String, // 88 characters
  secretKey: String // 44 characters
}
```

### .keys([secretKey, ]callback)
Generates a keypair. Called with a secretKey it will generate the corresponding public key. Without, it will generate both keys from scratch.
```javascript
mCrypto.keys(function (err, keys) {
//  keys = {
//    publicKey: String, // 88 characters
//    secretKey: String // 44 characters
//  }
})
```

### .box(string, nonce, theirPublicKey, mySecretKey, callback)
Encrypts a string using a public key. Returns a string.
```javascript
mCrypto.box(string, nonce, alicePublicKey, bobSecretKey, function (err, box) {
//  box = String // encrypted
})

mCrypto.box.open(box, nonce, bobPublicKey, aliceSecretKey, function (err, string) {
//  string = String // plaintext
})
```

### .secretbox(string, nonce, secretKey, callback)
Encrypts a string symmetrically with one secret key. Returns a string.
```javascript
mCrypto.secretbox(string, nonce, secretKey, function (err, box) {
//  box = String // encrypted
})

mCrypto.secretbox.open(box, nonce, secretKey, function (err, string) {
//  string = String // plaintext
})
```

### .sign(string, secretKey, callback)
Signs a string, returning a signature as a string. This uses `tweetnacl.sign.detached` under the hood.
```javascript
mCrypto.sign(string, secretKey, function (err, signature) {
//  signature = String
})

mCrypto.sign.verify(string, signature, publicKey, function (err, valid) {
//  valid = Boolean
})
```
