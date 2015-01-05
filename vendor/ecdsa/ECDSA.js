!function(e){if("object"==typeof exports)module.exports=e();else if("function"==typeof define&&define.amd)define(e);else{var f;"undefined"!=typeof window?f=window:"undefined"!=typeof global?f=global:"undefined"!=typeof self&&(f=self),f.ECDSA=e()}}(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);throw new Error("Cannot find module '"+o+"'")}var f=n[o]={exports:{}};t[o][0].call(f.exports,function(e){var n=t[o][1][e];return s(n?n:e)},f,f.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(_dereq_,module,exports){
(function (Buffer){
var crypto = _dereq_('crypto')
var assert = _dereq_('assert')

var ecurve = _dereq_('ecurve')
var Point = ecurve.Point
var BigInteger = _dereq_('bigi')

var util = _dereq_('./util')

//dropped support for all others
var curve = ecurve.getCurveByName('secp256k1')


/**
  * Calculate pubkey extraction parameter.
  *
  * When extracting a pubkey from a signature, we have to
  * distinguish four different cases. Rather than putting this
  * burden on the verifier, Bitcoin includes a 2-bit value with the
  * signature.
  *
  * This function simply tries all four cases and returns the value
  * that resulted in a successful pubkey recovery.
  */
function calcPubKeyRecoveryParam(e, signature, Q) {
  for (var i = 0; i < 4; i++) {
    var Qprime = recoverPubKey(e, signature, i)

    if (Qprime.equals(Q)) {
      return i
    }
  }

  throw new Error('Unable to find valid recovery factor')
}

function deterministicGenerateK(hash, D) {
  assert(Buffer.isBuffer(hash), 'Hash must be a Buffer, not ' + hash)
  assert.equal(hash.length, 32, 'Hash must be 256 bit')
  assert(BigInteger.isBigInteger(D, true), 'Private key must be a BigInteger')

  var x = D.toBuffer(32)
  var k = new Buffer(32)
  var v = new Buffer(32)
  k.fill(0)
  v.fill(1)

  k = util.hmacSHA256(Buffer.concat([v, new Buffer([0]), x, hash]), k)
  v = util.hmacSHA256(v, k)

  k = util.hmacSHA256(Buffer.concat([v, new Buffer([1]), x, hash]), k)
  v = util.hmacSHA256(v, k)
  v = util.hmacSHA256(v, k)

  var n = curve.n
  var kB = BigInteger.fromBuffer(v).mod(n)
  assert(kB.compareTo(BigInteger.ONE) > 0, 'Invalid k value')
  assert(kB.compareTo(curve.n) < 0, 'Invalid k value')

  return kB
}

function parseSig(buffer) {
  assert.equal(buffer.readUInt8(0), 0x30, 'Not a DER sequence')
  assert.equal(buffer.readUInt8(1), buffer.length - 2, 'Invalid sequence length')

  assert.equal(buffer.readUInt8(2), 0x02, 'Expected a DER integer')
  var rLen = buffer.readUInt8(3)
  var rB = buffer.slice(4, 4 + rLen)

  var offset = 4 + rLen
  assert.equal(buffer.readUInt8(offset), 0x02, 'Expected a DER integer (2)')
  var sLen = buffer.readUInt8(1 + offset)
  var sB = buffer.slice(2 + offset)
  offset += 2 + sLen

  assert.equal(offset, buffer.length, 'Invalid DER encoding')

  return { r: BigInteger.fromDERInteger(rB), s: BigInteger.fromDERInteger(sB) }
}

function parseSigCompact(buffer) {
   assert.equal(buffer.length, 65, 'Invalid signature length')
  var i = buffer.readUInt8(0) - 27

  // At most 3 bits
  assert.equal(i, i & 7, 'Invalid signature parameter')
  var compressed = !!(i & 4)

  // Recovery param only
  i = i & 3

  var r = BigInteger.fromBuffer(buffer.slice(1, 33))
  var s = BigInteger.fromBuffer(buffer.slice(33))

  return {
    signature: {
      r: r,
      s: s
    },
    i: i,
    compressed: compressed
  }
}

/**
  * Recover a public key from a signature.
  *
  * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
  * Key Recovery Operation".
  *
  * http://www.secg.org/download/aid-780/sec1-v2.pdf
  */
function recoverPubKey(e, signature, i) {
  assert.strictEqual(i & 3, i, 'Recovery param is more than two bits')

  var n = curve.n
  var G = curve.G

  var r = signature.r
  var s = signature.s

  assert(r.signum() > 0 && r.compareTo(n) < 0, 'Invalid r value')
  assert(s.signum() > 0 && s.compareTo(n) < 0, 'Invalid s value')

  // A set LSB signifies that the y-coordinate is odd
  var isYOdd = i & 1

  // The more significant bit specifies whether we should use the
  // first or second candidate key.
  var isSecondKey = i >> 1

  // 1.1 Let x = r + jn
  var x = isSecondKey ? r.add(n) : r
  var R = curve.pointFromX(isYOdd, x)

  // 1.4 Check that nR is at infinity
  var nR = R.multiply(n)
  assert(curve.isInfinity(nR), 'nR is not a valid curve point')

  // Compute -e from e
  var eNeg = e.negate().mod(n)

  // 1.6.1 Compute Q = r^-1 (sR -  eG)
  //               Q = r^-1 (sR + -eG)
  var rInv = r.modInverse(n)

  var Q = R.multiplyTwo(s, G, eNeg).multiply(rInv)
  curve.validate(Q)

  return Q
}


function serializeSig(signature) {
  //var rBa = r.toByteArraySigned();
  //var sBa = s.toByteArraySigned();
  var rBa = signature.r.toDERInteger()
  var sBa = signature.s.toDERInteger()


  var sequence = [];
  sequence.push(0x02); // INTEGER
  sequence.push(rBa.length);
  sequence = sequence.concat(rBa);

  sequence.push(0x02); // INTEGER
  sequence.push(sBa.length);
  sequence = sequence.concat(sBa);

  sequence.unshift(sequence.length);
  sequence.unshift(0x30); // SEQUENCE

  return sequence;
}

function serializeSigCompact(signature, i, compressed) {
  if (compressed) {
    i += 4
  }

  i += 27

  var buffer = new Buffer(65)
  buffer.writeUInt8(i, 0)

  signature.r.toBuffer(32).copy(buffer, 1)
  signature.s.toBuffer(32).copy(buffer, 33)

  return buffer
}

function sign(hash, privateKey) {
  if (Buffer.isBuffer(privateKey))
    var D = BigInteger.fromBuffer(privateKey)
  else
    var D = privateKey //big integer for legacy compatiblity

  var k = deterministicGenerateK(hash, D)

  var n = curve.n
  var G = curve.G
  var Q = G.multiply(k)
  var e = BigInteger.fromBuffer(hash)

  var r = Q.affineX.mod(n)
  assert.notEqual(r.signum(), 0, 'Invalid R value')

  var s = k.modInverse(n).multiply(e.add(D.multiply(r))).mod(n)
  assert.notEqual(s.signum(), 0, 'Invalid S value')

  var N_OVER_TWO = n.shiftRight(1)

  // enforce low S values, see bip62: 'low s values in signatures'
  if (s.compareTo(N_OVER_TWO) > 0) {
    s = n.subtract(s)
  }

  return {r: r, s: s}
}

function verify(hash, signature, pubkey) {
  assert(signature.r && signature.s, "Invalid signature.")

  var Q;
   if (Buffer.isBuffer(pubkey)) {
    Q = Point.decodeFrom(curve, pubkey);
  } else {
    throw new Error("Invalid format for pubkey value, must be Buffer");
  }
  var e = BigInteger.fromBuffer(hash);

  return verifyRaw(e, {r: signature.r, s: signature.s}, Q)
}

function verifyRaw(e, signature, Q) {
  var n = curve.n
  var G = curve.G

  var r = signature.r
  var s = signature.s

  // 1.4.1 Enforce r and s are both integers in the interval [1, n − 1]
  if (r.signum() <= 0 || r.compareTo(n) >= 0) return false
  if (s.signum() <= 0 || s.compareTo(n) >= 0) return false

  // c = s^-1 mod n
  var c = s.modInverse(n)

  // 1.4.4 Compute u1 = es^−1 mod n
  //               u2 = rs^−1 mod n
  var u1 = e.multiply(c).mod(n)
  var u2 = r.multiply(c).mod(n)

  // 1.4.5 Compute R = (xR, yR) = u1G + u2Q
  var R = G.multiplyTwo(u1, Q, u2)
  var v = R.affineX.mod(n)

  // 1.4.5 (cont.) Enforce R is not at infinity
  if (curve.isInfinity(R)) return false

  // 1.4.8 If v = r, output "valid", and if v != r, output "invalid"
  return v.equals(r)
}

module.exports = {
  curve: curve,
  deterministicGenerateK: deterministicGenerateK,
  parseSig: parseSig,
  parseSigCompact: parseSigCompact,
  recoverPubKey: recoverPubKey,
  serializeSig: serializeSig,
  serializeSigCompact: serializeSigCompact,
  sign: sign,
  verify: verify,
  verifyRaw: verifyRaw
}



}).call(this,_dereq_("buffer").Buffer)
},{"./util":2,"assert":12,"bigi":5,"buffer":23,"crypto":16,"ecurve":9}],2:[function(_dereq_,module,exports){
var crypto = _dereq_('crypto')

module.exports = {
  hmacSHA256: hmacSHA256
}

function hmacSHA256(v, k) {
  return crypto.createHmac('sha256', k).update(v).digest()
}
},{"crypto":16}],3:[function(_dereq_,module,exports){
// (public) Constructor
function BigInteger(a, b, c) {
  if (!(this instanceof BigInteger))
    return new BigInteger(a, b, c)

  if (a != null) {
    if ("number" == typeof a) this.fromNumber(a, b, c)
    else if (b == null && "string" != typeof a) this.fromString(a, 256)
    else this.fromString(a, b)
  }
}

var proto = BigInteger.prototype

// duck-typed isBigInteger
proto.__bigi = _dereq_('../package.json').version
BigInteger.isBigInteger = function (obj, check_ver) {
  return obj && obj.__bigi && (!check_ver || obj.__bigi === proto.__bigi)
}

// Bits per digit
var dbits

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i, x, w, j, c, n) {
  while (--n >= 0) {
    var v = x * this[i++] + w[j] + c
    c = Math.floor(v / 0x4000000)
    w[j++] = v & 0x3ffffff
  }
  return c
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i, x, w, j, c, n) {
  var xl = x & 0x7fff,
    xh = x >> 15
  while (--n >= 0) {
    var l = this[i] & 0x7fff
    var h = this[i++] >> 15
    var m = xh * l + h * xl
    l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff)
    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30)
    w[j++] = l & 0x3fffffff
  }
  return c
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i, x, w, j, c, n) {
  var xl = x & 0x3fff,
    xh = x >> 14
  while (--n >= 0) {
    var l = this[i] & 0x3fff
    var h = this[i++] >> 14
    var m = xh * l + h * xl
    l = xl * l + ((m & 0x3fff) << 14) + w[j] + c
    c = (l >> 28) + (m >> 14) + xh * h
    w[j++] = l & 0xfffffff
  }
  return c
}

// wtf?
BigInteger.prototype.am = am1
dbits = 26

BigInteger.prototype.DB = dbits
BigInteger.prototype.DM = ((1 << dbits) - 1)
var DV = BigInteger.prototype.DV = (1 << dbits)

var BI_FP = 52
BigInteger.prototype.FV = Math.pow(2, BI_FP)
BigInteger.prototype.F1 = BI_FP - dbits
BigInteger.prototype.F2 = 2 * dbits - BI_FP

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz"
var BI_RC = new Array()
var rr, vv
rr = "0".charCodeAt(0)
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv
rr = "a".charCodeAt(0)
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv
rr = "A".charCodeAt(0)
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv

function int2char(n) {
  return BI_RM.charAt(n)
}

function intAt(s, i) {
  var c = BI_RC[s.charCodeAt(i)]
  return (c == null) ? -1 : c
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for (var i = this.t - 1; i >= 0; --i) r[i] = this[i]
  r.t = this.t
  r.s = this.s
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1
  this.s = (x < 0) ? -1 : 0
  if (x > 0) this[0] = x
  else if (x < -1) this[0] = x + DV
  else this.t = 0
}

// return bigint initialized to value
function nbv(i) {
  var r = new BigInteger()
  r.fromInt(i)
  return r
}

// (protected) set from string and radix
function bnpFromString(s, b) {
  var self = this

  var k
  if (b == 16) k = 4
  else if (b == 8) k = 3
  else if (b == 256) k = 8; // byte array
  else if (b == 2) k = 1
  else if (b == 32) k = 5
  else if (b == 4) k = 2
  else {
    self.fromRadix(s, b)
    return
  }
  self.t = 0
  self.s = 0
  var i = s.length,
    mi = false,
    sh = 0
  while (--i >= 0) {
    var x = (k == 8) ? s[i] & 0xff : intAt(s, i)
    if (x < 0) {
      if (s.charAt(i) == "-") mi = true
      continue
    }
    mi = false
    if (sh == 0)
      self[self.t++] = x
    else if (sh + k > self.DB) {
      self[self.t - 1] |= (x & ((1 << (self.DB - sh)) - 1)) << sh
      self[self.t++] = (x >> (self.DB - sh))
    } else
      self[self.t - 1] |= x << sh
    sh += k
    if (sh >= self.DB) sh -= self.DB
  }
  if (k == 8 && (s[0] & 0x80) != 0) {
    self.s = -1
    if (sh > 0) self[self.t - 1] |= ((1 << (self.DB - sh)) - 1) << sh
  }
  self.clamp()
  if (mi) BigInteger.ZERO.subTo(self, self)
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s & this.DM
  while (this.t > 0 && this[this.t - 1] == c)--this.t
}

// (public) return string representation in given radix
function bnToString(b) {
  var self = this
  if (self.s < 0) return "-" + self.negate()
    .toString(b)
  var k
  if (b == 16) k = 4
  else if (b == 8) k = 3
  else if (b == 2) k = 1
  else if (b == 32) k = 5
  else if (b == 4) k = 2
  else return self.toRadix(b)
  var km = (1 << k) - 1,
    d, m = false,
    r = "",
    i = self.t
  var p = self.DB - (i * self.DB) % k
  if (i-- > 0) {
    if (p < self.DB && (d = self[i] >> p) > 0) {
      m = true
      r = int2char(d)
    }
    while (i >= 0) {
      if (p < k) {
        d = (self[i] & ((1 << p) - 1)) << (k - p)
        d |= self[--i] >> (p += self.DB - k)
      } else {
        d = (self[i] >> (p -= k)) & km
        if (p <= 0) {
          p += self.DB
          --i
        }
      }
      if (d > 0) m = true
      if (m) r += int2char(d)
    }
  }
  return m ? r : "0"
}

// (public) -this
function bnNegate() {
  var r = new BigInteger()
  BigInteger.ZERO.subTo(this, r)
  return r
}

// (public) |this|
function bnAbs() {
  return (this.s < 0) ? this.negate() : this
}

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s - a.s
  if (r != 0) return r
  var i = this.t
  r = i - a.t
  if (r != 0) return (this.s < 0) ? -r : r
  while (--i >= 0)
    if ((r = this[i] - a[i]) != 0) return r
  return 0
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1,
    t
  if ((t = x >>> 16) != 0) {
    x = t
    r += 16
  }
  if ((t = x >> 8) != 0) {
    x = t
    r += 8
  }
  if ((t = x >> 4) != 0) {
    x = t
    r += 4
  }
  if ((t = x >> 2) != 0) {
    x = t
    r += 2
  }
  if ((t = x >> 1) != 0) {
    x = t
    r += 1
  }
  return r
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if (this.t <= 0) return 0
  return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
}

// (public) return the number of bytes in "this"
function bnByteLength() {
  return this.bitLength() >> 3
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n, r) {
  var i
  for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i]
  for (i = n - 1; i >= 0; --i) r[i] = 0
  r.t = this.t + n
  r.s = this.s
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n, r) {
  for (var i = n; i < this.t; ++i) r[i - n] = this[i]
  r.t = Math.max(this.t - n, 0)
  r.s = this.s
}

// (protected) r = this << n
function bnpLShiftTo(n, r) {
  var self = this
  var bs = n % self.DB
  var cbs = self.DB - bs
  var bm = (1 << cbs) - 1
  var ds = Math.floor(n / self.DB),
    c = (self.s << bs) & self.DM,
    i
  for (i = self.t - 1; i >= 0; --i) {
    r[i + ds + 1] = (self[i] >> cbs) | c
    c = (self[i] & bm) << bs
  }
  for (i = ds - 1; i >= 0; --i) r[i] = 0
  r[ds] = c
  r.t = self.t + ds + 1
  r.s = self.s
  r.clamp()
}

// (protected) r = this >> n
function bnpRShiftTo(n, r) {
  var self = this
  r.s = self.s
  var ds = Math.floor(n / self.DB)
  if (ds >= self.t) {
    r.t = 0
    return
  }
  var bs = n % self.DB
  var cbs = self.DB - bs
  var bm = (1 << bs) - 1
  r[0] = self[ds] >> bs
  for (var i = ds + 1; i < self.t; ++i) {
    r[i - ds - 1] |= (self[i] & bm) << cbs
    r[i - ds] = self[i] >> bs
  }
  if (bs > 0) r[self.t - ds - 1] |= (self.s & bm) << cbs
  r.t = self.t - ds
  r.clamp()
}

// (protected) r = this - a
function bnpSubTo(a, r) {
  var self = this
  var i = 0,
    c = 0,
    m = Math.min(a.t, self.t)
  while (i < m) {
    c += self[i] - a[i]
    r[i++] = c & self.DM
    c >>= self.DB
  }
  if (a.t < self.t) {
    c -= a.s
    while (i < self.t) {
      c += self[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += self.s
  } else {
    c += self.s
    while (i < a.t) {
      c -= a[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c -= a.s
  }
  r.s = (c < 0) ? -1 : 0
  if (c < -1) r[i++] = self.DV + c
  else if (c > 0) r[i++] = c
  r.t = i
  r.clamp()
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a, r) {
  var x = this.abs(),
    y = a.abs()
  var i = x.t
  r.t = i + y.t
  while (--i >= 0) r[i] = 0
  for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t)
  r.s = 0
  r.clamp()
  if (this.s != a.s) BigInteger.ZERO.subTo(r, r)
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs()
  var i = r.t = 2 * x.t
  while (--i >= 0) r[i] = 0
  for (i = 0; i < x.t - 1; ++i) {
    var c = x.am(i, x[i], r, 2 * i, 0, 1)
    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
      r[i + x.t] -= x.DV
      r[i + x.t + 1] = 1
    }
  }
  if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1)
  r.s = 0
  r.clamp()
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m, q, r) {
  var self = this
  var pm = m.abs()
  if (pm.t <= 0) return
  var pt = self.abs()
  if (pt.t < pm.t) {
    if (q != null) q.fromInt(0)
    if (r != null) self.copyTo(r)
    return
  }
  if (r == null) r = new BigInteger()
  var y = new BigInteger(),
    ts = self.s,
    ms = m.s
  var nsh = self.DB - nbits(pm[pm.t - 1]); // normalize modulus
  if (nsh > 0) {
    pm.lShiftTo(nsh, y)
    pt.lShiftTo(nsh, r)
  } else {
    pm.copyTo(y)
    pt.copyTo(r)
  }
  var ys = y.t
  var y0 = y[ys - 1]
  if (y0 == 0) return
  var yt = y0 * (1 << self.F1) + ((ys > 1) ? y[ys - 2] >> self.F2 : 0)
  var d1 = self.FV / yt,
    d2 = (1 << self.F1) / yt,
    e = 1 << self.F2
  var i = r.t,
    j = i - ys,
    t = (q == null) ? new BigInteger() : q
  y.dlShiftTo(j, t)
  if (r.compareTo(t) >= 0) {
    r[r.t++] = 1
    r.subTo(t, r)
  }
  BigInteger.ONE.dlShiftTo(ys, t)
  t.subTo(y, y); // "negative" y so we can replace sub with am later
  while (y.t < ys) y[y.t++] = 0
  while (--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i] == y0) ? self.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2)
    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
      y.dlShiftTo(j, t)
      r.subTo(t, r)
      while (r[i] < --qd) r.subTo(t, r)
    }
  }
  if (q != null) {
    r.drShiftTo(ys, q)
    if (ts != ms) BigInteger.ZERO.subTo(q, q)
  }
  r.t = ys
  r.clamp()
  if (nsh > 0) r.rShiftTo(nsh, r); // Denormalize remainder
  if (ts < 0) BigInteger.ZERO.subTo(r, r)
}

// (public) this mod a
function bnMod(a) {
  var r = new BigInteger()
  this.abs()
    .divRemTo(a, null, r)
  if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r)
  return r
}

// Modular reduction using "classic" algorithm
function Classic(m) {
  this.m = m
}

function cConvert(x) {
  if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m)
  else return x
}

function cRevert(x) {
  return x
}

function cReduce(x) {
  x.divRemTo(this.m, null, x)
}

function cMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

function cSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

Classic.prototype.convert = cConvert
Classic.prototype.revert = cRevert
Classic.prototype.reduce = cReduce
Classic.prototype.mulTo = cMulTo
Classic.prototype.sqrTo = cSqrTo

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if (this.t < 1) return 0
  var x = this[0]
  if ((x & 1) == 0) return 0
  var y = x & 3; // y == 1/x mod 2^2
  y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
  y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
  y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y > 0) ? this.DV - y : -y
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m
  this.mp = m.invDigit()
  this.mpl = this.mp & 0x7fff
  this.mph = this.mp >> 15
  this.um = (1 << (m.DB - 15)) - 1
  this.mt2 = 2 * m.t
}

// xR mod m
function montConvert(x) {
  var r = new BigInteger()
  x.abs()
    .dlShiftTo(this.m.t, r)
  r.divRemTo(this.m, null, r)
  if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r)
  return r
}

// x/R mod m
function montRevert(x) {
  var r = new BigInteger()
  x.copyTo(r)
  this.reduce(r)
  return r
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while (x.t <= this.mt2) // pad x so am has enough room later
    x[x.t++] = 0
  for (var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i] & 0x7fff
    var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM
    // use am to combine the multiply-shift-add into one call
    j = i + this.m.t
    x[j] += this.m.am(0, u0, x, i, 0, this.m.t)
    // propagate carry
    while (x[j] >= x.DV) {
      x[j] -= x.DV
      x[++j]++
    }
  }
  x.clamp()
  x.drShiftTo(this.m.t, x)
  if (x.compareTo(this.m) >= 0) x.subTo(this.m, x)
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

// r = "xy/R mod m"; x,y != r
function montMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

Montgomery.prototype.convert = montConvert
Montgomery.prototype.revert = montRevert
Montgomery.prototype.reduce = montReduce
Montgomery.prototype.mulTo = montMulTo
Montgomery.prototype.sqrTo = montSqrTo

// (protected) true iff this is even
function bnpIsEven() {
  return ((this.t > 0) ? (this[0] & 1) : this.s) == 0
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e, z) {
  if (e > 0xffffffff || e < 1) return BigInteger.ONE
  var r = new BigInteger(),
    r2 = new BigInteger(),
    g = z.convert(this),
    i = nbits(e) - 1
  g.copyTo(r)
  while (--i >= 0) {
    z.sqrTo(r, r2)
    if ((e & (1 << i)) > 0) z.mulTo(r2, g, r)
    else {
      var t = r
      r = r2
      r2 = t
    }
  }
  return z.revert(r)
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e, m) {
  var z
  if (e < 256 || m.isEven()) z = new Classic(m)
  else z = new Montgomery(m)
  return this.exp(e, z)
}

// protected
proto.copyTo = bnpCopyTo
proto.fromInt = bnpFromInt
proto.fromString = bnpFromString
proto.clamp = bnpClamp
proto.dlShiftTo = bnpDLShiftTo
proto.drShiftTo = bnpDRShiftTo
proto.lShiftTo = bnpLShiftTo
proto.rShiftTo = bnpRShiftTo
proto.subTo = bnpSubTo
proto.multiplyTo = bnpMultiplyTo
proto.squareTo = bnpSquareTo
proto.divRemTo = bnpDivRemTo
proto.invDigit = bnpInvDigit
proto.isEven = bnpIsEven
proto.exp = bnpExp

// public
proto.toString = bnToString
proto.negate = bnNegate
proto.abs = bnAbs
proto.compareTo = bnCompareTo
proto.bitLength = bnBitLength
proto.byteLength = bnByteLength
proto.mod = bnMod
proto.modPowInt = bnModPowInt

// (public)
function bnClone() {
  var r = new BigInteger()
  this.copyTo(r)
  return r
}

// (public) return value as integer
function bnIntValue() {
  if (this.s < 0) {
    if (this.t == 1) return this[0] - this.DV
    else if (this.t == 0) return -1
  } else if (this.t == 1) return this[0]
  else if (this.t == 0) return 0
  // assumes 16 < DB < 32
  return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]
}

// (public) return value as byte
function bnByteValue() {
  return (this.t == 0) ? this.s : (this[0] << 24) >> 24
}

// (public) return value as short (assumes DB>=16)
function bnShortValue() {
  return (this.t == 0) ? this.s : (this[0] << 16) >> 16
}

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) {
  return Math.floor(Math.LN2 * this.DB / Math.log(r))
}

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if (this.s < 0) return -1
  else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0
  else return 1
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if (b == null) b = 10
  if (this.signum() == 0 || b < 2 || b > 36) return "0"
  var cs = this.chunkSize(b)
  var a = Math.pow(b, cs)
  var d = nbv(a),
    y = new BigInteger(),
    z = new BigInteger(),
    r = ""
  this.divRemTo(d, y, z)
  while (y.signum() > 0) {
    r = (a + z.intValue())
      .toString(b)
      .substr(1) + r
    y.divRemTo(d, y, z)
  }
  return z.intValue()
    .toString(b) + r
}

// (protected) convert from radix string
function bnpFromRadix(s, b) {
  var self = this
  self.fromInt(0)
  if (b == null) b = 10
  var cs = self.chunkSize(b)
  var d = Math.pow(b, cs),
    mi = false,
    j = 0,
    w = 0
  for (var i = 0; i < s.length; ++i) {
    var x = intAt(s, i)
    if (x < 0) {
      if (s.charAt(i) == "-" && self.signum() == 0) mi = true
      continue
    }
    w = b * w + x
    if (++j >= cs) {
      self.dMultiply(d)
      self.dAddOffset(w, 0)
      j = 0
      w = 0
    }
  }
  if (j > 0) {
    self.dMultiply(Math.pow(b, j))
    self.dAddOffset(w, 0)
  }
  if (mi) BigInteger.ZERO.subTo(self, self)
}

// (protected) alternate constructor
function bnpFromNumber(a, b, c) {
  var self = this
  if ("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if (a < 2) self.fromInt(1)
    else {
      self.fromNumber(a, c)
      if (!self.testBit(a - 1)) // force MSB set
        self.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, self)
      if (self.isEven()) self.dAddOffset(1, 0); // force odd
      while (!self.isProbablePrime(b)) {
        self.dAddOffset(2, 0)
        if (self.bitLength() > a) self.subTo(BigInteger.ONE.shiftLeft(a - 1), self)
      }
    }
  } else {
    // new BigInteger(int,RNG)
    var x = new Array(),
      t = a & 7
    x.length = (a >> 3) + 1
    b.nextBytes(x)
    if (t > 0) x[0] &= ((1 << t) - 1)
    else x[0] = 0
    self.fromString(x, 256)
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var self = this
  var i = self.t,
    r = new Array()
  r[0] = self.s
  var p = self.DB - (i * self.DB) % 8,
    d, k = 0
  if (i-- > 0) {
    if (p < self.DB && (d = self[i] >> p) != (self.s & self.DM) >> p)
      r[k++] = d | (self.s << (self.DB - p))
    while (i >= 0) {
      if (p < 8) {
        d = (self[i] & ((1 << p) - 1)) << (8 - p)
        d |= self[--i] >> (p += self.DB - 8)
      } else {
        d = (self[i] >> (p -= 8)) & 0xff
        if (p <= 0) {
          p += self.DB
          --i
        }
      }
      if ((d & 0x80) != 0) d |= -256
      if (k === 0 && (self.s & 0x80) != (d & 0x80))++k
      if (k > 0 || d != self.s) r[k++] = d
    }
  }
  return r
}

function bnEquals(a) {
  return (this.compareTo(a) == 0)
}

function bnMin(a) {
  return (this.compareTo(a) < 0) ? this : a
}

function bnMax(a) {
  return (this.compareTo(a) > 0) ? this : a
}

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a, op, r) {
  var self = this
  var i, f, m = Math.min(a.t, self.t)
  for (i = 0; i < m; ++i) r[i] = op(self[i], a[i])
  if (a.t < self.t) {
    f = a.s & self.DM
    for (i = m; i < self.t; ++i) r[i] = op(self[i], f)
    r.t = self.t
  } else {
    f = self.s & self.DM
    for (i = m; i < a.t; ++i) r[i] = op(f, a[i])
    r.t = a.t
  }
  r.s = op(self.s, a.s)
  r.clamp()
}

// (public) this & a
function op_and(x, y) {
  return x & y
}

function bnAnd(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_and, r)
  return r
}

// (public) this | a
function op_or(x, y) {
  return x | y
}

function bnOr(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_or, r)
  return r
}

// (public) this ^ a
function op_xor(x, y) {
  return x ^ y
}

function bnXor(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_xor, r)
  return r
}

// (public) this & ~a
function op_andnot(x, y) {
  return x & ~y
}

function bnAndNot(a) {
  var r = new BigInteger()
  this.bitwiseTo(a, op_andnot, r)
  return r
}

// (public) ~this
function bnNot() {
  var r = new BigInteger()
  for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i]
  r.t = this.t
  r.s = ~this.s
  return r
}

// (public) this << n
function bnShiftLeft(n) {
  var r = new BigInteger()
  if (n < 0) this.rShiftTo(-n, r)
  else this.lShiftTo(n, r)
  return r
}

// (public) this >> n
function bnShiftRight(n) {
  var r = new BigInteger()
  if (n < 0) this.lShiftTo(-n, r)
  else this.rShiftTo(n, r)
  return r
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if (x == 0) return -1
  var r = 0
  if ((x & 0xffff) == 0) {
    x >>= 16
    r += 16
  }
  if ((x & 0xff) == 0) {
    x >>= 8
    r += 8
  }
  if ((x & 0xf) == 0) {
    x >>= 4
    r += 4
  }
  if ((x & 3) == 0) {
    x >>= 2
    r += 2
  }
  if ((x & 1) == 0)++r
  return r
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for (var i = 0; i < this.t; ++i)
    if (this[i] != 0) return i * this.DB + lbit(this[i])
  if (this.s < 0) return this.t * this.DB
  return -1
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0
  while (x != 0) {
    x &= x - 1
    ++r
  }
  return r
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0,
    x = this.s & this.DM
  for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x)
  return r
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n / this.DB)
  if (j >= this.t) return (this.s != 0)
  return ((this[j] & (1 << (n % this.DB))) != 0)
}

// (protected) this op (1<<n)
function bnpChangeBit(n, op) {
  var r = BigInteger.ONE.shiftLeft(n)
  this.bitwiseTo(r, op, r)
  return r
}

// (public) this | (1<<n)
function bnSetBit(n) {
  return this.changeBit(n, op_or)
}

// (public) this & ~(1<<n)
function bnClearBit(n) {
  return this.changeBit(n, op_andnot)
}

// (public) this ^ (1<<n)
function bnFlipBit(n) {
  return this.changeBit(n, op_xor)
}

// (protected) r = this + a
function bnpAddTo(a, r) {
  var self = this

  var i = 0,
    c = 0,
    m = Math.min(a.t, self.t)
  while (i < m) {
    c += self[i] + a[i]
    r[i++] = c & self.DM
    c >>= self.DB
  }
  if (a.t < self.t) {
    c += a.s
    while (i < self.t) {
      c += self[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += self.s
  } else {
    c += self.s
    while (i < a.t) {
      c += a[i]
      r[i++] = c & self.DM
      c >>= self.DB
    }
    c += a.s
  }
  r.s = (c < 0) ? -1 : 0
  if (c > 0) r[i++] = c
  else if (c < -1) r[i++] = self.DV + c
  r.t = i
  r.clamp()
}

// (public) this + a
function bnAdd(a) {
  var r = new BigInteger()
  this.addTo(a, r)
  return r
}

// (public) this - a
function bnSubtract(a) {
  var r = new BigInteger()
  this.subTo(a, r)
  return r
}

// (public) this * a
function bnMultiply(a) {
  var r = new BigInteger()
  this.multiplyTo(a, r)
  return r
}

// (public) this^2
function bnSquare() {
  var r = new BigInteger()
  this.squareTo(r)
  return r
}

// (public) this / a
function bnDivide(a) {
  var r = new BigInteger()
  this.divRemTo(a, r, null)
  return r
}

// (public) this % a
function bnRemainder(a) {
  var r = new BigInteger()
  this.divRemTo(a, null, r)
  return r
}

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = new BigInteger(),
    r = new BigInteger()
  this.divRemTo(a, q, r)
  return new Array(q, r)
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0, n - 1, this, 0, 0, this.t)
  ++this.t
  this.clamp()
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n, w) {
  if (n == 0) return
  while (this.t <= w) this[this.t++] = 0
  this[w] += n
  while (this[w] >= this.DV) {
    this[w] -= this.DV
    if (++w >= this.t) this[this.t++] = 0
    ++this[w]
  }
}

// A "null" reducer
function NullExp() {}

function nNop(x) {
  return x
}

function nMulTo(x, y, r) {
  x.multiplyTo(y, r)
}

function nSqrTo(x, r) {
  x.squareTo(r)
}

NullExp.prototype.convert = nNop
NullExp.prototype.revert = nNop
NullExp.prototype.mulTo = nMulTo
NullExp.prototype.sqrTo = nSqrTo

// (public) this^e
function bnPow(e) {
  return this.exp(e, new NullExp())
}

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a, n, r) {
  var i = Math.min(this.t + a.t, n)
  r.s = 0; // assumes a,this >= 0
  r.t = i
  while (i > 0) r[--i] = 0
  var j
  for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t)
  for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i)
  r.clamp()
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a, n, r) {
  --n
  var i = r.t = this.t + a.t - n
  r.s = 0; // assumes a,this >= 0
  while (--i >= 0) r[i] = 0
  for (i = Math.max(n - this.t, 0); i < a.t; ++i)
    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n)
  r.clamp()
  r.drShiftTo(1, r)
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = new BigInteger()
  this.q3 = new BigInteger()
  BigInteger.ONE.dlShiftTo(2 * m.t, this.r2)
  this.mu = this.r2.divide(m)
  this.m = m
}

function barrettConvert(x) {
  if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m)
  else if (x.compareTo(this.m) < 0) return x
  else {
    var r = new BigInteger()
    x.copyTo(r)
    this.reduce(r)
    return r
  }
}

function barrettRevert(x) {
  return x
}

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  var self = this
  x.drShiftTo(self.m.t - 1, self.r2)
  if (x.t > self.m.t + 1) {
    x.t = self.m.t + 1
    x.clamp()
  }
  self.mu.multiplyUpperTo(self.r2, self.m.t + 1, self.q3)
  self.m.multiplyLowerTo(self.q3, self.m.t + 1, self.r2)
  while (x.compareTo(self.r2) < 0) x.dAddOffset(1, self.m.t + 1)
  x.subTo(self.r2, x)
  while (x.compareTo(self.m) >= 0) x.subTo(self.m, x)
}

// r = x^2 mod m; x != r
function barrettSqrTo(x, r) {
  x.squareTo(r)
  this.reduce(r)
}

// r = x*y mod m; x,y != r
function barrettMulTo(x, y, r) {
  x.multiplyTo(y, r)
  this.reduce(r)
}

Barrett.prototype.convert = barrettConvert
Barrett.prototype.revert = barrettRevert
Barrett.prototype.reduce = barrettReduce
Barrett.prototype.mulTo = barrettMulTo
Barrett.prototype.sqrTo = barrettSqrTo

// (public) this^e % m (HAC 14.85)
function bnModPow(e, m) {
  var i = e.bitLength(),
    k, r = nbv(1),
    z
  if (i <= 0) return r
  else if (i < 18) k = 1
  else if (i < 48) k = 3
  else if (i < 144) k = 4
  else if (i < 768) k = 5
  else k = 6
  if (i < 8)
    z = new Classic(m)
  else if (m.isEven())
    z = new Barrett(m)
  else
    z = new Montgomery(m)

  // precomputation
  var g = new Array(),
    n = 3,
    k1 = k - 1,
    km = (1 << k) - 1
  g[1] = z.convert(this)
  if (k > 1) {
    var g2 = new BigInteger()
    z.sqrTo(g[1], g2)
    while (n <= km) {
      g[n] = new BigInteger()
      z.mulTo(g2, g[n - 2], g[n])
      n += 2
    }
  }

  var j = e.t - 1,
    w, is1 = true,
    r2 = new BigInteger(),
    t
  i = nbits(e[j]) - 1
  while (j >= 0) {
    if (i >= k1) w = (e[j] >> (i - k1)) & km
    else {
      w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i)
      if (j > 0) w |= e[j - 1] >> (this.DB + i - k1)
    }

    n = k
    while ((w & 1) == 0) {
      w >>= 1
      --n
    }
    if ((i -= n) < 0) {
      i += this.DB
      --j
    }
    if (is1) { // ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r)
      is1 = false
    } else {
      while (n > 1) {
        z.sqrTo(r, r2)
        z.sqrTo(r2, r)
        n -= 2
      }
      if (n > 0) z.sqrTo(r, r2)
      else {
        t = r
        r = r2
        r2 = t
      }
      z.mulTo(r2, g[w], r)
    }

    while (j >= 0 && (e[j] & (1 << i)) == 0) {
      z.sqrTo(r, r2)
      t = r
      r = r2
      r2 = t
      if (--i < 0) {
        i = this.DB - 1
        --j
      }
    }
  }
  return z.revert(r)
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s < 0) ? this.negate() : this.clone()
  var y = (a.s < 0) ? a.negate() : a.clone()
  if (x.compareTo(y) < 0) {
    var t = x
    x = y
    y = t
  }
  var i = x.getLowestSetBit(),
    g = y.getLowestSetBit()
  if (g < 0) return x
  if (i < g) g = i
  if (g > 0) {
    x.rShiftTo(g, x)
    y.rShiftTo(g, y)
  }
  while (x.signum() > 0) {
    if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x)
    if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y)
    if (x.compareTo(y) >= 0) {
      x.subTo(y, x)
      x.rShiftTo(1, x)
    } else {
      y.subTo(x, y)
      y.rShiftTo(1, y)
    }
  }
  if (g > 0) y.lShiftTo(g, y)
  return y
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if (n <= 0) return 0
  var d = this.DV % n,
    r = (this.s < 0) ? n - 1 : 0
  if (this.t > 0)
    if (d == 0) r = this[0] % n
    else
      for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n
  return r
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven()
  if ((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO
  var u = m.clone(),
    v = this.clone()
  var a = nbv(1),
    b = nbv(0),
    c = nbv(0),
    d = nbv(1)
  while (u.signum() != 0) {
    while (u.isEven()) {
      u.rShiftTo(1, u)
      if (ac) {
        if (!a.isEven() || !b.isEven()) {
          a.addTo(this, a)
          b.subTo(m, b)
        }
        a.rShiftTo(1, a)
      } else if (!b.isEven()) b.subTo(m, b)
      b.rShiftTo(1, b)
    }
    while (v.isEven()) {
      v.rShiftTo(1, v)
      if (ac) {
        if (!c.isEven() || !d.isEven()) {
          c.addTo(this, c)
          d.subTo(m, d)
        }
        c.rShiftTo(1, c)
      } else if (!d.isEven()) d.subTo(m, d)
      d.rShiftTo(1, d)
    }
    if (u.compareTo(v) >= 0) {
      u.subTo(v, u)
      if (ac) a.subTo(c, a)
      b.subTo(d, b)
    } else {
      v.subTo(u, v)
      if (ac) c.subTo(a, c)
      d.subTo(b, d)
    }
  }
  if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO
  if (d.compareTo(m) >= 0) return d.subtract(m)
  if (d.signum() < 0) d.addTo(m, d)
  else return d
  if (d.signum() < 0) return d.add(m)
  else return d
}

var lowprimes = [
  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
  73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
  239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
  421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
  613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]

var lplim = (1 << 26) / lowprimes[lowprimes.length - 1]

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs()
  if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
    for (i = 0; i < lowprimes.length; ++i)
      if (x[0] == lowprimes[i]) return true
    return false
  }
  if (x.isEven()) return false
  i = 1
  while (i < lowprimes.length) {
    var m = lowprimes[i],
      j = i + 1
    while (j < lowprimes.length && m < lplim) m *= lowprimes[j++]
    m = x.modInt(m)
    while (i < j) if (m % lowprimes[i++] == 0) return false
  }
  return x.millerRabin(t)
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE)
  var k = n1.getLowestSetBit()
  if (k <= 0) return false
  var r = n1.shiftRight(k)
  t = (t + 1) >> 1
  if (t > lowprimes.length) t = lowprimes.length
  var a = new BigInteger(null)
  var j, bases = []
  for (var i = 0; i < t; ++i) {
    for (;;) {
      j = lowprimes[Math.floor(Math.random() * lowprimes.length)]
      if (bases.indexOf(j) == -1) break
    }
    bases.push(j)
    a.fromInt(j)
    var y = a.modPow(r, this)
    if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2, this)
        if (y.compareTo(BigInteger.ONE) == 0) return false
      }
      if (y.compareTo(n1) != 0) return false
    }
  }
  return true
}

// protected
proto.chunkSize = bnpChunkSize
proto.toRadix = bnpToRadix
proto.fromRadix = bnpFromRadix
proto.fromNumber = bnpFromNumber
proto.bitwiseTo = bnpBitwiseTo
proto.changeBit = bnpChangeBit
proto.addTo = bnpAddTo
proto.dMultiply = bnpDMultiply
proto.dAddOffset = bnpDAddOffset
proto.multiplyLowerTo = bnpMultiplyLowerTo
proto.multiplyUpperTo = bnpMultiplyUpperTo
proto.modInt = bnpModInt
proto.millerRabin = bnpMillerRabin

// public
proto.clone = bnClone
proto.intValue = bnIntValue
proto.byteValue = bnByteValue
proto.shortValue = bnShortValue
proto.signum = bnSigNum
proto.toByteArray = bnToByteArray
proto.equals = bnEquals
proto.min = bnMin
proto.max = bnMax
proto.and = bnAnd
proto.or = bnOr
proto.xor = bnXor
proto.andNot = bnAndNot
proto.not = bnNot
proto.shiftLeft = bnShiftLeft
proto.shiftRight = bnShiftRight
proto.getLowestSetBit = bnGetLowestSetBit
proto.bitCount = bnBitCount
proto.testBit = bnTestBit
proto.setBit = bnSetBit
proto.clearBit = bnClearBit
proto.flipBit = bnFlipBit
proto.add = bnAdd
proto.subtract = bnSubtract
proto.multiply = bnMultiply
proto.divide = bnDivide
proto.remainder = bnRemainder
proto.divideAndRemainder = bnDivideAndRemainder
proto.modPow = bnModPow
proto.modInverse = bnModInverse
proto.pow = bnPow
proto.gcd = bnGCD
proto.isProbablePrime = bnIsProbablePrime

// JSBN-specific extension
proto.square = bnSquare

// constants
BigInteger.ZERO = nbv(0)
BigInteger.ONE = nbv(1)
BigInteger.valueOf = nbv

module.exports = BigInteger

},{"../package.json":6}],4:[function(_dereq_,module,exports){
(function (Buffer){
// FIXME: Kind of a weird way to throw exceptions, consider removing
var assert = _dereq_('assert')
var BigInteger = _dereq_('./bigi')

/**
 * Turns a byte array into a big integer.
 *
 * This function will interpret a byte array as a big integer in big
 * endian notation.
 */
BigInteger.fromByteArrayUnsigned = function(byteArray) {
  // BigInteger expects a DER integer conformant byte array
  if (byteArray[0] & 0x80) {
    return new BigInteger([0].concat(byteArray))
  }

  return new BigInteger(byteArray)
}

/**
 * Returns a byte array representation of the big integer.
 *
 * This returns the absolute of the contained value in big endian
 * form. A value of zero results in an empty array.
 */
BigInteger.prototype.toByteArrayUnsigned = function() {
  var byteArray = this.toByteArray()
  return byteArray[0] === 0 ? byteArray.slice(1) : byteArray
}

BigInteger.fromDERInteger = function(byteArray) {
  return new BigInteger(byteArray)
}

/*
 * Converts BigInteger to a DER integer representation.
 *
 * The format for this value uses the most significant bit as a sign
 * bit.  If the most significant bit is already set and the integer is
 * positive, a 0x00 is prepended.
 *
 * Examples:
 *
 *      0 =>     0x00
 *      1 =>     0x01
 *     -1 =>     0xff
 *    127 =>     0x7f
 *   -127 =>     0x81
 *    128 =>   0x0080
 *   -128 =>     0x80
 *    255 =>   0x00ff
 *   -255 =>   0xff01
 *  16300 =>   0x3fac
 * -16300 =>   0xc054
 *  62300 => 0x00f35c
 * -62300 => 0xff0ca4
*/
BigInteger.prototype.toDERInteger = BigInteger.prototype.toByteArray

BigInteger.fromBuffer = function(buffer) {
  // BigInteger expects a DER integer conformant byte array
  if (buffer[0] & 0x80) {
    var byteArray = Array.prototype.slice.call(buffer)

    return new BigInteger([0].concat(byteArray))
  }

  return new BigInteger(buffer)
}

BigInteger.fromHex = function(hex) {
  if (hex === '') return BigInteger.ZERO

  assert.equal(hex, hex.match(/^[A-Fa-f0-9]+/), 'Invalid hex string')
  assert.equal(hex.length % 2, 0, 'Incomplete hex')
  return new BigInteger(hex, 16)
}

BigInteger.prototype.toBuffer = function(size) {
  var byteArray = this.toByteArrayUnsigned()
  var zeros = []

  var padding = size - byteArray.length
  while (zeros.length < padding) zeros.push(0)

  return new Buffer(zeros.concat(byteArray))
}

BigInteger.prototype.toHex = function(size) {
  return this.toBuffer(size).toString('hex')
}

}).call(this,_dereq_("buffer").Buffer)
},{"./bigi":3,"assert":12,"buffer":23}],5:[function(_dereq_,module,exports){
var BigInteger = _dereq_('./bigi')

//addons
_dereq_('./convert')

module.exports = BigInteger
},{"./bigi":3,"./convert":4}],6:[function(_dereq_,module,exports){
module.exports={
  "name": "bigi",
  "version": "1.4.0",
  "description": "Big integers.",
  "keywords": [
    "cryptography",
    "math",
    "bitcoin",
    "arbitrary",
    "precision",
    "arithmetic",
    "big",
    "integer",
    "int",
    "number",
    "biginteger",
    "bigint",
    "bignumber",
    "decimal",
    "float"
  ],
  "devDependencies": {
    "mocha": "^1.20.1",
    "jshint": "^2.5.1",
    "coveralls": "^2.10.0",
    "istanbul": "^0.2.11"
  },
  "repository": {
    "url": "https://github.com/cryptocoinjs/bigi",
    "type": "git"
  },
  "main": "./lib/index.js",
  "scripts": {
    "test": "_mocha -- test/*.js",
    "jshint": "jshint --config jshint.json lib/*.js ; true",
    "unit": "mocha",
    "coverage": "istanbul cover ./node_modules/.bin/_mocha -- --reporter list test/*.js",
    "coveralls": "npm run-script coverage && node ./node_modules/.bin/coveralls < coverage/lcov.info"
  },
  "dependencies": {},
  "testling": {
    "files": "test/*.js",
    "harness": "mocha",
    "browsers": [
      "ie/9..latest",
      "firefox/latest",
      "chrome/latest",
      "safari/6.0..latest",
      "iphone/6.0..latest",
      "android-browser/4.2..latest"
    ]
  },
  "bugs": {
    "url": "https://github.com/cryptocoinjs/bigi/issues"
  },
  "homepage": "https://github.com/cryptocoinjs/bigi",
  "_id": "bigi@1.4.0",
  "dist": {
    "shasum": "90ac1aeac0a531216463bdb58f42c1e05c8407ac",
    "tarball": "http://registry.npmjs.org/bigi/-/bigi-1.4.0.tgz"
  },
  "_from": "bigi@>=1.2.1 <2.0.0",
  "_npmVersion": "1.4.3",
  "_npmUser": {
    "name": "jp",
    "email": "jprichardson@gmail.com"
  },
  "maintainers": [
    {
      "name": "jp",
      "email": "jprichardson@gmail.com"
    },
    {
      "name": "midnightlightning",
      "email": "boydb@midnightdesign.ws"
    },
    {
      "name": "sidazhang",
      "email": "sidazhang89@gmail.com"
    },
    {
      "name": "nadav",
      "email": "npm@shesek.info"
    }
  ],
  "directories": {},
  "_shasum": "90ac1aeac0a531216463bdb58f42c1e05c8407ac",
  "_resolved": "https://registry.npmjs.org/bigi/-/bigi-1.4.0.tgz"
}

},{}],7:[function(_dereq_,module,exports){
var assert = _dereq_('assert')
var BigInteger = _dereq_('bigi')

var Point = _dereq_('./point')

function Curve(p, a, b, Gx, Gy, n, h) {
  this.p = p
  this.a = a
  this.b = b
  this.G = Point.fromAffine(this, Gx, Gy)
  this.n = n
  this.h = h

  this.infinity = new Point(this, null, null, BigInteger.ZERO)

  // result caching
  this.pOverFour = p.add(BigInteger.ONE).shiftRight(2)
}

Curve.prototype.pointFromX = function(isOdd, x) {
  var alpha = x.pow(3).add(this.a.multiply(x)).add(this.b).mod(this.p)
  var beta = alpha.modPow(this.pOverFour, this.p)

  var y = beta
  if (beta.isEven() ^ !isOdd) {
    y = this.p.subtract(y) // -y % p
  }

  return Point.fromAffine(this, x, y)
}

Curve.prototype.isInfinity = function(Q) {
  if (Q === this.infinity) return true

  return Q.z.signum() === 0 && Q.y.signum() !== 0
}

Curve.prototype.isOnCurve = function(Q) {
  if (this.isInfinity(Q)) return true

  var x = Q.affineX
  var y = Q.affineY
  var a = this.a
  var b = this.b
  var p = this.p

  // Check that xQ and yQ are integers in the interval [0, p - 1]
  if (x.signum() < 0 || x.compareTo(p) >= 0) return false
  if (y.signum() < 0 || y.compareTo(p) >= 0) return false

  // and check that y^2 = x^3 + ax + b (mod p)
  var lhs = y.square().mod(p)
  var rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p)
  return lhs.equals(rhs)
}

/**
 * Validate an elliptic curve point.
 *
 * See SEC 1, section 3.2.2.1: Elliptic Curve Public Key Validation Primitive
 */
Curve.prototype.validate = function(Q) {
  // Check Q != O
  assert(!this.isInfinity(Q), 'Point is at infinity')
  assert(this.isOnCurve(Q), 'Point is not on the curve')

  // Check nQ = O (where Q is a scalar multiple of G)
  var nQ = Q.multiply(this.n)
  assert(this.isInfinity(nQ), 'Point is not a scalar multiple of G')

  return true
}

module.exports = Curve

},{"./point":11,"assert":12,"bigi":5}],8:[function(_dereq_,module,exports){
module.exports={
  "secp128r1": {
    "p": "fffffffdffffffffffffffffffffffff",
    "a": "fffffffdfffffffffffffffffffffffc",
    "b": "e87579c11079f43dd824993c2cee5ed3",
    "n": "fffffffe0000000075a30d1b9038a115",
    "h": "01",
    "Gx": "161ff7528b899b2d0c28607ca52c5b86",
    "Gy": "cf5ac8395bafeb13c02da292dded7a83"
  },
  "secp160k1": {
    "p": "fffffffffffffffffffffffffffffffeffffac73",
    "a": "00",
    "b": "07",
    "n": "0100000000000000000001b8fa16dfab9aca16b6b3",
    "h": "01",
    "Gx": "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
    "Gy": "938cf935318fdced6bc28286531733c3f03c4fee"
  },
  "secp160r1": {
    "p": "ffffffffffffffffffffffffffffffff7fffffff",
    "a": "ffffffffffffffffffffffffffffffff7ffffffc",
    "b": "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
    "n": "0100000000000000000001f4c8f927aed3ca752257",
    "h": "01",
    "Gx": "4a96b5688ef573284664698968c38bb913cbfc82",
    "Gy": "23a628553168947d59dcc912042351377ac5fb32"
  },
  "secp192k1": {
    "p": "fffffffffffffffffffffffffffffffffffffffeffffee37",
    "a": "00",
    "b": "03",
    "n": "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
    "h": "01",
    "Gx": "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
    "Gy": "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"
  },
  "secp192r1": {
    "p": "fffffffffffffffffffffffffffffffeffffffffffffffff",
    "a": "fffffffffffffffffffffffffffffffefffffffffffffffc",
    "b": "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "n": "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
    "h": "01",
    "Gx": "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "Gy": "07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
  },
  "secp256k1": {
    "p": "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    "a": "00",
    "b": "07",
    "n": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    "h": "01",
    "Gx": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "Gy": "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
  },
  "secp256r1": {
    "p": "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "a": "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    "b": "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "n": "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "h": "01",
    "Gx": "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "Gy": "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  }
}

},{}],9:[function(_dereq_,module,exports){
var Point = _dereq_('./point')
var Curve = _dereq_('./curve')

var getCurveByName = _dereq_('./names')

module.exports = {
  Curve: Curve,
  Point: Point,
  getCurveByName: getCurveByName
}

},{"./curve":7,"./names":10,"./point":11}],10:[function(_dereq_,module,exports){
var BigInteger = _dereq_('bigi')

var curves = _dereq_('./curves')
var Curve = _dereq_('./curve')

function getCurveByName(name) {
  var curve = curves[name]
  if (!curve) return null

  var p = new BigInteger(curve.p, 16)
  var a = new BigInteger(curve.a, 16)
  var b = new BigInteger(curve.b, 16)
  var n = new BigInteger(curve.n, 16)
  var h = new BigInteger(curve.h, 16)
  var Gx = new BigInteger(curve.Gx, 16)
  var Gy = new BigInteger(curve.Gy, 16)

  return new Curve(p, a, b, Gx, Gy, n, h)
}

module.exports = getCurveByName

},{"./curve":7,"./curves":8,"bigi":5}],11:[function(_dereq_,module,exports){
(function (Buffer){
var assert = _dereq_('assert')
var BigInteger = _dereq_('bigi')

var THREE = BigInteger.valueOf(3)

function Point(curve, x, y, z) {
  assert.notStrictEqual(z, undefined, 'Missing Z coordinate')

  this.curve = curve
  this.x = x
  this.y = y
  this.z = z
  this._zInv = null

  this.compressed = true
}

Object.defineProperty(Point.prototype, 'zInv', {
  get: function() {
    if (this._zInv === null) {
      this._zInv = this.z.modInverse(this.curve.p)
    }

    return this._zInv
  }
})

Object.defineProperty(Point.prototype, 'affineX', {
  get: function() {
    return this.x.multiply(this.zInv).mod(this.curve.p)
  }
})

Object.defineProperty(Point.prototype, 'affineY', {
  get: function() {
    return this.y.multiply(this.zInv).mod(this.curve.p)
  }
})

Point.fromAffine = function(curve, x, y) {
  return new Point(curve, x, y, BigInteger.ONE)
}

Point.prototype.equals = function(other) {
  if (other === this) return true
  if (this.curve.isInfinity(this)) return this.curve.isInfinity(other)
  if (this.curve.isInfinity(other)) return this.curve.isInfinity(this)

  // u = Y2 * Z1 - Y1 * Z2
  var u = other.y.multiply(this.z).subtract(this.y.multiply(other.z)).mod(this.curve.p)

  if (u.signum() !== 0) return false

  // v = X2 * Z1 - X1 * Z2
  var v = other.x.multiply(this.z).subtract(this.x.multiply(other.z)).mod(this.curve.p)

  return v.signum() === 0
}

Point.prototype.negate = function() {
  var y = this.curve.p.subtract(this.y)

  return new Point(this.curve, this.x, y, this.z)
}

Point.prototype.add = function(b) {
  if (this.curve.isInfinity(this)) return b
  if (this.curve.isInfinity(b)) return this

  var x1 = this.x
  var y1 = this.y
  var x2 = b.x
  var y2 = b.y

  // u = Y2 * Z1 - Y1 * Z2
  var u = y2.multiply(this.z).subtract(y1.multiply(b.z)).mod(this.curve.p)
  // v = X2 * Z1 - X1 * Z2
  var v = x2.multiply(this.z).subtract(x1.multiply(b.z)).mod(this.curve.p)

  if (v.signum() === 0) {
    if (u.signum() === 0) {
      return this.twice() // this == b, so double
    }

    return this.curve.infinity // this = -b, so infinity
  }

  var v2 = v.square()
  var v3 = v2.multiply(v)
  var x1v2 = x1.multiply(v2)
  var zu2 = u.square().multiply(this.z)

  // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
  var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.p)
  // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
  var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.p)
  // z3 = v^3 * z1 * z2
  var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.p)

  return new Point(this.curve, x3, y3, z3)
}

Point.prototype.twice = function() {
  if (this.curve.isInfinity(this)) return this
  if (this.y.signum() === 0) return this.curve.infinity

  var x1 = this.x
  var y1 = this.y

  var y1z1 = y1.multiply(this.z)
  var y1sqz1 = y1z1.multiply(y1).mod(this.curve.p)
  var a = this.curve.a

  // w = 3 * x1^2 + a * z1^2
  var w = x1.square().multiply(THREE)

  if (a.signum() !== 0) {
    w = w.add(this.z.square().multiply(a))
  }

  w = w.mod(this.curve.p)
  // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
  var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.p)
  // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
  var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.pow(3)).mod(this.curve.p)
  // z3 = 8 * (y1 * z1)^3
  var z3 = y1z1.pow(3).shiftLeft(3).mod(this.curve.p)

  return new Point(this.curve, x3, y3, z3)
}

// Simple NAF (Non-Adjacent Form) multiplication algorithm
// TODO: modularize the multiplication algorithm
Point.prototype.multiply = function(k) {
  if (this.curve.isInfinity(this)) return this
  if (k.signum() === 0) return this.curve.infinity

  var e = k
  var h = e.multiply(THREE)

  var neg = this.negate()
  var R = this

  for (var i = h.bitLength() - 2; i > 0; --i) {
    R = R.twice()

    var hBit = h.testBit(i)
    var eBit = e.testBit(i)

    if (hBit != eBit) {
      R = R.add(hBit ? this : neg)
    }
  }

  return R
}

// Compute this*j + x*k (simultaneous multiplication)
Point.prototype.multiplyTwo = function(j, x, k) {
  var i

  if (j.bitLength() > k.bitLength())
    i = j.bitLength() - 1
  else
    i = k.bitLength() - 1

  var R = this.curve.infinity
  var both = this.add(x)

  while (i >= 0) {
    R = R.twice()

    var jBit = j.testBit(i)
    var kBit = k.testBit(i)

    if (jBit) {
      if (kBit) {
        R = R.add(both)

      } else {
        R = R.add(this)
      }

    } else {
      if (kBit) {
        R = R.add(x)
      }
    }
    --i
  }

  return R
}

Point.prototype.getEncoded = function(compressed) {
  if (compressed == undefined) compressed = this.compressed
  if (this.curve.isInfinity(this)) return new Buffer('00', 'hex') // Infinity point encoded is simply '00'

  var x = this.affineX
  var y = this.affineY

  var buffer

  // Determine size of q in bytes
  var byteLength = Math.floor((this.curve.p.bitLength() + 7) / 8)

  // 0x02/0x03 | X
  if (compressed) {
    buffer = new Buffer(1 + byteLength)
    buffer.writeUInt8(y.isEven() ? 0x02 : 0x03, 0)

  // 0x04 | X | Y
  } else {
    buffer = new Buffer(1 + byteLength + byteLength)
    buffer.writeUInt8(0x04, 0)

    y.toBuffer(byteLength).copy(buffer, 1 + byteLength)
  }

  x.toBuffer(byteLength).copy(buffer, 1)

  return buffer
}

Point.decodeFrom = function(curve, buffer) {
  var type = buffer.readUInt8(0)
  var compressed = (type !== 4)

  var x = BigInteger.fromBuffer(buffer.slice(1, 33))
  var byteLength = Math.floor((curve.p.bitLength() + 7) / 8)

  var Q
  if (compressed) {
    assert.equal(buffer.length, byteLength + 1, 'Invalid sequence length')
    assert(type === 0x02 || type === 0x03, 'Invalid sequence tag')

    var isOdd = (type === 0x03)
    Q = curve.pointFromX(isOdd, x)

  } else {
    assert.equal(buffer.length, 1 + byteLength + byteLength, 'Invalid sequence length')

    var y = BigInteger.fromBuffer(buffer.slice(1 + byteLength))
    Q = Point.fromAffine(curve, x, y)
  }

  Q.compressed = compressed
  return Q
}

Point.prototype.toString = function () {
  if (this.curve.isInfinity(this)) return '(INFINITY)'

  return '(' + this.affineX.toString() + ',' + this.affineY.toString() + ')'
}

module.exports = Point

}).call(this,_dereq_("buffer").Buffer)
},{"assert":12,"bigi":5,"buffer":23}],12:[function(_dereq_,module,exports){
// http://wiki.commonjs.org/wiki/Unit_Testing/1.0
//
// THIS IS NOT TESTED NOR LIKELY TO WORK OUTSIDE V8!
//
// Originally from narwhal.js (http://narwhaljs.org)
// Copyright (c) 2009 Thomas Robinson <280north.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// when used in node, this will actually load the util module we depend on
// versus loading the builtin util module as happens otherwise
// this is a bug in node module loading as far as I am concerned
var util = _dereq_('util/');

var pSlice = Array.prototype.slice;
var hasOwn = Object.prototype.hasOwnProperty;

// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  if (options.message) {
    this.message = options.message;
    this.generatedMessage = false;
  } else {
    this.message = getMessage(this);
    this.generatedMessage = true;
  }
  var stackStartFunction = options.stackStartFunction || fail;

  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, stackStartFunction);
  }
  else {
    // non v8 browsers so we can have a stacktrace
    var err = new Error();
    if (err.stack) {
      var out = err.stack;

      // try to strip useless frames
      var fn_name = stackStartFunction.name;
      var idx = out.indexOf('\n' + fn_name);
      if (idx >= 0) {
        // once we have located the function frame
        // we need to strip out everything before it (and its line)
        var next_line = out.indexOf('\n', idx + 1);
        out = out.substring(next_line + 1);
      }

      this.stack = out;
    }
  }
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function replacer(key, value) {
  if (util.isUndefined(value)) {
    return '' + value;
  }
  if (util.isNumber(value) && (isNaN(value) || !isFinite(value))) {
    return value.toString();
  }
  if (util.isFunction(value) || util.isRegExp(value)) {
    return value.toString();
  }
  return value;
}

function truncate(s, n) {
  if (util.isString(s)) {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}

function getMessage(self) {
  return truncate(JSON.stringify(self.actual, replacer), 128) + ' ' +
         self.operator + ' ' +
         truncate(JSON.stringify(self.expected, replacer), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

function _deepEqual(actual, expected) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;

  } else if (util.isBuffer(actual) && util.isBuffer(expected)) {
    if (actual.length != expected.length) return false;

    for (var i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) return false;
    }

    return true;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if (!util.isObject(actual) && !util.isObject(expected)) {
    return actual == expected;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else {
    return objEquiv(actual, expected);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b) {
  if (util.isNullOrUndefined(a) || util.isNullOrUndefined(b))
    return false;
  // an identical 'prototype' property.
  if (a.prototype !== b.prototype) return false;
  //~~~I've managed to break Object.keys through screwy arguments passing.
  //   Converting to array solves the problem.
  if (isArguments(a)) {
    if (!isArguments(b)) {
      return false;
    }
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b);
  }
  try {
    var ka = objectKeys(a),
        kb = objectKeys(b),
        key, i;
  } catch (e) {//happens when one is a string literal and the other isn't
    return false;
  }
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length != kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] != kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key])) return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  } else if (actual instanceof expected) {
    return true;
  } else if (expected.call({}, actual) === true) {
    return true;
  }

  return false;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (util.isString(expected)) {
    message = expected;
    expected = null;
  }

  try {
    block();
  } catch (e) {
    actual = e;
  }

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  if (!shouldThrow && expectedException(actual, expected)) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws.apply(this, [true].concat(pSlice.call(arguments)));
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/message) {
  _throws.apply(this, [false].concat(pSlice.call(arguments)));
};

assert.ifError = function(err) { if (err) {throw err;}};

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    if (hasOwn.call(obj, key)) keys.push(key);
  }
  return keys;
};

},{"util/":14}],13:[function(_dereq_,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],14:[function(_dereq_,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = _dereq_('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = _dereq_('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this,_dereq_("/usr/local/share/npm/lib/node_modules/browserify/node_modules/insert-module-globals/node_modules/process/browser.js"),typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./support/isBuffer":13,"/usr/local/share/npm/lib/node_modules/browserify/node_modules/insert-module-globals/node_modules/process/browser.js":22,"inherits":21}],15:[function(_dereq_,module,exports){
var Buffer = _dereq_('buffer').Buffer;
var intSize = 4;
var zeroBuffer = new Buffer(intSize); zeroBuffer.fill(0);
var chrsz = 8;

function toArray(buf, bigEndian) {
  if ((buf.length % intSize) !== 0) {
    var len = buf.length + (intSize - (buf.length % intSize));
    buf = Buffer.concat([buf, zeroBuffer], len);
  }

  var arr = [];
  var fn = bigEndian ? buf.readInt32BE : buf.readInt32LE;
  for (var i = 0; i < buf.length; i += intSize) {
    arr.push(fn.call(buf, i));
  }
  return arr;
}

function toBuffer(arr, size, bigEndian) {
  var buf = new Buffer(size);
  var fn = bigEndian ? buf.writeInt32BE : buf.writeInt32LE;
  for (var i = 0; i < arr.length; i++) {
    fn.call(buf, arr[i], i * 4, true);
  }
  return buf;
}

function hash(buf, fn, hashSize, bigEndian) {
  if (!Buffer.isBuffer(buf)) buf = new Buffer(buf);
  var arr = fn(toArray(buf, bigEndian), buf.length * chrsz);
  return toBuffer(arr, hashSize, bigEndian);
}

module.exports = { hash: hash };

},{"buffer":23}],16:[function(_dereq_,module,exports){
var Buffer = _dereq_('buffer').Buffer
var sha = _dereq_('./sha')
var sha256 = _dereq_('./sha256')
var rng = _dereq_('./rng')
var md5 = _dereq_('./md5')

var algorithms = {
  sha1: sha,
  sha256: sha256,
  md5: md5
}

var blocksize = 64
var zeroBuffer = new Buffer(blocksize); zeroBuffer.fill(0)
function hmac(fn, key, data) {
  if(!Buffer.isBuffer(key)) key = new Buffer(key)
  if(!Buffer.isBuffer(data)) data = new Buffer(data)

  if(key.length > blocksize) {
    key = fn(key)
  } else if(key.length < blocksize) {
    key = Buffer.concat([key, zeroBuffer], blocksize)
  }

  var ipad = new Buffer(blocksize), opad = new Buffer(blocksize)
  for(var i = 0; i < blocksize; i++) {
    ipad[i] = key[i] ^ 0x36
    opad[i] = key[i] ^ 0x5C
  }

  var hash = fn(Buffer.concat([ipad, data]))
  return fn(Buffer.concat([opad, hash]))
}

function hash(alg, key) {
  alg = alg || 'sha1'
  var fn = algorithms[alg]
  var bufs = []
  var length = 0
  if(!fn) error('algorithm:', alg, 'is not yet supported')
  return {
    update: function (data) {
      if(!Buffer.isBuffer(data)) data = new Buffer(data)
        
      bufs.push(data)
      length += data.length
      return this
    },
    digest: function (enc) {
      var buf = Buffer.concat(bufs)
      var r = key ? hmac(fn, key, buf) : fn(buf)
      bufs = null
      return enc ? r.toString(enc) : r
    }
  }
}

function error () {
  var m = [].slice.call(arguments).join(' ')
  throw new Error([
    m,
    'we accept pull requests',
    'http://github.com/dominictarr/crypto-browserify'
    ].join('\n'))
}

exports.createHash = function (alg) { return hash(alg) }
exports.createHmac = function (alg, key) { return hash(alg, key) }
exports.randomBytes = function(size, callback) {
  if (callback && callback.call) {
    try {
      callback.call(this, undefined, new Buffer(rng(size)))
    } catch (err) { callback(err) }
  } else {
    return new Buffer(rng(size))
  }
}

function each(a, f) {
  for(var i in a)
    f(a[i], i)
}

// the least I can do is make error messages for the rest of the node.js/crypto api.
each(['createCredentials'
, 'createCipher'
, 'createCipheriv'
, 'createDecipher'
, 'createDecipheriv'
, 'createSign'
, 'createVerify'
, 'createDiffieHellman'
, 'pbkdf2'], function (name) {
  exports[name] = function () {
    error('sorry,', name, 'is not implemented yet')
  }
})

},{"./md5":17,"./rng":18,"./sha":19,"./sha256":20,"buffer":23}],17:[function(_dereq_,module,exports){
/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

var helpers = _dereq_('./helpers');

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

module.exports = function md5(buf) {
  return helpers.hash(buf, core_md5, 16);
};

},{"./helpers":15}],18:[function(_dereq_,module,exports){
// Original code adapted from Robert Kieffer.
// details at https://github.com/broofa/node-uuid
(function() {
  var _global = this;

  var mathRNG, whatwgRNG;

  // NOTE: Math.random() does not guarantee "cryptographic quality"
  mathRNG = function(size) {
    var bytes = new Array(size);
    var r;

    for (var i = 0, r; i < size; i++) {
      if ((i & 0x03) == 0) r = Math.random() * 0x100000000;
      bytes[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return bytes;
  }

  if (_global.crypto && crypto.getRandomValues) {
    whatwgRNG = function(size) {
      var bytes = new Uint8Array(size);
      crypto.getRandomValues(bytes);
      return bytes;
    }
  }

  module.exports = whatwgRNG || mathRNG;

}())

},{}],19:[function(_dereq_,module,exports){
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

var helpers = _dereq_('./helpers');

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

module.exports = function sha1(buf) {
  return helpers.hash(buf, core_sha1, 20, true);
};

},{"./helpers":15}],20:[function(_dereq_,module,exports){

/**
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined
 * in FIPS 180-2
 * Version 2.2-beta Copyright Angel Marin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 *
 */

var helpers = _dereq_('./helpers');

var safe_add = function(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
};

var S = function(X, n) {
  return (X >>> n) | (X << (32 - n));
};

var R = function(X, n) {
  return (X >>> n);
};

var Ch = function(x, y, z) {
  return ((x & y) ^ ((~x) & z));
};

var Maj = function(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z));
};

var Sigma0256 = function(x) {
  return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
};

var Sigma1256 = function(x) {
  return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
};

var Gamma0256 = function(x) {
  return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
};

var Gamma1256 = function(x) {
  return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
};

var core_sha256 = function(m, l) {
  var K = new Array(0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0xFC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x6CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2);
  var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
    var W = new Array(64);
    var a, b, c, d, e, f, g, h, i, j;
    var T1, T2;
  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;
  for (var i = 0; i < m.length; i += 16) {
    a = HASH[0]; b = HASH[1]; c = HASH[2]; d = HASH[3]; e = HASH[4]; f = HASH[5]; g = HASH[6]; h = HASH[7];
    for (var j = 0; j < 64; j++) {
      if (j < 16) {
        W[j] = m[j + i];
      } else {
        W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
      }
      T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
      T2 = safe_add(Sigma0256(a), Maj(a, b, c));
      h = g; g = f; f = e; e = safe_add(d, T1); d = c; c = b; b = a; a = safe_add(T1, T2);
    }
    HASH[0] = safe_add(a, HASH[0]); HASH[1] = safe_add(b, HASH[1]); HASH[2] = safe_add(c, HASH[2]); HASH[3] = safe_add(d, HASH[3]);
    HASH[4] = safe_add(e, HASH[4]); HASH[5] = safe_add(f, HASH[5]); HASH[6] = safe_add(g, HASH[6]); HASH[7] = safe_add(h, HASH[7]);
  }
  return HASH;
};

module.exports = function sha256(buf) {
  return helpers.hash(buf, core_sha256, 32, true);
};

},{"./helpers":15}],21:[function(_dereq_,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],22:[function(_dereq_,module,exports){
// shim for using process in browser

var process = module.exports = {};

process.nextTick = (function () {
    var canSetImmediate = typeof window !== 'undefined'
    && window.setImmediate;
    var canPost = typeof window !== 'undefined'
    && window.postMessage && window.addEventListener
    ;

    if (canSetImmediate) {
        return function (f) { return window.setImmediate(f) };
    }

    if (canPost) {
        var queue = [];
        window.addEventListener('message', function (ev) {
            var source = ev.source;
            if ((source === window || source === null) && ev.data === 'process-tick') {
                ev.stopPropagation();
                if (queue.length > 0) {
                    var fn = queue.shift();
                    fn();
                }
            }
        }, true);

        return function nextTick(fn) {
            queue.push(fn);
            window.postMessage('process-tick', '*');
        };
    }

    return function nextTick(fn) {
        setTimeout(fn, 0);
    };
})();

process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];

process.binding = function (name) {
    throw new Error('process.binding is not supported');
}

// TODO(shtylman)
process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};

},{}],23:[function(_dereq_,module,exports){
var base64 = _dereq_('base64-js')
var ieee754 = _dereq_('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = Buffer
exports.INSPECT_MAX_BYTES = 50
Buffer.poolSize = 8192

/**
 * If `Buffer._useTypedArrays`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (compatible down to IE6)
 */
Buffer._useTypedArrays = (function () {
   // Detect if browser supports Typed Arrays. Supported browsers are IE 10+,
   // Firefox 4+, Chrome 7+, Safari 5.1+, Opera 11.6+, iOS 4.2+.
   if (typeof Uint8Array === 'undefined' || typeof ArrayBuffer === 'undefined')
      return false

  // Does the browser support adding properties to `Uint8Array` instances? If
  // not, then that's the same as no `Uint8Array` support. We need to be able to
  // add all the node Buffer API methods.
  // Relevant Firefox bug: https://bugzilla.mozilla.org/show_bug.cgi?id=695438
  try {
    var arr = new Uint8Array(0)
    arr.foo = function () { return 42 }
    return 42 === arr.foo() &&
        typeof arr.subarray === 'function' // Chrome 9-10 lack `subarray`
  } catch (e) {
    return false
  }
})()

/**
 * Class: Buffer
 * =============
 *
 * The Buffer constructor returns instances of `Uint8Array` that are augmented
 * with function properties for all the node `Buffer` API functions. We use
 * `Uint8Array` so that square bracket notation works as expected -- it returns
 * a single octet.
 *
 * By augmenting the instances, we can avoid modifying the `Uint8Array`
 * prototype.
 */
function Buffer (subject, encoding, noZero) {
  if (!(this instanceof Buffer))
    return new Buffer(subject, encoding, noZero)

  var type = typeof subject

  // Workaround: node's base64 implementation allows for non-padded strings
  // while base64-js does not.
  if (encoding === 'base64' && type === 'string') {
    subject = stringtrim(subject)
    while (subject.length % 4 !== 0) {
      subject = subject + '='
    }
  }

  // Find the length
  var length
  if (type === 'number')
    length = coerce(subject)
  else if (type === 'string')
    length = Buffer.byteLength(subject, encoding)
  else if (type === 'object')
    length = coerce(subject.length) // Assume object is an array
  else
    throw new Error('First argument needs to be a number, array or string.')

  var buf
  if (Buffer._useTypedArrays) {
    // Preferred: Return an augmented `Uint8Array` instance for best performance
    buf = augment(new Uint8Array(length))
  } else {
    // Fallback: Return THIS instance of Buffer (created by `new`)
    buf = this
    buf.length = length
    buf._isBuffer = true
  }

  var i
  if (Buffer._useTypedArrays && typeof Uint8Array === 'function' &&
      subject instanceof Uint8Array) {
    // Speed optimization -- use set if we're copying from a Uint8Array
    buf._set(subject)
  } else if (isArrayish(subject)) {
    // Treat array-ish objects as a byte array
    for (i = 0; i < length; i++) {
      if (Buffer.isBuffer(subject))
        buf[i] = subject.readUInt8(i)
      else
        buf[i] = subject[i]
    }
  } else if (type === 'string') {
    buf.write(subject, 0, encoding)
  } else if (type === 'number' && !Buffer._useTypedArrays && !noZero) {
    for (i = 0; i < length; i++) {
      buf[i] = 0
    }
  }

  return buf
}

// STATIC METHODS
// ==============

Buffer.isEncoding = function (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'raw':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.isBuffer = function (b) {
  return !!(b !== null && b !== undefined && b._isBuffer)
}

Buffer.byteLength = function (str, encoding) {
  var ret
  str = str + ''
  switch (encoding || 'utf8') {
    case 'hex':
      ret = str.length / 2
      break
    case 'utf8':
    case 'utf-8':
      ret = utf8ToBytes(str).length
      break
    case 'ascii':
    case 'binary':
    case 'raw':
      ret = str.length
      break
    case 'base64':
      ret = base64ToBytes(str).length
      break
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      ret = str.length * 2
      break
    default:
      throw new Error('Unknown encoding')
  }
  return ret
}

Buffer.concat = function (list, totalLength) {
  assert(isArray(list), 'Usage: Buffer.concat(list, [totalLength])\n' +
      'list should be an Array.')

  if (list.length === 0) {
    return new Buffer(0)
  } else if (list.length === 1) {
    return list[0]
  }

  var i
  if (typeof totalLength !== 'number') {
    totalLength = 0
    for (i = 0; i < list.length; i++) {
      totalLength += list[i].length
    }
  }

  var buf = new Buffer(totalLength)
  var pos = 0
  for (i = 0; i < list.length; i++) {
    var item = list[i]
    item.copy(buf, pos)
    pos += item.length
  }
  return buf
}

// BUFFER INSTANCE METHODS
// =======================

function _hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  assert(strLen % 2 === 0, 'Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; i++) {
    var byte = parseInt(string.substr(i * 2, 2), 16)
    assert(!isNaN(byte), 'Invalid hex string')
    buf[offset + i] = byte
  }
  Buffer._charsWritten = i * 2
  return i
}

function _utf8Write (buf, string, offset, length) {
  var charsWritten = Buffer._charsWritten =
    blitBuffer(utf8ToBytes(string), buf, offset, length)
  return charsWritten
}

function _asciiWrite (buf, string, offset, length) {
  var charsWritten = Buffer._charsWritten =
    blitBuffer(asciiToBytes(string), buf, offset, length)
  return charsWritten
}

function _binaryWrite (buf, string, offset, length) {
  return _asciiWrite(buf, string, offset, length)
}

function _base64Write (buf, string, offset, length) {
  var charsWritten = Buffer._charsWritten =
    blitBuffer(base64ToBytes(string), buf, offset, length)
  return charsWritten
}

Buffer.prototype.write = function (string, offset, length, encoding) {
  // Support both (string, offset, length, encoding)
  // and the legacy (string, encoding, offset, length)
  if (isFinite(offset)) {
    if (!isFinite(length)) {
      encoding = length
      length = undefined
    }
  } else {  // legacy
    var swap = encoding
    encoding = offset
    offset = length
    length = swap
  }

  offset = Number(offset) || 0
  var remaining = this.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }
  encoding = String(encoding || 'utf8').toLowerCase()

  switch (encoding) {
    case 'hex':
      return _hexWrite(this, string, offset, length)
    case 'utf8':
    case 'utf-8':
    case 'ucs2': // TODO: No support for ucs2 or utf16le encodings yet
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return _utf8Write(this, string, offset, length)
    case 'ascii':
      return _asciiWrite(this, string, offset, length)
    case 'binary':
      return _binaryWrite(this, string, offset, length)
    case 'base64':
      return _base64Write(this, string, offset, length)
    default:
      throw new Error('Unknown encoding')
  }
}

Buffer.prototype.toString = function (encoding, start, end) {
  var self = this

  encoding = String(encoding || 'utf8').toLowerCase()
  start = Number(start) || 0
  end = (end !== undefined)
    ? Number(end)
    : end = self.length

  // Fastpath empty strings
  if (end === start)
    return ''

  switch (encoding) {
    case 'hex':
      return _hexSlice(self, start, end)
    case 'utf8':
    case 'utf-8':
    case 'ucs2': // TODO: No support for ucs2 or utf16le encodings yet
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return _utf8Slice(self, start, end)
    case 'ascii':
      return _asciiSlice(self, start, end)
    case 'binary':
      return _binarySlice(self, start, end)
    case 'base64':
      return _base64Slice(self, start, end)
    default:
      throw new Error('Unknown encoding')
  }
}

Buffer.prototype.toJSON = function () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function (target, target_start, start, end) {
  var source = this

  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (!target_start) target_start = 0

  // Copy 0 bytes; we're done
  if (end === start) return
  if (target.length === 0 || source.length === 0) return

  // Fatal error conditions
  assert(end >= start, 'sourceEnd < sourceStart')
  assert(target_start >= 0 && target_start < target.length,
      'targetStart out of bounds')
  assert(start >= 0 && start < source.length, 'sourceStart out of bounds')
  assert(end >= 0 && end <= source.length, 'sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length)
    end = this.length
  if (target.length - target_start < end - start)
    end = target.length - target_start + start

  // copy!
  for (var i = 0; i < end - start; i++)
    target[i + target_start] = this[i + start]
}

function _base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function _utf8Slice (buf, start, end) {
  var res = ''
  var tmp = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++) {
    if (buf[i] <= 0x7F) {
      res += decodeUtf8Char(tmp) + String.fromCharCode(buf[i])
      tmp = ''
    } else {
      tmp += '%' + buf[i].toString(16)
    }
  }

  return res + decodeUtf8Char(tmp)
}

function _asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++)
    ret += String.fromCharCode(buf[i])
  return ret
}

function _binarySlice (buf, start, end) {
  return _asciiSlice(buf, start, end)
}

function _hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; i++) {
    out += toHex(buf[i])
  }
  return out
}

// http://nodejs.org/api/buffer.html#buffer_buf_slice_start_end
Buffer.prototype.slice = function (start, end) {
  var len = this.length
  start = clamp(start, len, 0)
  end = clamp(end, len, len)

  if (Buffer._useTypedArrays) {
    return augment(this.subarray(start, end))
  } else {
    var sliceLen = end - start
    var newBuf = new Buffer(sliceLen, undefined, true)
    for (var i = 0; i < sliceLen; i++) {
      newBuf[i] = this[i + start]
    }
    return newBuf
  }
}

// `get` will be removed in Node 0.13+
Buffer.prototype.get = function (offset) {
  console.log('.get() is deprecated. Access using array indexes instead.')
  return this.readUInt8(offset)
}

// `set` will be removed in Node 0.13+
Buffer.prototype.set = function (v, offset) {
  console.log('.set() is deprecated. Access using array indexes instead.')
  return this.writeUInt8(v, offset)
}

Buffer.prototype.readUInt8 = function (offset, noAssert) {
  if (!noAssert) {
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset < this.length, 'Trying to read beyond buffer length')
  }

  if (offset >= this.length)
    return

  return this[offset]
}

function _readUInt16 (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 1 < buf.length, 'Trying to read beyond buffer length')
  }

  var len = buf.length
  if (offset >= len)
    return

  var val
  if (littleEndian) {
    val = buf[offset]
    if (offset + 1 < len)
      val |= buf[offset + 1] << 8
  } else {
    val = buf[offset] << 8
    if (offset + 1 < len)
      val |= buf[offset + 1]
  }
  return val
}

Buffer.prototype.readUInt16LE = function (offset, noAssert) {
  return _readUInt16(this, offset, true, noAssert)
}

Buffer.prototype.readUInt16BE = function (offset, noAssert) {
  return _readUInt16(this, offset, false, noAssert)
}

function _readUInt32 (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 3 < buf.length, 'Trying to read beyond buffer length')
  }

  var len = buf.length
  if (offset >= len)
    return

  var val
  if (littleEndian) {
    if (offset + 2 < len)
      val = buf[offset + 2] << 16
    if (offset + 1 < len)
      val |= buf[offset + 1] << 8
    val |= buf[offset]
    if (offset + 3 < len)
      val = val + (buf[offset + 3] << 24 >>> 0)
  } else {
    if (offset + 1 < len)
      val = buf[offset + 1] << 16
    if (offset + 2 < len)
      val |= buf[offset + 2] << 8
    if (offset + 3 < len)
      val |= buf[offset + 3]
    val = val + (buf[offset] << 24 >>> 0)
  }
  return val
}

Buffer.prototype.readUInt32LE = function (offset, noAssert) {
  return _readUInt32(this, offset, true, noAssert)
}

Buffer.prototype.readUInt32BE = function (offset, noAssert) {
  return _readUInt32(this, offset, false, noAssert)
}

Buffer.prototype.readInt8 = function (offset, noAssert) {
  if (!noAssert) {
    assert(offset !== undefined && offset !== null,
        'missing offset')
    assert(offset < this.length, 'Trying to read beyond buffer length')
  }

  if (offset >= this.length)
    return

  var neg = this[offset] & 0x80
  if (neg)
    return (0xff - this[offset] + 1) * -1
  else
    return this[offset]
}

function _readInt16 (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 1 < buf.length, 'Trying to read beyond buffer length')
  }

  var len = buf.length
  if (offset >= len)
    return

  var val = _readUInt16(buf, offset, littleEndian, true)
  var neg = val & 0x8000
  if (neg)
    return (0xffff - val + 1) * -1
  else
    return val
}

Buffer.prototype.readInt16LE = function (offset, noAssert) {
  return _readInt16(this, offset, true, noAssert)
}

Buffer.prototype.readInt16BE = function (offset, noAssert) {
  return _readInt16(this, offset, false, noAssert)
}

function _readInt32 (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 3 < buf.length, 'Trying to read beyond buffer length')
  }

  var len = buf.length
  if (offset >= len)
    return

  var val = _readUInt32(buf, offset, littleEndian, true)
  var neg = val & 0x80000000
  if (neg)
    return (0xffffffff - val + 1) * -1
  else
    return val
}

Buffer.prototype.readInt32LE = function (offset, noAssert) {
  return _readInt32(this, offset, true, noAssert)
}

Buffer.prototype.readInt32BE = function (offset, noAssert) {
  return _readInt32(this, offset, false, noAssert)
}

function _readFloat (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset + 3 < buf.length, 'Trying to read beyond buffer length')
  }

  return ieee754.read(buf, offset, littleEndian, 23, 4)
}

Buffer.prototype.readFloatLE = function (offset, noAssert) {
  return _readFloat(this, offset, true, noAssert)
}

Buffer.prototype.readFloatBE = function (offset, noAssert) {
  return _readFloat(this, offset, false, noAssert)
}

function _readDouble (buf, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset + 7 < buf.length, 'Trying to read beyond buffer length')
  }

  return ieee754.read(buf, offset, littleEndian, 52, 8)
}

Buffer.prototype.readDoubleLE = function (offset, noAssert) {
  return _readDouble(this, offset, true, noAssert)
}

Buffer.prototype.readDoubleBE = function (offset, noAssert) {
  return _readDouble(this, offset, false, noAssert)
}

Buffer.prototype.writeUInt8 = function (value, offset, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset < this.length, 'trying to write beyond buffer length')
    verifuint(value, 0xff)
  }

  if (offset >= this.length) return

  this[offset] = value
}

function _writeUInt16 (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 1 < buf.length, 'trying to write beyond buffer length')
    verifuint(value, 0xffff)
  }

  var len = buf.length
  if (offset >= len)
    return

  for (var i = 0, j = Math.min(len - offset, 2); i < j; i++) {
    buf[offset + i] =
        (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
            (littleEndian ? i : 1 - i) * 8
  }
}

Buffer.prototype.writeUInt16LE = function (value, offset, noAssert) {
  _writeUInt16(this, value, offset, true, noAssert)
}

Buffer.prototype.writeUInt16BE = function (value, offset, noAssert) {
  _writeUInt16(this, value, offset, false, noAssert)
}

function _writeUInt32 (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 3 < buf.length, 'trying to write beyond buffer length')
    verifuint(value, 0xffffffff)
  }

  var len = buf.length
  if (offset >= len)
    return

  for (var i = 0, j = Math.min(len - offset, 4); i < j; i++) {
    buf[offset + i] =
        (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
  }
}

Buffer.prototype.writeUInt32LE = function (value, offset, noAssert) {
  _writeUInt32(this, value, offset, true, noAssert)
}

Buffer.prototype.writeUInt32BE = function (value, offset, noAssert) {
  _writeUInt32(this, value, offset, false, noAssert)
}

Buffer.prototype.writeInt8 = function (value, offset, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset < this.length, 'Trying to write beyond buffer length')
    verifsint(value, 0x7f, -0x80)
  }

  if (offset >= this.length)
    return

  if (value >= 0)
    this.writeUInt8(value, offset, noAssert)
  else
    this.writeUInt8(0xff + value + 1, offset, noAssert)
}

function _writeInt16 (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 1 < buf.length, 'Trying to write beyond buffer length')
    verifsint(value, 0x7fff, -0x8000)
  }

  var len = buf.length
  if (offset >= len)
    return

  if (value >= 0)
    _writeUInt16(buf, value, offset, littleEndian, noAssert)
  else
    _writeUInt16(buf, 0xffff + value + 1, offset, littleEndian, noAssert)
}

Buffer.prototype.writeInt16LE = function (value, offset, noAssert) {
  _writeInt16(this, value, offset, true, noAssert)
}

Buffer.prototype.writeInt16BE = function (value, offset, noAssert) {
  _writeInt16(this, value, offset, false, noAssert)
}

function _writeInt32 (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 3 < buf.length, 'Trying to write beyond buffer length')
    verifsint(value, 0x7fffffff, -0x80000000)
  }

  var len = buf.length
  if (offset >= len)
    return

  if (value >= 0)
    _writeUInt32(buf, value, offset, littleEndian, noAssert)
  else
    _writeUInt32(buf, 0xffffffff + value + 1, offset, littleEndian, noAssert)
}

Buffer.prototype.writeInt32LE = function (value, offset, noAssert) {
  _writeInt32(this, value, offset, true, noAssert)
}

Buffer.prototype.writeInt32BE = function (value, offset, noAssert) {
  _writeInt32(this, value, offset, false, noAssert)
}

function _writeFloat (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 3 < buf.length, 'Trying to write beyond buffer length')
    verifIEEE754(value, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }

  var len = buf.length
  if (offset >= len)
    return

  ieee754.write(buf, value, offset, littleEndian, 23, 4)
}

Buffer.prototype.writeFloatLE = function (value, offset, noAssert) {
  _writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function (value, offset, noAssert) {
  _writeFloat(this, value, offset, false, noAssert)
}

function _writeDouble (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    assert(value !== undefined && value !== null, 'missing value')
    assert(typeof littleEndian === 'boolean', 'missing or invalid endian')
    assert(offset !== undefined && offset !== null, 'missing offset')
    assert(offset + 7 < buf.length,
        'Trying to write beyond buffer length')
    verifIEEE754(value, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }

  var len = buf.length
  if (offset >= len)
    return

  ieee754.write(buf, value, offset, littleEndian, 52, 8)
}

Buffer.prototype.writeDoubleLE = function (value, offset, noAssert) {
  _writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function (value, offset, noAssert) {
  _writeDouble(this, value, offset, false, noAssert)
}

// fill(value, start=0, end=buffer.length)
Buffer.prototype.fill = function (value, start, end) {
  if (!value) value = 0
  if (!start) start = 0
  if (!end) end = this.length

  if (typeof value === 'string') {
    value = value.charCodeAt(0)
  }

  assert(typeof value === 'number' && !isNaN(value), 'value is not a number')
  assert(end >= start, 'end < start')

  // Fill 0 bytes; we're done
  if (end === start) return
  if (this.length === 0) return

  assert(start >= 0 && start < this.length, 'start out of bounds')
  assert(end >= 0 && end <= this.length, 'end out of bounds')

  for (var i = start; i < end; i++) {
    this[i] = value
  }
}

Buffer.prototype.inspect = function () {
  var out = []
  var len = this.length
  for (var i = 0; i < len; i++) {
    out[i] = toHex(this[i])
    if (i === exports.INSPECT_MAX_BYTES) {
      out[i + 1] = '...'
      break
    }
  }
  return '<Buffer ' + out.join(' ') + '>'
}

/**
 * Creates a new `ArrayBuffer` with the *copied* memory of the buffer instance.
 * Added in Node 0.12. Only available in browsers that support ArrayBuffer.
 */
Buffer.prototype.toArrayBuffer = function () {
  if (typeof Uint8Array === 'function') {
    if (Buffer._useTypedArrays) {
      return (new Buffer(this)).buffer
    } else {
      var buf = new Uint8Array(this.length)
      for (var i = 0, len = buf.length; i < len; i += 1)
        buf[i] = this[i]
      return buf.buffer
    }
  } else {
    throw new Error('Buffer.toArrayBuffer not supported in this browser')
  }
}

// HELPER FUNCTIONS
// ================

function stringtrim (str) {
  if (str.trim) return str.trim()
  return str.replace(/^\s+|\s+$/g, '')
}

var BP = Buffer.prototype

/**
 * Augment the Uint8Array *instance* (not the class!) with Buffer methods
 */
function augment (arr) {
  arr._isBuffer = true

  // save reference to original Uint8Array get/set methods before overwriting
  arr._get = arr.get
  arr._set = arr.set

  // deprecated, will be removed in node 0.13+
  arr.get = BP.get
  arr.set = BP.set

  arr.write = BP.write
  arr.toString = BP.toString
  arr.toLocaleString = BP.toString
  arr.toJSON = BP.toJSON
  arr.copy = BP.copy
  arr.slice = BP.slice
  arr.readUInt8 = BP.readUInt8
  arr.readUInt16LE = BP.readUInt16LE
  arr.readUInt16BE = BP.readUInt16BE
  arr.readUInt32LE = BP.readUInt32LE
  arr.readUInt32BE = BP.readUInt32BE
  arr.readInt8 = BP.readInt8
  arr.readInt16LE = BP.readInt16LE
  arr.readInt16BE = BP.readInt16BE
  arr.readInt32LE = BP.readInt32LE
  arr.readInt32BE = BP.readInt32BE
  arr.readFloatLE = BP.readFloatLE
  arr.readFloatBE = BP.readFloatBE
  arr.readDoubleLE = BP.readDoubleLE
  arr.readDoubleBE = BP.readDoubleBE
  arr.writeUInt8 = BP.writeUInt8
  arr.writeUInt16LE = BP.writeUInt16LE
  arr.writeUInt16BE = BP.writeUInt16BE
  arr.writeUInt32LE = BP.writeUInt32LE
  arr.writeUInt32BE = BP.writeUInt32BE
  arr.writeInt8 = BP.writeInt8
  arr.writeInt16LE = BP.writeInt16LE
  arr.writeInt16BE = BP.writeInt16BE
  arr.writeInt32LE = BP.writeInt32LE
  arr.writeInt32BE = BP.writeInt32BE
  arr.writeFloatLE = BP.writeFloatLE
  arr.writeFloatBE = BP.writeFloatBE
  arr.writeDoubleLE = BP.writeDoubleLE
  arr.writeDoubleBE = BP.writeDoubleBE
  arr.fill = BP.fill
  arr.inspect = BP.inspect
  arr.toArrayBuffer = BP.toArrayBuffer

  return arr
}

// slice(start, end)
function clamp (index, len, defaultValue) {
  if (typeof index !== 'number') return defaultValue
  index = ~~index;  // Coerce to integer.
  if (index >= len) return len
  if (index >= 0) return index
  index += len
  if (index >= 0) return index
  return 0
}

function coerce (length) {
  // Coerce length to a number (possibly NaN), round up
  // in case it's fractional (e.g. 123.456) then do a
  // double negate to coerce a NaN to 0. Easy, right?
  length = ~~Math.ceil(+length)
  return length < 0 ? 0 : length
}

function isArray (subject) {
  return (Array.isArray || function (subject) {
    return Object.prototype.toString.call(subject) === '[object Array]'
  })(subject)
}

function isArrayish (subject) {
  return isArray(subject) || Buffer.isBuffer(subject) ||
      subject && typeof subject === 'object' &&
      typeof subject.length === 'number'
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    var b = str.charCodeAt(i)
    if (b <= 0x7F)
      byteArray.push(str.charCodeAt(i))
    else {
      var start = i
      if (b >= 0xD800 && b <= 0xDFFF) i++
      var h = encodeURIComponent(str.slice(start, i+1)).substr(1).split('%')
      for (var j = 0; j < h.length; j++)
        byteArray.push(parseInt(h[j], 16))
    }
  }
  return byteArray
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(str)
}

function blitBuffer (src, dst, offset, length) {
  var pos
  for (var i = 0; i < length; i++) {
    if ((i + offset >= dst.length) || (i >= src.length))
      break
    dst[i + offset] = src[i]
  }
  return i
}

function decodeUtf8Char (str) {
  try {
    return decodeURIComponent(str)
  } catch (err) {
    return String.fromCharCode(0xFFFD) // UTF 8 invalid char
  }
}

/*
 * We have to make sure that the value is a valid integer. This means that it
 * is non-negative. It has no fractional component and that it does not
 * exceed the maximum allowed value.
 */
function verifuint (value, max) {
  assert(typeof value == 'number', 'cannot write a non-number as a number')
  assert(value >= 0,
      'specified a negative value for writing an unsigned value')
  assert(value <= max, 'value is larger than maximum value for type')
  assert(Math.floor(value) === value, 'value has a fractional component')
}

function verifsint(value, max, min) {
  assert(typeof value == 'number', 'cannot write a non-number as a number')
  assert(value <= max, 'value larger than maximum allowed value')
  assert(value >= min, 'value smaller than minimum allowed value')
  assert(Math.floor(value) === value, 'value has a fractional component')
}

function verifIEEE754(value, max, min) {
  assert(typeof value == 'number', 'cannot write a non-number as a number')
  assert(value <= max, 'value larger than maximum allowed value')
  assert(value >= min, 'value smaller than minimum allowed value')
}

function assert (test, message) {
  if (!test) throw new Error(message || 'Failed assertion')
}

},{"base64-js":24,"ieee754":25}],24:[function(_dereq_,module,exports){
var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

;(function (exports) {
	'use strict';

  var Arr = (typeof Uint8Array !== 'undefined')
    ? Uint8Array
    : Array

	var ZERO   = '0'.charCodeAt(0)
	var PLUS   = '+'.charCodeAt(0)
	var SLASH  = '/'.charCodeAt(0)
	var NUMBER = '0'.charCodeAt(0)
	var LOWER  = 'a'.charCodeAt(0)
	var UPPER  = 'A'.charCodeAt(0)

	function decode (elt) {
		var code = elt.charCodeAt(0)
		if (code === PLUS)
			return 62 // '+'
		if (code === SLASH)
			return 63 // '/'
		if (code < NUMBER)
			return -1 //no match
		if (code < NUMBER + 10)
			return code - NUMBER + 26 + 26
		if (code < UPPER + 26)
			return code - UPPER
		if (code < LOWER + 26)
			return code - LOWER + 26
	}

	function b64ToByteArray (b64) {
		var i, j, l, tmp, placeHolders, arr

		if (b64.length % 4 > 0) {
			throw new Error('Invalid string. Length must be a multiple of 4')
		}

		// the number of equal signs (place holders)
		// if there are two placeholders, than the two characters before it
		// represent one byte
		// if there is only one, then the three characters before it represent 2 bytes
		// this is just a cheap hack to not do indexOf twice
		var len = b64.length
		placeHolders = '=' === b64.charAt(len - 2) ? 2 : '=' === b64.charAt(len - 1) ? 1 : 0

		// base64 is 4/3 + up to two characters of the original data
		arr = new Arr(b64.length * 3 / 4 - placeHolders)

		// if there are placeholders, only get up to the last complete 4 chars
		l = placeHolders > 0 ? b64.length - 4 : b64.length

		var L = 0

		function push (v) {
			arr[L++] = v
		}

		for (i = 0, j = 0; i < l; i += 4, j += 3) {
			tmp = (decode(b64.charAt(i)) << 18) | (decode(b64.charAt(i + 1)) << 12) | (decode(b64.charAt(i + 2)) << 6) | decode(b64.charAt(i + 3))
			push((tmp & 0xFF0000) >> 16)
			push((tmp & 0xFF00) >> 8)
			push(tmp & 0xFF)
		}

		if (placeHolders === 2) {
			tmp = (decode(b64.charAt(i)) << 2) | (decode(b64.charAt(i + 1)) >> 4)
			push(tmp & 0xFF)
		} else if (placeHolders === 1) {
			tmp = (decode(b64.charAt(i)) << 10) | (decode(b64.charAt(i + 1)) << 4) | (decode(b64.charAt(i + 2)) >> 2)
			push((tmp >> 8) & 0xFF)
			push(tmp & 0xFF)
		}

		return arr
	}

	function uint8ToBase64 (uint8) {
		var i,
			extraBytes = uint8.length % 3, // if we have 1 byte left, pad 2 bytes
			output = "",
			temp, length

		function encode (num) {
			return lookup.charAt(num)
		}

		function tripletToBase64 (num) {
			return encode(num >> 18 & 0x3F) + encode(num >> 12 & 0x3F) + encode(num >> 6 & 0x3F) + encode(num & 0x3F)
		}

		// go through the array every three bytes, we'll deal with trailing stuff later
		for (i = 0, length = uint8.length - extraBytes; i < length; i += 3) {
			temp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
			output += tripletToBase64(temp)
		}

		// pad the end with zeros, but make sure to not forget the extra bytes
		switch (extraBytes) {
			case 1:
				temp = uint8[uint8.length - 1]
				output += encode(temp >> 2)
				output += encode((temp << 4) & 0x3F)
				output += '=='
				break
			case 2:
				temp = (uint8[uint8.length - 2] << 8) + (uint8[uint8.length - 1])
				output += encode(temp >> 10)
				output += encode((temp >> 4) & 0x3F)
				output += encode((temp << 2) & 0x3F)
				output += '='
				break
		}

		return output
	}

	module.exports.toByteArray = b64ToByteArray
	module.exports.fromByteArray = uint8ToBase64
}())

},{}],25:[function(_dereq_,module,exports){
exports.read = function(buffer, offset, isLE, mLen, nBytes) {
  var e, m,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      nBits = -7,
      i = isLE ? (nBytes - 1) : 0,
      d = isLE ? -1 : 1,
      s = buffer[offset + i];

  i += d;

  e = s & ((1 << (-nBits)) - 1);
  s >>= (-nBits);
  nBits += eLen;
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8);

  m = e & ((1 << (-nBits)) - 1);
  e >>= (-nBits);
  nBits += mLen;
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8);

  if (e === 0) {
    e = 1 - eBias;
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity);
  } else {
    m = m + Math.pow(2, mLen);
    e = e - eBias;
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
};

exports.write = function(buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c,
      eLen = nBytes * 8 - mLen - 1,
      eMax = (1 << eLen) - 1,
      eBias = eMax >> 1,
      rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0),
      i = isLE ? 0 : (nBytes - 1),
      d = isLE ? 1 : -1,
      s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

  value = Math.abs(value);

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0;
    e = eMax;
  } else {
    e = Math.floor(Math.log(value) / Math.LN2);
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--;
      c *= 2;
    }
    if (e + eBias >= 1) {
      value += rt / c;
    } else {
      value += rt * Math.pow(2, 1 - eBias);
    }
    if (value * c >= 2) {
      e++;
      c /= 2;
    }

    if (e + eBias >= eMax) {
      m = 0;
      e = eMax;
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen);
      e = e + eBias;
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
      e = 0;
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8);

  e = (e << mLen) | m;
  eLen += mLen;
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8);

  buffer[offset + i - d] |= s * 128;
};

},{}]},{},[1])
(1)
});