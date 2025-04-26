/*
 * JavaScript implementation of SHA-256
 * Version 1.0
 * Copyright (C) 2025 Saher
 */

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF)
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
  return (msw << 16) | (lsw & 0xFFFF)
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt))
}

/*
 * This function applies the SHA-256 algorithm to a given input string.
 */
function sha256(input)
{
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x27b5a36e, 0x2f63c11e, 0x7a8f7e7e, 0x5a5e5f0e, 0x56a22e76, 0x722014b6,
  ]

  // Preprocess the input string (padding and length appending)
  var msg = str2binl(input);
  var msg_len = input.length * 8;
  msg[msg.length >> 5] |= 0x80 << (24 - msg_len % 32);
  msg[((msg.length + 64 >> 9) << 4) + 15] = msg_len;

  var w = new Array(64);
  var a, b, c, d, e, f, g, h;
  a = 0x6a09e667;
  b = 0xbb67ae85;
  c = 0x3c6ef372;
  d = 0xa54ff53a;
  e = 0x510e527f;
  f = 0x9b05688c;
  g = 0x1f83d9ab;
  h = 0x5be0cd19;

  // Main loop
  for (var i = 0; i < msg.length; i += 16) {
    var old_a = a;
    var old_b = b;
    var old_c = c;
    var old_d = d;
    var old_e = e;
    var old_f = f;
    var old_g = g;
    var old_h = h;

    for (var j = 0; j < 16; j++) {
      w[j] = msg[i + j];
    }
    for (var j = 16; j < 64; j++) {
      w[j] = safe_add(safe_add(safe_add(rol(w[j - 2], 17), rol(w[j - 2], 19)), (w[j - 2] >>> 10)), w[j - 7]);
      w[j] = safe_add(safe_add(safe_add(rol(w[j - 15], 7), rol(w[j - 15], 18)), (w[j - 15] >>> 3)), w[j - 16]);
    }

    for (var j = 0; j < 64; j++) {
      var temp1 = safe_add(safe_add(safe_add(safe_add(h, rol(e, 6)), (e & f) ^ (~e & g)), K[j]), w[j]));
      var temp2 = safe_add(rol(a, 2), ((a & b) ^ (a & c) ^ (b & c)));

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    a = safe_add(a, old_a);
    b = safe_add(b, old_b);
    c = safe_add(c, old_c);
    d = safe_add(d, old_d);
    e = safe_add(e, old_e);
    f = safe_add(f, old_f);
    g = safe_add(g, old_g);
    h = safe_add(h, old_h);
  }

  return [a, b, c, d, e, f, g, h];
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
  var hex_tab = "0123456789abcdef";
  var str = "";
  for (var i = 0; i < binarray.length * 4; i++) {
    str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
           hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
  }
  return str;
}

/*
 * Convert an 8-bit character string to a sequence of 16-word blocks, stored
 * as an array, and append appropriate padding for SHA-256 calculation.
 */
function str2binl(str)
{
  var nblk = ((str.length + 8) >> 6) + 1; // number of 16-word blocks
  var blks = new Array(nblk * 16);
  for (var i = 0; i < nblk * 16; i++) blks[i] = 0;
  for (var i = 0; i < str.length; i++) {
    blks[i >> 2] |= (str.charCodeAt(i) & 0xFF) << ((i % 4) * 8);
  }
  blks[i >> 2] |= 0x80 << ((i % 4) * 8);
  blks[nblk * 16 - 2] = str.length * 8;
  return blks;
}

/*
 * External interface
 */
function hexSHA256(str) {
  return binl2hex(sha256(str));
}

console.log(hexSHA256("Hello, world!"));
