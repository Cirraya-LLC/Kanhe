// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Embeds the range proofs' circuit (spec section 11.3) in the browser
// verifier: reads the published circuit file (zstd, decompressed with
// Node.js's zlib), compresses it again as one GZIP member, which the
// verifier's own decompressor reads (kanhe/verifier/gzip.hpp), and writes it
// as a C++ array. The verifier checks the circuit's id when it loads it, so
// this changes nothing it relies on.
//
// The DEFLATE stream is made here, not by zlib, whose output differs from
// one version, build, or processor to the next: the same circuit file gives
// the same page wherever it is built. It is one block of fixed Huffman codes,
// with matches found greedily through hash chains and taken one byte later
// when that one is longer.
//
// Usage: node embed-circuit.js CIRCUIT_ZST OUT_CPP
"use strict";
const fs = require("node:fs");
const zlib = require("node:zlib");

const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
  163, 195, 227, 258];
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DISTANCE_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
  2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DISTANCE_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
  13];
const WINDOW = 32768;
const MIN_MATCH = 3;
const MAX_MATCH = 258;
const CHAIN = 1024; // candidates tried at each position

// RFC 1951: one final block with the fixed codes (section 3.2.6).
function deflate(data) {
  const out = [];
  let held = 0;
  let count = 0;
  const bits = (value, n) => { // least significant bit first
    held |= value << count;
    count += n;
    while (count >= 8) {
      out.push(held & 0xff);
      held >>>= 8;
      count -= 8;
    }
  };
  const code = (value, n) => { // Huffman codes go most significant bit first
    let reversed = 0;
    for (let i = 0; i < n; i++) reversed = (reversed << 1) | ((value >>> i) & 1);
    bits(reversed, n);
  };
  const symbol = (s) => {
    if (s < 144) code(0x30 + s, 8);
    else if (s < 256) code(0x190 + s - 144, 9);
    else if (s < 280) code(s - 256, 7);
    else code(0xc0 + s - 280, 8);
  };
  const below = (bases, v) => {
    let i = bases.length - 1;
    while (bases[i] > v) i--;
    return i;
  };
  const match = (length, distance) => {
    const l = below(LENGTH_BASE, length);
    symbol(257 + l);
    bits(length - LENGTH_BASE[l], LENGTH_EXTRA[l]);
    const d = below(DISTANCE_BASE, distance);
    code(d, 5);
    bits(distance - DISTANCE_BASE[d], DISTANCE_EXTRA[d]);
  };

  const n = data.length;
  const head = new Int32Array(1 << 16).fill(-1);
  const previous = new Int32Array(WINDOW).fill(-1);
  const hash = (i) => ((data[i] << 8) ^ (data[i + 1] << 4) ^ data[i + 2]) & 0xffff;
  const insert = (i) => {
    if (i + MIN_MATCH > n) return;
    const h = hash(i);
    previous[i % WINDOW] = head[h];
    head[h] = i;
  };
  // The longest earlier match for position i: [length, distance], or [0, 0].
  const longest = (i) => {
    if (i + MIN_MATCH > n) return [0, 0];
    const limit = Math.min(MAX_MATCH, n - i);
    let best = 0;
    let from = 0;
    let tries = CHAIN;
    for (let j = head[hash(i)]; j >= 0 && i - j <= WINDOW && tries > 0; tries--) {
      if (data[j + best] === data[i + best]) {
        let k = 0;
        while (k < limit && data[j + k] === data[i + k]) k++;
        if (k > best) {
          best = k;
          from = j;
          if (k === limit) break;
        }
      }
      const p = previous[j % WINDOW];
      if (p >= j) break; // the slot was taken by a later position
      j = p;
    }
    return best >= MIN_MATCH ? [best, i - from] : [0, 0];
  };

  bits(1, 1); // the last block
  bits(1, 2); // fixed Huffman codes
  let i = 0;
  while (i < n) {
    let [length, distance] = longest(i);
    if (length === 0) {
      symbol(data[i]);
      insert(i);
      i += 1;
      continue;
    }
    insert(i);
    if (length < MAX_MATCH) {
      const [later, laterDistance] = longest(i + 1);
      if (later > length) {
        symbol(data[i]);
        i += 1;
        insert(i);
        [length, distance] = [later, laterDistance];
      }
    }
    match(length, distance);
    for (let k = 1; k < length; k++) insert(i + k);
    i += length;
  }
  symbol(256);
  if (count > 0) out.push(held & 0xff);
  return Uint8Array.from(out);
}

function crc32(data) {
  const table = new Uint32Array(256);
  for (let k = 0; k < 256; k++) {
    let c = k;
    for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[k] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (const byte of data) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// RFC 1952: no name, no time, the operating system unknown.
function gzip(data) {
  const le32 = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
  return Uint8Array.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, ...deflate(data), ...le32(crc32(data)),
    ...le32(data.length >>> 0)]);
}

function main() {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) {
    console.error("usage: node embed-circuit.js CIRCUIT_ZST OUT_CPP");
    process.exit(2);
  }
  if (typeof zlib.zstdDecompressSync !== "function") {
    console.error("embed-circuit.js: reading the circuit file needs Node.js 22.15 or later (zstd)");
    process.exit(1);
  }
  const circuit = zlib.zstdDecompressSync(fs.readFileSync(input));
  const compressed = gzip(circuit);
  // What zlib reads back must be the circuit, byte for byte.
  if (Buffer.compare(zlib.gunzipSync(compressed), circuit) !== 0) {
    console.error("embed-circuit.js: the compressed circuit does not decompress to the circuit");
    process.exit(1);
  }
  const rows = [];
  for (let at = 0; at < compressed.length; at += 16) {
    rows.push("    " + Array.from(compressed.subarray(at, at + 16), (b) => "0x" + b.toString(16).padStart(2, "0"))
      .join(", ") + ",");
  }
  const source = [
    "// Generated by chain/verifier/wasm/embed-circuit.js from the range proofs'",
    "// circuit file: the circuit, " + circuit.length + " bytes, as one GZIP member.",
    "",
    "#include <cstddef>",
    "#include <cstdint>",
    "",
    "namespace kanhe::verifier_wasm {",
    "",
    "extern const std::uint8_t range_circuit_gzip[];",
    "extern const std::size_t range_circuit_gzip_size;",
    "extern const std::size_t range_circuit_size;",
    "",
    "const std::uint8_t range_circuit_gzip[] = {",
    ...rows,
    "};",
    "const std::size_t range_circuit_gzip_size = sizeof(range_circuit_gzip);",
    "const std::size_t range_circuit_size = " + circuit.length + ";",
    "",
    "} // namespace kanhe::verifier_wasm",
    "",
  ].join("\n");
  fs.writeFileSync(output, source);
}

main();
