#!/usr/bin/env node
/**
 * Generates the extension's PNG icons from code so the repository carries no binary blobs
 * (easier to security-review; nothing opaque in git). Draws a rounded shield with a lens cutout.
 */
import { deflateSync } from 'node:zlib';
import { writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outdir = path.join(root, 'assets/icons');

const TEAL = [13, 148, 136];
const DEEP = [15, 62, 68];
const WHITE = [255, 255, 255];

function crc32(buf) {
  let c = ~0;
  for (const byte of buf) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // truecolour + alpha
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // no filter
    pixels.copy(raw, rowStart + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Signed distance to a rounded rectangle centred at (0,0) with half-extents (hx,hy). */
function sdRoundRect(x, y, hx, hy, r) {
  const dx = Math.abs(x) - (hx - r);
  const dy = Math.abs(y) - (hy - r);
  const ox = Math.max(dx, 0);
  const oy = Math.max(dy, 0);
  return Math.hypot(ox, oy) + Math.min(Math.max(dx, dy), 0) - r;
}

function mix(a, b, t) {
  return [
    Math.round(a[0] + (b[0] - a[0]) * t),
    Math.round(a[1] + (b[1] - a[1]) * t),
    Math.round(a[2] + (b[2] - a[2]) * t),
  ];
}

/** Coverage of a shape, sampled 3x3 per pixel for cheap antialiasing. */
function coverage(px, py, size, sdf) {
  let hits = 0;
  for (let sy = 0; sy < 3; sy++) {
    for (let sx = 0; sx < 3; sx++) {
      const x = ((px + (sx + 0.5) / 3) / size) * 2 - 1;
      const y = ((py + (sy + 0.5) / 3) / size) * 2 - 1;
      if (sdf(x, y) <= 0) hits++;
    }
  }
  return hits / 9;
}

function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const badge = (x, y) => sdRoundRect(x, y, 0.86, 0.86, 0.34);
  const lensOuter = (x, y) => Math.hypot(x + 0.1, y + 0.1) - 0.44;
  const lensInner = (x, y) => Math.hypot(x + 0.1, y + 0.1) - 0.26;
  // Diagonal handle from the lens edge toward the lower-right corner.
  const handle = (x, y) => {
    const u = (x - 0.24 + (y - 0.24)) / 2;
    const t = Math.min(Math.max(u, 0), 0.34);
    return Math.hypot(x - 0.24 - t, y - 0.24 - t) - (size <= 16 ? 0.11 : 0.095);
  };

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      const i = (py * size + px) * 4;
      const cBadge = coverage(px, py, size, badge);
      if (cBadge <= 0) continue;

      const base = mix(TEAL, DEEP, py / size);
      const ring = Math.max(
        0,
        coverage(px, py, size, lensOuter) - coverage(px, py, size, lensInner),
      );
      const stem = coverage(px, py, size, handle);
      const glyph = Math.min(1, ring + stem);
      const rgb = mix(base, WHITE, glyph);

      pixels[i] = rgb[0];
      pixels[i + 1] = rgb[1];
      pixels[i + 2] = rgb[2];
      pixels[i + 3] = Math.round(255 * cBadge);
    }
  }
  return encodePng(size, pixels);
}

await mkdir(outdir, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  await writeFile(path.join(outdir, `icon${size}.png`), render(size));
}
