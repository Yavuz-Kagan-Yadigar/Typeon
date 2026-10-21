package com.p2p.messenger.util

import java.io.File

/** Minimal GIF decoder: full-canvas RGBA frames (not premultiplied) + delays. */
class GifFrames(val width: Int, val height: Int, val frames: Array<ByteArray>, val delaysMs: IntArray, val hasAlpha: Boolean) {
    companion object {
        /** Null when it is not a GIF, is corrupt, or exceeds [maxFrames] / [maxPixels] (width*height*frames). */
        fun decode(file: File, maxFrames: Int, maxPixels: Long): GifFrames? = try { parse(file.readBytes(), maxFrames, maxPixels) } catch (e: Exception) { null }

        private fun parse(d: ByteArray, maxFrames: Int, maxPixels: Long): GifFrames? {
            if (d.size < 13 || String(d, 0, 3, Charsets.ISO_8859_1) != "GIF") return null
            fun u8(i: Int) = d[i].toInt() and 0xFF
            fun u16(i: Int) = u8(i) or (u8(i + 1) shl 8)
            val w = u16(6); val h = u16(8)
            if (w == 0 || h == 0 || w.toLong() * h > maxPixels) return null
            var pos = 13
            var gct: IntArray? = null
            if (u8(10) and 0x80 != 0) { val n = 2 shl (u8(10) and 7); gct = palette(d, pos, n); pos += n * 3 }
            var canvas = IntArray(w * h)
            val out = ArrayList<ByteArray>(); val delays = ArrayList<Int>()
            var delay = 100; var transp = -1; var disposal = 0; var alpha = false
            while (pos < d.size) {
                when (u8(pos++)) {
                    0x21 -> {
                        val label = u8(pos++)
                        if (label == 0xF9 && u8(pos) >= 4) {
                            val f = u8(pos + 1); disposal = (f shr 2) and 7
                            delay = u16(pos + 2) * 10; if (delay <= 10) delay = 100
                            transp = if (f and 1 != 0) u8(pos + 4) else -1
                        }
                        while (true) { val n = u8(pos++); if (n == 0) break; pos += n }
                    }
                    0x2C -> {
                        val ix = u16(pos); val iy = u16(pos + 2); val iw = u16(pos + 4); val ih = u16(pos + 6); val fl = u8(pos + 8)
                        pos += 9
                        var pal = gct
                        if (fl and 0x80 != 0) { val n = 2 shl (fl and 7); pal = palette(d, pos, n); pos += n * 3 }
                        if (pal == null || ix + iw > w || iy + ih > h) return null
                        val minCode = u8(pos++)
                        val data = java.io.ByteArrayOutputStream()
                        while (true) { val n = u8(pos++); if (n == 0) break; data.write(d, pos, n); pos += n }
                        val idx = lzw(data.toByteArray(), minCode, iw * ih)
                        if (out.size >= maxFrames || (out.size + 1L) * w * h > maxPixels) return null
                        val prev = if (disposal == 3) canvas.copyOf() else null
                        val rows = if (fl and 0x40 != 0) interlaced(ih) else IntArray(ih) { it }
                        for (r in 0 until ih) for (x in 0 until iw) {
                            val c = idx[r * iw + x].toInt() and 0xFF
                            if (c == transp) continue
                            canvas[(iy + rows[r]) * w + ix + x] = pal[c.coerceAtMost(pal.size - 1)]
                        }
                        if (canvas.any { it ushr 24 == 0 }) alpha = true
                        val bytes = ByteArray(w * h * 4)
                        for (i in canvas.indices) {
                            val p = canvas[i]
                            bytes[i * 4] = (p shr 16).toByte(); bytes[i * 4 + 1] = (p shr 8).toByte()
                            bytes[i * 4 + 2] = p.toByte(); bytes[i * 4 + 3] = (p ushr 24).toByte()
                        }
                        out.add(bytes); delays.add(delay)
                        when (disposal) {
                            2 -> for (r in 0 until ih) java.util.Arrays.fill(canvas, (iy + r) * w + ix, (iy + r) * w + ix + iw, 0)
                            3 -> canvas = prev!!
                        }
                        disposal = 0; transp = -1
                    }
                    0x3B -> break
                    else -> return null
                }
            }
            if (out.size < 2) return null // a still GIF goes the normal way
            return GifFrames(w, h, out.toTypedArray(), delays.toIntArray(), alpha)
        }

        private fun palette(d: ByteArray, pos: Int, n: Int) = IntArray(n) {
            val o = pos + it * 3
            (0xFF shl 24) or ((d[o].toInt() and 0xFF) shl 16) or ((d[o + 1].toInt() and 0xFF) shl 8) or (d[o + 2].toInt() and 0xFF)
        }

        private fun interlaced(h: Int): IntArray {
            val r = ArrayList<Int>()
            for ((s, st) in listOf(0 to 8, 4 to 8, 2 to 4, 1 to 2)) { var y = s; while (y < h) { r.add(y); y += st } }
            return r.toIntArray()
        }

        private fun lzw(src: ByteArray, minCode: Int, total: Int): ByteArray {
            val out = ByteArray(total)
            val clear = 1 shl minCode; val eoi = clear + 1
            val prefix = IntArray(4096); val suffix = ByteArray(4096); val stack = ByteArray(4097)
            var size = minCode + 1; var next = eoi + 1; var prev = -1; var first = 0
            var acc = 0; var bits = 0; var sp = 0; var o = 0; var i = 0
            for (c in 0 until clear) suffix[c] = c.toByte()
            while (o < total) {
                while (bits < size && i < src.size) { acc = acc or ((src[i++].toInt() and 0xFF) shl bits); bits += 8 }
                if (bits < size) break
                var code = acc and ((1 shl size) - 1); acc = acc ushr size; bits -= size
                if (code == clear) { size = minCode + 1; next = eoi + 1; prev = -1; continue }
                if (code == eoi) break
                if (prev == -1) { out[o++] = suffix[code]; prev = code; first = code; continue }
                val inCode = code
                if (code >= next) { stack[sp++] = first.toByte(); code = prev }
                while (code >= clear) { stack[sp++] = suffix[code]; code = prefix[code] }
                first = suffix[code].toInt() and 0xFF
                stack[sp++] = first.toByte()
                if (next < 4096) {
                    prefix[next] = prev; suffix[next] = first.toByte(); next++
                    if (next == (1 shl size) && size < 12) size++
                }
                prev = inCode
                while (sp > 0 && o < total) out[o++] = stack[--sp]
                sp = 0
            }
            return out
        }
    }
}
