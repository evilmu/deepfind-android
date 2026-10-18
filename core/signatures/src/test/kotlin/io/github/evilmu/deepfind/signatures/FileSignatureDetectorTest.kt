package io.github.evilmu.deepfind.signatures

import org.junit.Assert.*
import org.junit.Test

class FileSignatureDetectorTest {
    @Test fun pdf() {
        val found = FileSignatureDetector.detect("%PDF-1.7".toByteArray())
        assertEquals(DetectedType.PDF, found.type)
        assertTrue(found.mismatchedExtension("cache.bin"))
    }
    @Test fun sqlite() {
        assertEquals(DetectedType.SQLITE,
            FileSignatureDetector.detect("SQLite format 3\u0000".toByteArray()).type)
    }
    @Test fun wav() {
        assertEquals(DetectedType.WAV,
            FileSignatureDetector.detect("RIFF....WAVEfmt ".toByteArray()).type)
    }
    @Test fun zipNotClaimedAsApk() {
        val found = FileSignatureDetector.detect(byteArrayOf(0x50,0x4b,0x03,0x04))
        assertEquals(DetectedType.ZIP, found.type)
        assertFalse(found.mismatchedExtension("app.apk"))
    }
    @Test fun ebml() {
        assertEquals(DetectedType.EBML,
            FileSignatureDetector.detect(byteArrayOf(0x1a,0x45,0xdf.toByte(),0xa3.toByte())).type)
    }
    @Test fun unknown() {
        assertEquals(Confidence.NONE,
            FileSignatureDetector.detect(byteArrayOf(0x04, 0x06, 0x08)).confidence)
    }
}
