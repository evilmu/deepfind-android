package io.github.evilmu.deepfind.signatures

enum class Confidence { HIGH, MEDIUM, LOW, NONE }

enum class DetectedType(val label: String, val extensions: Set<String>) {
    PDF("PDF", setOf("pdf")),
    PNG("PNG image", setOf("png")),
    JPEG("JPEG image", setOf("jpg", "jpeg", "jpe")),
    GIF("GIF image", setOf("gif")),
    ZIP("ZIP container (APK possible)", setOf("zip", "apk", "jar", "docx", "xlsx", "pptx", "epub")),
    RAR("RAR archive", setOf("rar")),
    GZIP("GZIP archive", setOf("gz", "tgz")),
    SQLITE("SQLite database", setOf("sqlite", "sqlite3", "db")),
    SQLITE_WAL("SQLite WAL", setOf("wal")),
    WAV("WAV audio", setOf("wav")),
    FLAC("FLAC audio", setOf("flac")),
    OGG("Ogg / Opus container", setOf("ogg", "oga", "opus", "ogv")),
    MP3("MP3 audio", setOf("mp3")),
    MP4("ISO BMFF (MP4/M4A possible)", setOf("mp4", "m4a", "m4v", "mov", "3gp")),
    EBML("EBML (WebM / Matroska possible)", setOf("webm", "mkv", "mka")),
    ELF("ELF binary", setOf("elf", "so")),
    DEX("Android DEX", setOf("dex")),
    MHTML("MHTML page archive", setOf("mhtml", "mht")),
    UNKNOWN("Unknown", emptySet())
}

data class Detection(val type: DetectedType, val confidence: Confidence, val reason: String) {
    fun mismatchedExtension(name: String): Boolean {
        val ext = name.substringAfterLast('.', "").lowercase()
        return ext.isNotBlank() && type != DetectedType.UNKNOWN && ext !in type.extensions
    }
}

object FileSignatureDetector {
    private fun ByteArray.has(vararg magic: Int, offset: Int = 0): Boolean =
        size >= offset + magic.size && magic.indices.all { i ->
            (this[offset + i].toInt() and 0xff) == magic[i]
        }
    private fun ByteArray.ascii(s: String, offset: Int = 0): Boolean {
        val bytes = s.toByteArray(Charsets.US_ASCII)
        return size >= offset + bytes.size && bytes.indices.all { i -> this[offset + i] == bytes[i] }
    }
    fun detect(header: ByteArray): Detection {
        fun hit(type: DetectedType, reason: String, level: Confidence = Confidence.HIGH) =
            Detection(type, level, reason)
        if (header.ascii("%PDF-")) return hit(DetectedType.PDF, "%PDF-")
        if (header.has(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)) return hit(DetectedType.PNG, "PNG header")
        if (header.has(0xFF,0xD8,0xFF)) return hit(DetectedType.JPEG, "JPEG marker")
        if (header.ascii("GIF87a") || header.ascii("GIF89a")) return hit(DetectedType.GIF, "GIF header")
        if (header.has(0x50,0x4B,0x03,0x04) || header.has(0x50,0x4B,0x05,0x06))
            return hit(DetectedType.ZIP, "ZIP PK header, container only")
        if (header.has(0x52,0x61,0x72,0x21,0x1A,0x07)) return hit(DetectedType.RAR, "RAR header")
        if (header.has(0x1F,0x8B)) return hit(DetectedType.GZIP, "GZIP header")
        if (header.ascii("SQLite format 3\u0000")) return hit(DetectedType.SQLITE, "SQLite header")
        if (header.has(0x37,0x7F,0x06,0x82) || header.has(0x37,0x7F,0x06,0x83))
            return hit(DetectedType.SQLITE_WAL, "SQLite WAL magic")
        if (header.ascii("RIFF") && header.ascii("WAVE", 8)) return hit(DetectedType.WAV, "RIFF/WAVE")
        if (header.ascii("fLaC")) return hit(DetectedType.FLAC, "FLAC")
        if (header.ascii("OggS")) return hit(DetectedType.OGG, "OggS")
        if (header.ascii("ID3")) return hit(DetectedType.MP3, "ID3")
        if (header.size >= 2 && (header[0].toInt() and 0xff) == 0xff &&
            (header[1].toInt() and 0xe0) == 0xe0 && (header[1].toInt() and 0x06) != 0)
            return hit(DetectedType.MP3, "MPEG audio sync, not fully validated", Confidence.LOW)
        if (header.ascii("ftyp", 4)) return hit(DetectedType.MP4, "ftyp box")
        if (header.has(0x1A,0x45,0xDF,0xA3)) return hit(DetectedType.EBML, "EBML container")
        if (header.has(0x7F,0x45,0x4C,0x46)) return hit(DetectedType.ELF, "ELF")
        if (header.ascii("dex\n") && header.size >= 8 && header[7] == 0.toByte())
            return hit(DetectedType.DEX, "DEX header")
        val preview = header.take(512).toByteArray().toString(Charsets.ISO_8859_1).lowercase()
        if (preview.contains("mime-version:") && preview.contains("multipart/related"))
            return hit(DetectedType.MHTML, "MIME multipart/related", Confidence.MEDIUM)
        return hit(DetectedType.UNKNOWN, "No recognized signature", Confidence.NONE)
    }
}
