package io.github.evilmu.deepfind

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import io.github.evilmu.deepfind.signatures.Detection
import io.github.evilmu.deepfind.signatures.FileSignatureDetector
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

data class Artifact(
    val name: String,
    val path: String,
    val uri: Uri,
    val bytes: Long,
    val modifiedMillis: Long,
    val mime: String?,
    val detection: Detection,
    val warning: String? = null,
)

data class ScanResult(val artifacts: List<Artifact>, val visited: Int, val truncated: Boolean)

suspend fun scanFolder(context: Context, uri: Uri): ScanResult {
    val root = DocumentFile.fromTreeUri(context, uri)
        ?: error("Pasta não disponível no provedor")
    require(root.isDirectory) { "Selecione uma pasta" }
    val pending = ArrayDeque<Triple<DocumentFile,String,Int>>()
    pending.add(Triple(root, root.name ?: "raiz", 0))
    val result = ArrayList<Artifact>()
    val visitedUris = HashSet<String>()
    var examined = 0
    while (pending.isNotEmpty() && examined < 10000) {
        coroutineContext.ensureActive()
        val (node,path,depth) = pending.removeLast()
        if (!visitedUris.add(node.uri.toString())) continue
        examined++
        if (node.isDirectory && depth < 32) {
            try {
                node.listFiles().reversed().forEach { child ->
                    pending.add(Triple(child, path + "/" + (child.name ?: "sem-nome"), depth+1))
                }
            } catch (_: Exception) { /* Provider denied access: skip subtree */ }
        } else if (node.isFile) {
            var warning: String? = null
            val header = try {
                context.contentResolver.openInputStream(node.uri)?.use { stream ->
                    val buffer = ByteArray(1024)
                    val n = stream.read(buffer)
                    if (n <= 0) byteArrayOf() else buffer.copyOf(n)
                } ?: byteArrayOf()
            } catch (e: Exception) {
                warning = "Sem leitura: " + e.javaClass.simpleName
                byteArrayOf()
            }
            result.add(Artifact(
                node.name ?: "sem-nome", path, node.uri, node.length(),
                node.lastModified(), node.type, FileSignatureDetector.detect(header), warning,
            ))
        }
    }
    return ScanResult(result, examined, pending.isNotEmpty())
}
