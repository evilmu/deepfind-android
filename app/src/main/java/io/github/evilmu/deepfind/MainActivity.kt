package io.github.evilmu.deepfind

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.evilmu.deepfind.signatures.Confidence
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { DeepFindScreen(contentResolver) } }
    }
}

@Composable
private fun DeepFindScreen(resolver: ContentResolver) {
    val scope = rememberCoroutineScope()
    var job by remember { mutableStateOf<Job?>(null) }
    var working by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<ScanResult?>(null) }
    var query by remember { mutableStateOf("") }
    var notice by remember { mutableStateOf<String?>(null) }
    var inspected by remember { mutableStateOf<Artifact?>(null) }
    var hex by remember { mutableStateOf("") }
    val context = androidx.compose.ui.platform.LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            try { resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            catch (_: SecurityException) { }
            job?.cancel()
            report = null
            working = true
            job = scope.launch {
                try {
                    report = withContext(Dispatchers.IO) { scanFolder(context.applicationContext, uri) }
                } catch (e: Exception) {
                    if (e !is kotlinx.coroutines.CancellationException) notice = "Falha: " + e.message
                } finally { working = false }
            }
        }
    }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val r = report
        if (uri != null && r != null) scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val json = JSONObject()
                    json.put("tool", "DeepFind 0.1-alpha")
                    json.put("utc", Instant.now().toString())
                    json.put("visited", r.visited)
                    json.put("truncated", r.truncated)
                    val rows = JSONArray()
                    r.artifacts.forEach { item ->
                        val row = JSONObject()
                        row.put("name", item.name)
                        row.put("relativePath", item.path)
                        row.put("uri", item.uri.toString())
                        row.put("size", item.bytes)
                        row.put("mtime", item.modifiedMillis)
                        row.put("providerMime", item.mime)
                        row.put("signature", item.detection.type.label)
                        row.put("confidence", item.detection.confidence.name)
                        row.put("reason", item.detection.reason)
                        row.put("warning", item.warning)
                        rows.put(row)
                    }
                    json.put("artifacts", rows)
                    resolver.openOutputStream(uri)?.use {
                        it.write(json.toString(2).toByteArray(Charsets.UTF_8))
                    } ?: error("Destino indisponível")
                }
                notice = "Relatório JSON exportado."
            } catch (e: Exception) { notice = "Exportação falhou: " + e.message }
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("DeepFind", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Android Forensic Intelligence • 0.1-alpha", style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(8.dp))
        Text("Varredura somente leitura de pastas autorizadas pelo Android.")
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { picker.launch(null) }, enabled = !working) { Text("Selecionar pasta") }
            if (working) OutlinedButton(onClick = { job?.cancel() }) { Text("Cancelar") }
        }
        if (working) { CircularProgressIndicator(); Text("Analisando...") }
        val r = report
        if (r != null) {
            Text("Arquivos: " + r.artifacts.size + " • Entradas: " + r.visited)
            if (r.truncated) Text("Limite de 10 mil entradas atingido.")
            OutlinedButton(onClick = { exporter.launch("deepfind-report.json") }) { Text("Exportar JSON") }
            OutlinedTextField(query, { query = it }, label = { Text("Filtrar nome, caminho ou tipo") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            val filtered = remember(r, query) {
                r.artifacts.filter { a -> query.isBlank() ||
                    a.name.contains(query, true) || a.path.contains(query, true) ||
                    a.detection.type.label.contains(query, true) }
            }
            LazyColumn(Modifier.weight(1f)) {
                items(filtered, key = { it.uri.toString() }) { item ->
                    Column(Modifier.fillMaxWidth().clickable {
                        inspected = item
                        hex = "Lendo..."
                        scope.launch {
                            hex = withContext(Dispatchers.IO) {
                                try {
                                    resolver.openInputStream(item.uri)?.use { stream ->
                                        val bytes = ByteArray(256)
                                        val count = stream.read(bytes)
                                        if (count <= 0) "Sem bytes disponíveis"
                                        else bytes.take(count).chunked(16).mapIndexed { row, chunk ->
                                            "%04X  ".format(row * 16) +
                                                chunk.joinToString(" ") { "%02X".format(it.toInt() and 255) }
                                        }.joinToString("\n")
                                    } ?: "Não foi possível abrir"
                                } catch (e: Exception) { "Leitura negada: " + e.javaClass.simpleName }
                            }
                        }
                    }.padding(vertical = 10.dp)) {
                        Text(item.name, fontWeight = FontWeight.SemiBold)
                        Text(item.detection.type.label + " • " + item.detection.confidence + " • " + item.bytes + " bytes",
                            style = MaterialTheme.typography.bodySmall)
                        if (item.detection.mismatchedExtension(item.name))
                            Text("Extensão diferente da assinatura", color = MaterialTheme.colorScheme.error)
                        if (item.warning != null) Text(item.warning)
                        Text(item.path, style = MaterialTheme.typography.labelSmall, maxLines = 2)
                    }
                    HorizontalDivider()
                }
            }
        }
    }
    if (notice != null) AlertDialog(
        onDismissRequest = { notice = null }, title = { Text("DeepFind") },
        text = { Text(notice ?: "") },
        confirmButton = { TextButton(onClick = { notice = null }) { Text("OK") } })
    inspected?.let { item ->
        AlertDialog(
            onDismissRequest = { inspected = null },
            title = { Text(item.name) },
            text = {
                androidx.compose.foundation.layout.Column {
                    Text("Caminho: " + item.path, maxLines = 3)
                    Text("Assinatura: " + item.detection.type.label)
                    Text("Confiança: " + item.detection.confidence)
                    Text("Evidência: " + item.detection.reason)
                    Text("Hexadecimal (até 256 bytes):")
                    androidx.compose.foundation.layout.Column(Modifier.height(180.dp)) {
                        Text(hex, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { inspected = null }) { Text("Fechar") } })
    }
}
