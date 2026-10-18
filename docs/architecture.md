# Arquitetura

**Alpha 0.1:** a UI usa Storage Access Framework e documentos `content://`; ScanEngine varre em IO de modo recursivo, somente leitura (10k entradas, 32 níveis); detector JVM classifica 1024 bytes iniciais; view hex oferece 256 bytes; resultado é exportado pelo usuário para JSON. Não exige rede nem root.

**Próximos módulos:** ArtifactSource (SAF/MediaStore/root), ArtifactAnalyzer (mídia/SQLite/Chromium/DEX), EvidenceStore (hash/casos), FTS5 e sandbox Rust. Um URI não representa necessariamente caminho real de armazenamento. Não prometemos arquivos privados no modo SAF.
