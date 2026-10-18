# DeepFind — Plano completo de implementação

**Repositório:** evilmu/deepfind-android • **Licença:** GPL-3.0-only • **Stack:** Kotlin, Jetpack Compose, Android SAF, motor de assinaturas JVM, futura extensão Rust.

## Objetivo
Plataforma forense Android local-first para descoberta e triagem de arquivos, metadados, artefatos de aplicativos e conteúdo em cache autorizado. Inspirada em princípios do Ghidra (módulos e evidências verificáveis), sem alegar descompilação completa ou acesso irrestrito.

## Princípios inegociáveis
- Somente leitura por padrão; escrita apenas para relatórios no destino escolhido pelo usuário.
- Consentimento explícito, segurança, privilégio mínimo e nenhuma coleta remota silenciosa.
- Evidência diferenciada de hipótese: assinatura, extensão, MIME, timestamp e confiança.
- Nenhuma afirmação de recuperação de apagados ou reconstrução garantida de mídia em streaming.
- Limitar CPU/memória, validar inputs não confiáveis e fazer testes adversariais.

## Fase 0 — Alpha inicial
- [x] Projeto Android em Kotlin + Compose.
- [x] Selecionar pasta com Storage Access Framework (SAF), escanear recursivamente até 10.000 entradas/32 níveis.
- [x] Identificar por cabeçalho: PDF, PNG, JPG, GIF, ZIP, RAR, GZIP, SQLite/WAL, WAV, FLAC, Ogg, MP3, MP4/M4A, EBML, ELF, DEX, MHTML.
- [x] Comparação com extensões, confiança, seleção e inspeção hex (256 bytes).
- [x] Exportação JSON explícita.
- [x] CI compilando APK de debug e executando testes unitários.
- [ ] Validar primeiro workflow e corrigir falhas até build verde.
- [ ] Testar em Android 11/13/15 e publicar release assinado.

**Aceite:** tests green; APK debug instala e varre pasta autorizada sem alterar fontes; relatório exportável.

## Fase 1 — Indexador profundo e buscas
- Interfaces de fontes (SAF, MediaStore, mídia externa, extrações autorizadas, root).
- SQLite/FTS5 local, busca incremental, snapshots comparáveis e filtros por assinatura, nome, hash, origem e intervalo temporal.
- SHA-256 em streaming, duplicados, triagem por extensão vs conteúdo e registros de leitura negada.
- Base de testes de volume 50k arquivos e diretórios adversariais.

## Fase 2 — Root isolado
- Modo root opt-in com Magisk/su e confirmação explícita por ação.
- Acesso local aos dados que o Android/SELinux permitam efetivamente acessar.
- Executor com mínimo privilégio; somente leitura e logs; não contornar controles do sistema inadvertidamente.
- Testes num aparelho de laboratório; revisão de segurança antes da liberação.

## Fase 3 — Parsers forenses
- SQLite/WAL, caches Chromium, LevelDB, XML, protobuf e containeres de mídia.
- Distinguir WebM/EBML, ISO BMFF, MHTML e mídia parcial de arquivo completo.
- Extração estática de metadados APK/DEX/ELF com análise segura de bytes não confiáveis.
- Motor Rust opcional isolado com fuzzing e limites de memória.

## Fase 4 — Casos e cadeia de custódia
- Casos criptografados opcionalmente, hashing SHA-256, timeline de eventos, logs append-only, exportação verificável e redaction.
- Origem e horário observados separados de inferências.
- Não declarar validade jurídica automática de relatórios.

## Fase 5 — Distribuição open source
- GitHub Releases com APK assinado, SHA-256, SBOM, changelog e documentação em PT-BR/EN.
- Revisão F-Droid e reprodução do build, monitoramento de vulnerabilidades e dependências.
- Guia de contribuição e política de divulgação responsável.

## Riscos
- Android 11+ não autoriza SAF a ler /data/data/cache de outros apps.
- Streams podem não ser gravados como arquivos completos.
- Root não ignora SELinux nem garante recuperação de arquivos apagados.
- Evidências podem incluir dados pessoais: exibir/compartilhar só com consentimento.

## Critérios transversais
CI verde; testes JVM/instrumentados; benchmark de memória; trilha de logs opcional sem segredos; entradas maliciosas tratadas sem execução; documentação de comportamento por versão Android.
