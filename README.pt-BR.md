[English](README.md) · **Português**

# FileScan

![.NET](https://img.shields.io/badge/.NET-10-512BD4) ![License](https://img.shields.io/badge/license-MIT-blue) ![Tests](https://img.shields.io/badge/tests-145%20passing-brightgreen)

Um pequeno **microsserviço de validação de arquivos**: você entrega um upload e ele devolve um
veredito fail-closed para persistência — pensado para ficar na frente de apps existentes com uma
única chamada HTTP antes do storage. `Clean` é um resultado estrutural/conteúdo ativo limitado,
não um certificado de ausência de malware.

A maioria dos pipelines de upload confia na extensão. Uploads maliciosos — PDFs com JavaScript
auto-executável, documentos Office com DDE/macros, formula injection em CSV, imagens polyglot —
passam pela checagem de extensão, e pelo antivírus por assinatura quando o payload é novo. O
FileScan pega essa classe de ataque na **camada de aplicação**, antes de o arquivo ser gravado. E
preenche uma lacuna real: não existe biblioteca **.NET** gratuita e consagrada para detecção de
injeção multi-formato — as alternativas são CDR comercial ou ferramentas de outras linguagens.

## Destaques

- **Detecção de injeção multi-formato** — JavaScript em PDF, DDE/macros do Office, formula injection
  em CSV (OWASP), imagens polyglot — e **inspeção recursiva de anexos de PDF** (um XML embutido
  benigno passa; um `.exe` embutido é pego).
- **Verificação do tipo real** por conteúdo / magic bytes (Mime-Detective), não só pela extensão.
- **Reutilizável como biblioteca** — o motor de validação é uma class library independente
  (`FileScan.Core`): referencie direto de qualquer app .NET, sem chamada de API e sem ClamAV.
- **Sem container** — a camada de antivírus ClamAV é opcional; desligada, o serviço é .NET puro e
  faz deploy como qualquer app web comum.
- **Validado em documentos reais — zero falso-positivo** — dezenas de arquivos reais (PDFs de
  seguro, documentos Office, imagens) passam limpos após ajuste de falso-positivo.
- **Pensado em segurança** — fail-closed, rate limiting por cliente ligado por padrão, Swagger só em
  Development, auth opcional por API key (constant-time), limites de tamanho/descompressão configuráveis.
- **145 testes automatizados** (xUnit) com entradas geradas em código — `dotnet test`, sem Docker.

> ⚠️ **Aviso / Escopo:** o FileScan faz **detecção heurística** de conteúdo malicioso/injeção.
> **Não é** um produto de CDR certificado, **não substitui** um antivírus completo nem uma solução
> comercial, e é fornecido **sem garantia** (ver [LICENSE](LICENSE)). Use como **camada de defesa em
> profundidade** e valide no seu contexto — payloads ofuscados/criptografados e ameaças zero-day
> podem escapar. Ver [SECURITY.md](SECURITY.md).

## Como funciona

Três camadas de validação, em ordem:

1. **Estrutural** (barata, síncrona): tamanho, **allowlist de extensão** e **tipo real do conteúdo
   via Mime-Detective** (magic bytes) — recusa binário perigoso (um `.exe` disfarçado) e arquivos
   cujo conteúdo não bate com a extensão declarada (ex.: um PNG renomeado para `.pdf`).
2. **Conteúdo ativo** (heurística multi-formato): detecta injeção de script por tipo de arquivo —
   - **PDF**: um parser estrutural Apache-2.0 valida xref/trailer, referências indiretas e object
     streams; JavaScript (`/JavaScript`, `/JS`), `/Launch` e anexos são inspecionados recursivamente
     com orçamento compartilhado de profundidade, entradas e descompressão. Filtro, predictor,
     criptografia ou estrutura ambígua não suportada devolve `NotInspected`.
   - **Office OOXML** (`docx`/`xlsx`): descompacta o ZIP e procura DDE, macros (`vbaProject`),
     formula injection e objetos OLE.
   - **CSV**: formula/command injection conforme **OWASP** (célula iniciando com `=` `@` Tab, ou
     `+`/`-` quando parece fórmula; `cmd|`, `WEBSERVICE`…).
   - **Imagens** (`jpg`/`png`): marcadores `<script>`/`<?php` embutidos (best effort).
   - **Legado/HTML** (`doc`/`xls`): `<script>`, DDE, fórmulas e marcadores de macro.
3. **Antivírus** (opcional): scan via **ClamAV** (motor open-source), usando o cliente `nClam`.

> A camada de conteúdo ativo **detecta e aplica política — não sanitiza** (não é CDR). Payloads
> criptografados/ofuscados podem escapar; cobertura total exige CDR ou sandbox.

> O **ClamAV é opcional** (`FileScan:ClamAv:Enabled`): desligado, o serviço roda só as camadas
> estrutural + conteúdo ativo — **sem container/daemon**.

---

## Uso como biblioteca (`FileScan.Core`)

O motor de validação vive em **`FileScan.Core`**, uma class library pura que usa Mime-Detective e
PdfPig — sem ClamAV, sem ASP.NET, sem daemon. Qualquer projeto .NET pode referenciá-la e
validar uploads in-process, sem chamar uma API:

```csharp
using FileScan.Scanning;

var scanner = new FileScanService(new FileScannerOptions
{
    AllowedExtensions = ["pdf", "docx", "xlsx", "csv", "jpg", "png"],
    // Limites por stream e orçamentos agregados/recursivos são por instância.
});

ScanResponse result = await scanner.ScanAsync(fileName, bytes);
if (result.Verdict != ScanVerdict.Clean)
    // rejeitar o upload (result.Reason diz o porquê)
```

As opções são **capturadas por instância** (sem estado global nem mutável pelo chamador): dois
consumidores no mesmo processo podem usar limites diferentes, e alterar o `FileScannerOptions`
original depois do construtor não muda um scanner existente. Um motor de antivírus pode ser plugado
via a interface opcional `IVirusScanner` — é exatamente assim que a API deste repo pluga o ClamAV.

Para gerar o pacote NuGet localmente: `dotnet pack FileScan.Core -c Release -o artifacts`.

Releases são publicados via tag (`git tag v0.2.0 && git push origin v0.2.0`) no
**[nuget.org](https://www.nuget.org/packages/FileScan.Core)** (via Trusted Publishing / OIDC —
sem chave de longa duração) e no **GitHub Packages**. Antes do hash, os timestamps ZIP do pacote
são normalizados para o timestamp do commit; assim, o retry da mesma tag recria o mesmo artefato,
sem mascarar nem inventar divergência de hash. Em reruns do nuget.org, somente a entrada
`.signature.p7s` acrescentada pelo repositório é excluída da comparação canônica; todos os arquivos
distribuídos continuam cobertos pelo hash. Consumir do nuget.org não exige setup:

O workflow publica o `.snupkg` determinístico explicitamente no servidor de símbolos do nuget.org
e registra seu próprio SHA-256. O GitHub Packages é o espelho do pacote (`.nupkg`), não é tratado
como servidor de símbolos.

```bash
dotnet add package FileScan.Core
```

O GitHub Packages (`https://nuget.pkg.github.com/vhbfcode/index.json`) fica como espelho; ele
exige autenticação mesmo para pacotes públicos (PAT com `read:packages`).

---

## API

### `POST /scan`
- **Request:** `multipart/form-data`, arquivo no campo `file`.
- **Auth:** header `X-Api-Key` (só quando `FileScan:ApiKey` está configurada).
- **Response 200** (veredito definitivo):
  ```json
  {
    "fileName": "contrato.pdf",
    "sizeBytes": 18342,
    "verdict": "Clean",        // Clean | Malicious | Rejected | NotInspected | ActiveContentDetected
    "reason": null,            // preenchido quando não é Clean
    "engine": "clamav",        // "clamav" ou "filescan" (qual camada decidiu)
    "scannedAtUtc": "2026-05-29T13:00:00.0000000Z"
  }
  ```
- **Response 503**: `verdict = "Error"` — não foi possível escanear (ClamAV fora). O chamador
  **deve falhar fechado**. (Só ocorre com `ClamAv:Enabled=true`.)

**Contrato de veredito (fail-closed por construção):** `Clean` significa que a inspeção
estrutural/de conteúdo ativo **terminou integralmente** e nada foi encontrado. Quando parte do
arquivo não pôde ser inspecionada — filtro de stream não suportado, PDF criptografado, estrutura
inválida/truncada, limite de descompressão atingido — o veredito é **`NotInspected`** (nunca
`Clean`): ausência de inspeção não é aceitação, e a ausência de antivírus não muda isso.

`Flag` devolve `ActiveContentDetected` com `warnings`; `Ignore` devolve `NotInspected` porque a
inspeção foi pulada. Nenhuma das duas políticas pode devolver `Clean`. Se o antivírus disser
`Clean` e a camada estrutural estiver incompleta, o resultado continua `NotInspected` com
`engine = "filescan"`.
Anexos PDF são resolvidos por associações normativas de `FileSpec` (`EmbeddedFiles`, `AF` e `FS`
dentro de uma annotation `/Subtype /FileAttachment`) e sua relação `/EF`; `/Type /EmbeddedFile`
não é obrigatório. Chaves de extensão `/EF` ou `/FS` sem esse contexto não são tratadas como
anexo. Valores inválidos na name tree, `/Limits` no nó raiz e alvos associados ausentes, cíclicos
ou que não sejam stream devolvem `NotInspected`. Strings PDF literais e hexadecimais são ordenadas
e comparadas pelos bytes decodificados, inclusive nos `/Limits` dos filhos. Cancelamento é propagado como `OperationCanceledException`,
inclusive entre a materialização do upload e o parsing.

> ⚠️ **Escopo dessa garantia: PDF e OOXML.** Só esses inspetores distinguem "inspecionado por
> inteiro" de "não consegui ler este trecho". Para OLE2 legado (`.doc`/`.xls`), imagens, CSV e
> texto o motor é heurística best-effort de varredura de bytes: `Clean` nesses formatos significa
> "nenhum marcador casou", **não** "parseado por completo" (macro OLE2 ofuscada/comprimida pode
> evadir). Se você aceita uploads OLE2 sem antivírus plugado, trate isso como risco residual —
> ou bloqueie essas extensões via `AllowedExtensions`.

**Regra de ouro do chamador:** só persistir o arquivo se `HTTP 200` **e** `verdict == "Clean"`.

> ⚠️ **`Clean` ≠ "pode renderizar inline".** O FileScan só escaneia, não serve arquivo.
> Ao entregar um upload de usuário ao browser, o app consumidor **deve** servir como
> download (`Content-Disposition: attachment`), desligar o sniffing (`X-Content-Type-Options: nosniff`),
> mandar o `Content-Type` correto e aplicar CSP (`object-src 'none'`) — de preferência a
> partir de uma origem separada/sem cookies. É aí que se neutraliza o stored XSS via PDF
> com JavaScript. Ver [SECURITY.md](SECURITY.md#caller-responsibilities-serving-uploaded-files).

### `GET /health`
Liveness — o processo está de pé.

### `GET /ready`
Readiness — o ClamAV responde ao ping (`200`) ou não (`503`). Sempre `200` quando o ClamAV está
desligado.

A documentação interativa (Swagger UI) fica em `/swagger`.

---

## Configuração (`appsettings.json` → seção `FileScan`)

| Chave | Default | Descrição |
|---|---|---|
| `MaxFileSizeBytes` | `26214400` (25 MB) | Tamanho máximo do arquivo (também define o teto do request, + margem) |
| `MaxDecompressedBytesPerStream` | `16777216` (16 MB) | Cap de bytes descomprimidos por stream/anexo (guarda anti zip-bomb) |
| `MaxTotalDecompressedBytes` | `67108864` (64 MB) | Orçamento agregado compartilhado por PDF, OOXML e anexos recursivos |
| `MaxContainerEntries` | `1024` | Orçamento agregado de objetos/streams/entradas por scan |
| `MaxEmbeddedFiles` / `MaxEmbeddedDepth` | `50` / `3` | Quantidade agregada de anexos e profundidade recursiva de PDF |
| `AllowedExtensions` | `pdf,doc,docx,xls,xlsx,csv,jpg,jpeg,png` | Allowlist de extensões aceitas; vazio = não restringe |
| `ApiKey` | `""` | Exige o header `X-Api-Key` quando preenchida |
| `ClamAv:Enabled` | `true` | Liga a camada de antivírus. `false` = só estrutural + conteúdo ativo (**sem container/daemon**) |
| `ClamAv:Host` / `ClamAv:Port` | `localhost` / `3310` | Endereço do daemon `clamd` (quando habilitado) |
| `ActiveContent:OnDetected` | `Reject` | `Reject`; `Flag` → `ActiveContentDetected` + warnings; `Ignore` → `NotInspected` |
| `RateLimit:Enabled` / `:PermitLimit` / `:WindowSeconds` | `true` / `60` / `60` | Rate limit do `/scan` por cliente (API key, ou IP): N requisições por janela → `429` |

Qualquer chave pode ser sobrescrita por variável de ambiente, ex.: `FileScan__ClamAv__Enabled=false`.

---

## Início rápido

Sem ClamAV (só estrutural + conteúdo ativo — sem Docker):

```bash
FileScan__ClamAv__Enabled=false dotnet run --project FileScan.Api
# depois abra http://localhost:5080/swagger
```

Com a camada de antivírus completa:

```bash
docker run -d --name clamav -p 3310:3310 clamav/clamav   # espere ficar "healthy"
dotnet run --project FileScan.Api
```

---

## Exemplo de integração (lado de quem chama)

```csharp
using var content = new MultipartFormDataContent();
content.Add(new StreamContent(file.OpenReadStream()), "file", file.FileName);

var resp = await httpClient.PostAsync("https://filescan.../scan", content, ct);
if (resp.StatusCode != HttpStatusCode.OK)
    throw new InvalidOperationException("Validação indisponível — upload recusado."); // fail closed

var result = await resp.Content.ReadFromJsonAsync<ScanResponse>(cancellationToken: ct);
if (result!.Verdict != "Clean")
    throw new InvalidOperationException($"Arquivo recusado: {result.Reason}");

// só aqui grava no storage
```

---

## Testes

```bash
dotnet test
```

Suíte automatizada (xUnit): inspeção por formato + testes de ponta-a-ponta no endpoint `/scan`
(com o ClamAV **desligado**, então não precisa de Docker). As entradas de teste são geradas em
código — nenhum arquivo externo. Há também scripts de teste manual em `_testfiles/`
(`run_pdf_batch.py <pasta>`, `make-injections.ps1`).

## Licença

[MIT](LICENSE) © 2026 Vitor Fallavena.

Dependências: **nClam** (Apache-2.0), **PdfPig** (Apache-2.0), **Mime-Detective** (MIT; definições *Default* livres para uso
comercial), **Serilog** (Apache-2.0), **Swashbuckle** (MIT). O **ClamAV** (GPLv2) roda como
processo/contêiner **separado** — não é linkado ao código deste projeto.

## Agradecimentos

Projetado e construído com [Claude Code](https://www.anthropic.com/claude-code) — da análise inicial
à detecção multi-formato, ajuste de falso-positivos em documentos reais, hardening de segurança e testes.
