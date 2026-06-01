[English](README.md) · **Português**

# FileScan

Um pequeno **microsserviço de validação de arquivos**. Recebe um upload e diz se é
**malicioso ou não** — pensado para ser plugado na frente de apps existentes com uma única
chamada HTTP antes de o arquivo ser gravado no storage.

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
   - **PDF**: JavaScript (`/JavaScript`, `/JS`), `/Launch` e **inspeção recursiva de anexos**
     (`/EmbeddedFile` — o anexo é extraído e validado; benigno passa, exe/script/macro embutido é
     pego). Cobre streams FlateDecode.
   - **Office OOXML** (`docx`/`xlsx`): descompacta o ZIP e procura DDE, macros (`vbaProject`),
     formula injection e objetos OLE.
   - **CSV**: formula/command injection conforme **OWASP** (célula iniciando com `=` `@` Tab, ou
     `+`/`-` quando parece fórmula; `cmd|`, `WEBSERVICE`…).
   - **Imagens** (`jpg`/`png`): `<script>`/`<?php` embutido e dados anexados após o fim da imagem
     (polyglot).
   - **Legado/HTML** (`doc`/`xls`): `<script>`, DDE, fórmulas e marcadores de macro.
3. **Antivírus** (opcional): scan via **ClamAV** (motor open-source), usando o cliente `nClam`.

> A camada de conteúdo ativo **detecta e aplica política — não sanitiza** (não é CDR). Payloads
> criptografados/ofuscados podem escapar; cobertura total exige CDR ou sandbox.

> O **ClamAV é opcional** (`FileScan:ClamAv:Enabled`): desligado, o serviço roda só as camadas
> estrutural + conteúdo ativo — **sem container/daemon**.

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
    "verdict": "Clean",        // Clean | Malicious | Rejected
    "reason": null,            // preenchido quando Malicious/Rejected
    "engine": "clamav",        // "clamav" ou "filescan" (qual camada decidiu)
    "scannedAtUtc": "2026-05-29T13:00:00.0000000Z"
  }
  ```
- **Response 503**: `verdict = "Error"` — não foi possível escanear (ClamAV fora). O chamador
  **deve falhar fechado**. (Só ocorre com `ClamAv:Enabled=true`.)

**Regra de ouro do chamador:** só persistir o arquivo se `HTTP 200` **e** `verdict == "Clean"`.

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
| `AllowedExtensions` | `pdf,doc,docx,xls,xlsx,csv,jpg,jpeg,png` | Allowlist de extensões aceitas; vazio = não restringe |
| `ApiKey` | `""` | Exige o header `X-Api-Key` quando preenchida |
| `ClamAv:Enabled` | `true` | Liga a camada de antivírus. `false` = só estrutural + conteúdo ativo (**sem container/daemon**) |
| `ClamAv:Host` / `ClamAv:Port` | `localhost` / `3310` | Endereço do daemon `clamd` (quando habilitado) |
| `ActiveContent:OnDetected` | `Reject` | Conteúdo ativo (PDF/Office/CSV/imagens): `Reject`, `Flag` (passa + `warnings`) ou `Ignore` |

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

Dependências: **nClam** (Apache-2.0), **Mime-Detective** (MIT; definições *Default* livres para uso
comercial), **Serilog** (Apache-2.0), **Swashbuckle** (MIT). O **ClamAV** (GPLv2) roda como
processo/contêiner **separado** — não é linkado ao código deste projeto.
