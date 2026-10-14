---
id: FS-040
titulo: Isolar o PdfDocument.Open do PdfPig em processo worker (FileScan.Core 0.4.0)
status: Concluído (2ª linha APROVADO r2) — aguardando publicação pelo dono
plano: PLANO-026 do Fenix (decisão D4), ticket de adoção T-343 do Fenix
branch: feature/open-isolado (da main c98e989)
---

# FS-040 — `PdfDocument.Open` isolado em processo worker

## Contexto

O PdfPig 0.1.16 recursa sem limite dentro do `PdfDocument.Open`; um estouro de pilha não é capturável e derruba o
hospedeiro. A guarda pré-Open da 0.3.0 é melhor esforço (seis rodadas de revisão acharam contornos). A defesa
robusta é rodar o `Open` em um processo filho: crash/timeout/lixo do filho ⇒ `NotInspected`, nunca `Clean`.

## Definition of Done

- [x] Projeto `FileScan.Worker` (exe .NET 10) roda o estágio de conteúdo da `FileScanService` (guarda pré-Open
  primeiro); protocolo stdin/stdout, uma mensagem por scan; o stdout só carrega o protocolo.
- [x] `IsolatedFileScanService` com pool de workers quentes; crash/OOM/timeout (20 s)/JSON inválido/fluxo truncado/
  resposta incoerente ⇒ mata a árvore do worker, reinicia, `NotInspected`; reciclagem a cada N scans; cancelamento
  propagado; concorrência segura.
- [x] Limites do SO: Windows = Job Object (`KILL_ON_JOB_CLOSE`, 1 processo, teto de memória); qualquer SO = teto do
  heap do GC + vigia do PID pai; falha ao aplicar limite ⇒ `NotInspected`. Best-effort documentado.
- [x] `FileScannerOptions.Isolation = InProcess | Worker` (padrão `Worker`); worker ausente/impossível ⇒
  `NotInspected` + erro logável (`OnIsolationEvent`), sem fallback para `InProcess`.
- [x] Worker no nupkg (`tools/filescan-worker` + `build/FileScan.Core.targets`), localizado relativo ao assembly,
  funcional após `dotnet publish`; `eng/package-smoke` estendido; `dotnet pack` para pasta fora do repo.
- [x] Testes de aceitação (corpus da 0.3.0, ataque que passa pela guarda, timeout, JSON inválido, worker morto
  entre scans, paridade) + sabotagens com dente, revertidas.
- [x] `<Version>0.4.0</Version>`; CHANGELOG, README (en/pt-BR), SECURITY honestos; `PROJECT_NOTES.local.md`.
- [x] Suíte completa verde no Windows **e no Linux** (`mcr.microsoft.com/dotnet/sdk:10.0`).
- [x] Revisão adversarial com 2ª linha APROVADA (rodada 2, 2026-10-14; suíte 348/348 Windows e Linux).

## Resultado da implementação

Commits em `feature/open-isolado`: `9db0075` (feat), `fa5a8c8` (docs), `45d6cfe` (fix pack/handshake), mais os
commits da VOLTA r1 (ver `git log`). Arquivos: `FileScan.Core/Isolation/*`, `FileScan.Worker/*`,
`FileScan.Core/{FileScanService,FileScannerOptions,PdfStructuralInspector,FileScan.Core.csproj}`,
`FileScan.Core/build/FileScan.Core.targets`, `FileScan.Api/*` (opções e log), `eng/package-smoke/*`,
`eng/Run-PackageSmoke.ps1`, `FileScan.Tests/Isolation/*`, `FileScan.Tests.Child/Program.cs`, documentação.

Decisões: o worker compila os fontes do Core (evita ciclo de build); só o estágio de conteúdo cruza o processo (AV e
validação estrutural ficam no hospedeiro); o `Reason` ao cliente nunca carrega caminhos do servidor (detalhe só em
`OnIsolationEvent`). Assunção: o hospedeiro tem o runtime .NET 10 e o host `dotnet` (worker framework-dependent).

### Lastro (por item)

| Item | Lastro |
|---|---|
| Suíte Windows | `dotnet test FileScan.slnx -c Release` = 348/348 (VOLTA r1, 1 execução completa) |
| Suíte Linux | contêiner `mcr.microsoft.com/dotnet/sdk:10.0` sobre `git archive HEAD`: 348/348 (execução final); 1ª execução da VOLTA r1 também 348/348 |
| Ataques que passam pela guarda | 5 casos estouram a pilha de verdade no worker (Windows 0xC00000FD; no Linux KilledCount==1 confirmado pelo teste); `KilledCount == 1` afirmado antes do veredito; `paginas20000` só no Windows (no Linux dá Clean) |
| Invariantes do outcome | 6 testes (um por regra, incl. as ligadas à política Reject/Flag/Ignore) |
| Job Object | limites lidos de volta via `QueryInformationJobObject` (KILL_ON_JOB_CLOSE, 1 processo, teto, DIE_ON_UNHANDLED_EXCEPTION); host-death com e sem vigia |
| Smoke de pacote | `eng/Run-PackageSmoke.ps1` exit 0 (build e publish do consumidor), 1 execução |
| Canário de deriva | `WorkerProjectDriftTests` (3) compara os `.csproj` do Core e do Worker |

Não executado — requer macOS: nenhum teste em macOS. Os 5 casos "somente Windows" (Job Object, `paginas20000`,
`--host-nowatchdog`) retornam cedo no Linux (passam vazios, por desenho, documentados no teste).

### Revisão adversarial

- **Revisor:** releitura crítica do próprio diff — postura: **há um defeito; procurei-o**; nenhuma conclusão herdada.
  **2ª linha:** rodada 1 (revisor-2a-linha) deu **VOLTA** (4 itens bloqueantes/maiores + 6 menores); tratada nesta
  VOLTA; rodada 2 pendente.
- **Escopos auditados:** `ContentOutcome.ValidationProblem` e o uso no pool; ciclo de vida `keep/retire/descarte`;
  `WorkerProcess.StartAsync` (limites, handshake); Job Object; empacotamento (nupkg, publish, targets); `Reason` ao
  cliente; sanitização do log; paridade InProcess × Worker; Linux (contêiner).
- **Tentativas de refutação:** (1) rodar a suíte no Linux — quebrou `paginas20000` (Clean) → corrigido, re-rodado
  verde; (2) remover cada uma das 6 regras de `ValidationProblem` — cada remoção derrubou exatamente o teste da sua
  regra; (3) remover `KILL_ON_JOB_CLOSE` com vigia desligado — derrubou `WorkerDoesNotSurviveItsHost` e o teste dos
  limites; com os dois removidos, também `--host`; (4) remover o vigia no Linux — `--host` falhou (órfão vivo por 31 s);
  (5) sabotagens da 1ª entrega (sem reinício, crash→Clean, sem timeout, sem validação) — todas derrubaram testes;
  (6) um `Reason` com caminho do servidor — agora coberto por teste que procura o caminho no `Reason` e no evento.
  Resistiu: worker morto entre scans, cancelamento, 24 scans concorrentes.
- **Achados:** 1) `paginas20000` Clean no Linux → profundidade/OS tratados; 2) duas regras do outcome sem teste (+
  a de terminal sem motivo) → 6 prefixos novos + invariantes por política; 3) `WorkerDoesNotSurviveItsHost` sem dente
  no Windows → limites provados via `QueryInformationJobObject` e modo sem vigia; 4) sem registro de ticket → este
  arquivo; 5) `IsKilled` → worker morto nunca volta ao pool (**sem teste comportamental**: a corrida não é
  reproduzível de forma determinística; só a propriedade é testada); 6) texto de CHANGELOG/SECURITY → alinhado;
  7) `Reason` vazando caminhos → categoria curta no `Reason`; 8) `Sanitize` → cobre U+2028/2029/Format; 9) checagem de
  PID do handshake restaurada (shim ⇒ falha fechada; **sem teste**: não há como forjar o PID do hello sem
  um host shim real); 10) canário de deriva entre os dois `.csproj`.
- **Lastro dos checkboxes observáveis:** ver a tabela de Lastro acima.
- **Veredito final da 2ª linha:** APROVADO — rodada 2 (revisor-2a-linha, Opus 5.5, 2026-10-14)

**Resíduos MENORES da r2 (registrados; não bloqueiam):**
- **N1.** O teste do `Reason` é tautológico na falha de partida: com `{ex.Message}` restaurado em `WorkerPool.cs:85`, continua verde. A melhoria é exercitar `WorkerLaunch` com um `HostPath` inexistente num diretório "segredo" e afirmar sobre o `Failure`.
- **N2.** `KilledWorker_NeverGoesBackToTheIdlePool` só testa a propriedade `IsKilled`, não o comportamento, que hoje é coberto pelo `HasExited` de `TakeIdleLive`. Renomear o teste.
- **N3.** O `WorkerProjectDriftTests` compara o `Include` literal: um `EmbeddedResource` replicado corretamente no Worker (caminho relativo diferente) fica vermelho, um falso positivo. A correção é normalizar os caminhos completos. "Não há como forjar o PID" exagera: um modo shim no `Tests.Child` testaria a checagem.
- **N4.** Corrigido no fechamento: os READMEs (en/pt-BR) agora distinguem o erro de configuração (worker ou host ausente) de "o worker não pôde ser iniciado".
