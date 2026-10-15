---
id: FS-041
titulo: Executar o scan do worker em thread com pilha fixa (independente do ulimit -s)
status: Disponível
depende-de: [FS-040]
desbloqueia: []
esforco-estimado: S
alocado: TBD
inicio: ~
fim: ~
---

# FS-041 — Executar o scan do worker em thread com pilha fixa (independente do ulimit -s)

## Contexto

O publish do `v0.4.0` (FS-040) reprovou no runner ubuntu do GitHub:
`AttackPastTheGuard_OverflowsTheStack_NotInspected_HostSurvives_WorkerRestarts("dests_cadeia50000")` deu
`NotInspected` **sem derrubar o worker** (`KilledCount=0`, ~1 s). No Windows e no contêiner `sdk:10.0` padrão o
teste passava.

Causa reproduzida em 2026-10-15 no `mcr.microsoft.com/dotnet/sdk:10.0` (`git archive` do `main` em `8c8f5bf`,
filtro `AttackPastTheGuard`): fora do Windows, a pilha onde o worker roda o scan segue o `ulimit -s` do host,
porque o loop do `WorkerHost` é `async` e não fixa a pilha.

| `--ulimit stack` | resultado |
|---|---|
| 8 MB (padrão Docker/WSL) | 5/5 estouram (3 rodadas) |
| 16 MB | `dests_cadeia50000` → `NotInspected` sem kill, em 964 ms (**reproduz o CI**) |
| 64 MB | também `paginas200000` |
| unlimited | 5/5 estouram |

O número de CPUs (`--cpuset-cpus` 1/2/4) e a suíte completa (348/348 com 4 CPUs, 2x) não mudam nada. **Nunca
houve fail-open**: com pilha grande o PdfPig abre e o inspetor limitado devolve `NotInspected`. O problema é o
comportamento depender da configuração do host, o que inclui o App Service Linux de produção.

O `v0.4.0` foi publicado com uma exceção provisória no teste: fora do Windows, `dests_cadeia50000` exige só
`NotInspected`, sem exigir o estouro. Este ticket a remove.

---

## Pré-leitura obrigatória

- `FileScan.Core/Isolation/WorkerHost.cs` — loop do worker (onde o scan roda hoje).
- `FileScan.Tests/Isolation/IsolationAcceptanceTests.cs` — teoria `AttackPastTheGuard_*` e a exceção provisória.
- `FileScan.Tests.Child/Program.cs` — worker falso usado pelos testes (`noguard-`); precisa da mesma pilha fixa.
- `docs/tickets/FS-040-open-isolado.md` — desenho do isolamento.
- `../ProjectStandard/standard/testes-canarios-verificacao.md` §18.10 — verificação endurecida.

---

## Entregáveis

1. `FileScan.Core/Isolation/WorkerHost.cs`: executar cada scan numa thread dedicada com `maxStackSize` fixo (ex.:
   1 MB, igual ao padrão do Windows), sem depender do `ulimit -s` nem do thread pool. Valor como constante
   documentada (avaliar se vira opção).
2. Worker falso de teste (`FileScan.Tests.Child`) com a mesma regra, para os testes exercitarem o caminho real.
3. Remover a exceção provisória de `dests_cadeia50000` em `IsolationAcceptanceTests.cs`; reavaliar a exceção de
   `paginas20000` no Linux, que talvez passe a estourar e possa sair também.
4. `CHANGELOG.md` (0.4.1) e, se for o caso, `SECURITY.md`/READMEs.

---

## Definition of Done (DoD)

- [ ] Código implementado conforme entregáveis.
- [ ] Sem warnings novos no build.
- [ ] Sem alteração quebrando contrato sem ticket de breaking change.
- [ ] Testes `AttackPastTheGuard_*` determinísticos no Windows e no `sdk:10.0` com `--ulimit stack` = 8 MB,
      16 MB, 64 MB e unlimited (sem exceção por SO para `dests_cadeia50000`).
- [ ] Suíte completa verde no Windows, no Linux (contêiner) e no CI do GitHub.
- [ ] Seção `## Resultado da implementação` deste arquivo preenchida.

**Verificação endurecida** (`testes-canarios-verificacao.md` §18.10 — obrigatório; marcar `[x]` sem cumprir presume não-feito):

- [ ] **Lastro:** todo checkbox acima que exige verificação **observável** traz no Resultado a **evidência** do que foi rodado/medido/visto.
- [ ] **Dente:** todo canário/teste estrutural novo tem um auto-teste que prova que ele **acusa** a violação-alvo e **não** dispara em código válido.
- [ ] **Revisão adversarial:** sub-seção `### Revisão adversarial` do Resultado preenchida conforme o gabarito; 2ª linha independente (ou dispensa registrada pelo dono).
- [ ] **Loop até completar:** nenhuma verificação ficou pendente/parcial/presumida.

---

## Notas técnicas

- Com 1 MB fixo, a margem para PDFs legítimos com árvores profundas cai em relação aos 8 MB do Linux. Medir se
  algum PDF real do corpus muda de `Clean` para `NotInspected`.
- O estouro com pilha fixa continua matando só o worker. O pai já trata isso (`KilledCount`, `NotInspected`,
  restart).

---

## Branch e PR

- **Branch:** `fix/FS-041-pilha-fixa-worker`
- **Título do PR:** `FS-041 — pilha fixa no worker`
- **Descrição do PR:** linkar este arquivo + listar commits principais

---

## Ao concluir

1. Preencher `## Resultado da implementação` **+ `### Revisão adversarial`** conforme o gabarito do template.
2. Atualizar frontmatter: `status: Concluído`, `fim: YYYY-MM-DD`, só depois da 2ª linha APROVADO (ou dispensa registrada).
3. Publicar `v0.4.1`.

---

## Resultado da implementação

_Preencher ao concluir._

### Revisão adversarial

_Preencher ao concluir (gabarito em `../ProjectStandard/templates/_template-ticket.md`)._
