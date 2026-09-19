# Propuesta de paper (D1) — CCR-Receipts

**Título de trabajo:**
*"When Is It Worth Attesting? Cost-Aware, Receipt-Augmented Capability Routing Against
Competent Malice in A2A Agent Ecosystems"*

Alternativas: *"Trust, but Verify the Runtime: Attestation-Aware Delegation in Multi-Agent
Systems"* · *"Beyond Capability: Cost-Aware Attestation for Secure Delegation in A2A MAS"*.

**Venue objetivo:** AAMAS 2027 (26th Int. Conf. on Autonomous Agents and Multiagent Systems),
Hanoi, Vietnam, 3–7 mayo 2027.
**Deadlines (TENTATIVOS — verificar en el sitio oficial / OpenReview de AAMAS 2027):**
abstract ~2-oct-2026, paper ~9-oct-2026. ⇒ ~12 semanas desde jul-2026.
**Estado:** propuesta. Continúa la línea del paper CCR/A2A (AISec 2026, submission #88).
**Idioma:** borrador en español (patrón `Paper.A2A.vX.md` ES → `.tex` EN sometible).

---

## 1. Tesis en una línea
El eje de **éxito** del routing CCR ya tiene dos evidencias (Card + Canary); el eje de
**riesgo/incidente** no tiene **ninguna** — solo se penaliza. Añadimos una **tercera evidencia
que actúa sobre el riesgo** (attestation de entorno + execution receipts), con una decisión
*value-of-information* de **"¿cuándo conviene atestiguar?"** simétrica a la del canary, y
caracterizamos **cuándo esa evidencia —más fuerte y más cara— vale su costo** frente a un
adversario **competente y bien-firmado** (la Limitación C del paper original).

## 2. Motivación y gap
- El estado del arte 2025–26 **validó** la Limitación C de CCR: *capability ≠ malice* es hoy
  el problema abierto #1 (OWASP Agentic **ASI10 "Rogue Agents"**; Microsoft "Double Agents";
  MAESTRO L3; NIST AI Agent Standards). El canary vive en el eje de **capacidad**; no toca la
  **malicia**.
- Las primitivas existen pero **nadie modela su costo/beneficio en routing**:
  - **AIP / IBCTs** (arXiv:2603.24775, *verificado*): tokens de delegación verificables — el
    "receipt", pero sin decidir cuándo pedirlo.
  - **AgenTEE** (arXiv:2604.18231, *verificado*): ejecución de agentes en TEE con remote
    attestation (~5% overhead) — la "attestation de entorno", sin integración al routing.
- Gap concreto: **una decisión de routing que incorpore attestation/receipts como evidencia
  sobre el eje de incidente, con su propio VoI y su frontera de rentabilidad.**

## 3. Contribuciones
- **C1 — Modelo de evidencia de tres niveles.** Primera formulación de routing de capacidades
  que coloca **evidencia *reducible* sobre el eje de incidente** (attestation/receipt),
  simétrica al canary sobre el eje de éxito; con una **receipt value-of-information** ("cuándo
  atestiguar").
- **C2 — La "attestation frontier" (titular).** Caracterización de la región
  `(valor V, precio de riesgo λ_R, costo de receipt ρ, claim-gap, clase de amenaza)` donde
  `Card+Canary+Receipt` domina a `Card+Canary` — espejo de "when does verifying pay".
- **C3 — Routing bajo attestation heterogénea.** Pools mixtos (agentes atestiguables vs. no):
  política *attest-if-available* y degradación grácil — un problema de coordinación multi-agente
  realista y poco estudiado.
- **C4 — Artefacto de sistemas real + benchmark extendido.** Un **agente A2A atestiguado sobre
  Azure Confidential Computing** que emite *quotes* de remote attestation verificables,
  integrado al router CCR; más el benchmark reproducible existente extendido (eje `ρ` + persona
  `competent_exfiltrator`).

## 4. Modelo formal (extensión compacta del paper)
Utilidad esperada original:
```
U(a_i|t) = V·Pr[S_i=1|e_i] − λ_R·Pr[H_i=1|e_i] − λ_C·Cost(a_i,t)
Pr[S_i=1] = α·Card(c_i,t) + (1−α)·Canary(a_i,t)   (evidencia sobre ÉXITO)
```
**Extensión:** evidencia sobre el **RIESGO**. Sea `Att_i ∈ [0,1]` la fuerza de attestation
(0 = ninguna; →1 = TEE fuerte de un stack auditado sin egress para la clase cubierta) y
`cov ∈ [0,1]` la **cobertura** (fracción de la masa de incidente que la attestation puede
remover *estructuralmente*; `cov<1` porque attestation ≠ information-flow control):
```
Pr[H_i=1 | e_i] = Risk_i · (1 − cov · Att_i)          (ahora REDUCIBLE)
Cost(a_i,t)     += ρ_i   (costo/overhead del receipt/attestation)
```
**Receipt-VoI (simétrico al canary-VoI):**
```
Canary-VoI (eje ÉXITO):   V·u_i        − λ_C·κ_i  > τ
Receipt-VoI (eje RIESGO):  λ_R·ΔPr[H_i] − λ_C·ρ_i  > τ_A
        con  ΔPr[H_i] = Risk_i · cov · E[Att_i]
```
Interpretación: **paga attestation cuando la reducción de riesgo que compras supera su costo.**
Esa **simetría éxito/riesgo es la espina teórica** del paper (y el gancho para AAMAS).

## 5. Modelo de amenaza (sobre A2ASecBench)
- **Foco:** `competent_exfiltrator` — competente, con firma válida, pasa canary y ejecuta bien
  la tarea, pero exfiltra el dato real (la persona que el canary NO atrapa).
- **Adversarios específicos de attestation:** *forger* (falsifica quote), *replay* (reusa quote
  vieja), *honesto-no-atestiguable* (no puede/– no quiere atestiguar), *atestiguado-que-abusa*
  dentro de política.
- **Qué cubre attestation:** stack modificado/malicioso, egress no auditado.
  **Qué NO:** mal uso semántico de un dato legítimamente recibido → eso es D2/IFC.

## 6. Preguntas de investigación
- **RQ1 (cobertura):** vs. el exfiltrador competente y firmado, ¿`CCR-R` reduce incidentes
  frente a `CCR` (card+canary) y `attestation_only`? ¿Cuánto y en qué ataques (A2ASecBench
  Capability Cloaking / ASRF)?
- **RQ2 (¿cuándo atestiguar?):** frontera de attestation sobre `V, λ_R, ρ`. ¿Cuándo la
  reducción de riesgo justifica el costo/overhead?
- **RQ3 (adopción parcial):** ¿cómo degradan calidad/incidente al bajar la fracción de agentes
  atestiguables? ¿Hay fallback grácil?
- **RQ4 (robustez):** ¿resiste forgery/replay y adversarios *canary-aware + attestation-aware*?
  ¿Cambia el resultado de indistinguibilidad del canary al añadir attestation?
- **RQ5 (artefacto real):** ¿se sostienen las conclusiones en un agente atestiguado real sobre
  Azure Confidential Computing? (pilot, honesto en escala).

## 7. Plan experimental (reutiliza `a2a-ccr-lab`)
- **Núcleo determinista:** nuevo eje de escenario `ρ` (análogo a `κ`); personas nuevas
  (`competent_exfiltrator`, `attested_honest`, `attestation_forger`, `unattestable_honest`) en
  `ccrlib/agents.py`; baselines `random`, `attestation_only`, `card_only`, `CCR`
  (card+canary), `CCR-R` (card+canary+receipt) en `ccrlib/policies.py`.
- **Métricas:** success, incident, net-utility, **attestation frontier**, curva de
  adopción-parcial; CIs por *task-clustered bootstrap* (como el paper).
- **Ruta real (validación distribuida):** sumar **Azure Confidential Computing** (VMs
  confidenciales SEV-SNP/TDX o confidential containers) a la infra Bicep existente; un
  verificador de attestation (formato público, p. ej. RATS **EAT**); quote real integrado al
  router. **Fallback honesto:** si el artefacto real se retrasa, degradar a *pilot* (como el
  real-LLM pilot del paper AISec) sin perder el resultado de simulación.

## 8. Alcance y limitaciones honestas (van en el paper)
- **Attestation ≠ IFC.** Prueba *qué código corre*, no que sea semánticamente benigno. `CCR-R`
  **sube la barrera** (raíz de hardware + accountability/deterrencia), pero la respuesta
  *completa* a competent-malice es **D1 + D2 (IFC)** → se enmarca como **programa**, no callejón.
- Supuestos del TEE (root of trust del vendor, side-channels), overhead (~5%), confianza en el
  verificador/CA, y adopción parcial (por eso C3).

## 9. Posicionamiento (related work — VERIFICAR cada cita antes de escribir)
- **Provee primitiva, no decisión:** AIP/IBCTs (2603.24775 ✓), AgenTEE (2604.18231 ✓),
  BlockA2A, AgentDID *(por verificar)*.
- **Provenance/receipts:** LDP "provenance paradox" (2603.08852, *por verificar*); survey
  *From Agent Traces to Trust* (2606.04990, *por verificar*) — receipts firmados = "frontera
  urgente" no resuelta.
- **Complemento (no competidor):** FIDES (2505.23643, Microsoft Research, IFC) → D2.
- **Requerimiento del campo:** OWASP Agentic ASI10; MAESTRO L3; NIST.
- **Taxonomía de amenazas:** A2ASecBench (ICLR 2026), ya usada por el paper base.

> ⚠️ Ambos reportes de estado-del-arte usaron búsqueda web (riesgo de citas alucinadas). AIP y
> AgenTEE ya están verificados; el resto se verifica (arXiv/OpenReview) antes de citarlo.

## 10. Por qué AAMAS (y por qué es *tuyo*)
- **Encaje AAMAS:** es una **mecánica de decisión de delegación bajo incertidumbre en
  multi-agente** (utilidad esperada de 3 niveles + frontera + coordinación bajo adopción
  parcial), no solo un sistema de seguridad → núcleo de AAMAS (tracks de *trust/reputation* y
  *engineering MAS*). La reproducibilidad del lab es una fortaleza para el comité.
- **Diferenciador:** la intersección **identidad/attestation + hardware/TEE + Azure** es rara
  en MAS; el artefacto real (agente atestiguado emitiendo quotes) es algo que un grupo puro de
  ML/teoría no produce.

## 11. Compliance (esta dirección roza tu trabajo interno — atención)
Attestation/identidad **es** tu dominio de Core Auth ⇒ la de mayor sensibilidad de las 6.
Regla: **todo desde fuente pública** (RATS/EAT, DICE, TPM, FIDO, Confidential Computing
Consortium, docs públicas de Azure Confidential Computing, papers públicos). **Cero
conocimiento interno**, sin hablar en nombre de Microsoft, y confirmar pre-aprobación de
*Outside Activities* como en el paper anterior.

## 12. Contexto de programa (line of work)
- **D1 (este):** CCR-Receipts → AAMAS 2027.
- **D5 (hermano rápido):** cerrar el gap de síntesis del canary (AUC 0.78) → venue de menor
  prestigio / workshop (según tu plan). Bajo riesgo, muy *plug-in* al lab.
- **D2 (complemento):** CCR-IFC (information-flow monitoring post-delegación) → cierra lo que
  D1 no cubre; futuro flagship de seguridad.

## 13. Próximos pasos sugeridos
1. Afinar el modelo (§4): fijar la semántica de `cov` y de `Att_i`, y probar la simetría VoI.
2. Verificar related-work (§9) contra arXiv/OpenReview.
3. Prototipar en el lab: eje `ρ` + `competent_exfiltrator` + baseline `CCR-R` (RQ1/RQ2 en
   simulación primero; el artefacto Azure después).
4. Confirmar CFP/page-limit/formato reales de AAMAS 2027 y pre-aprobación de Outside Activities.
