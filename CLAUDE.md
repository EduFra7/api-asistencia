# CLAUDE.md — Proyecto LEO (Control de Asistencia)

Guía maestra para Claude Code al trabajar en este repositorio.

---

## 🎯 Qué es este proyecto

**Proyecto LEO** (nombre comercial provisional: "Control de Asistencia") es un **SaaS multi-tenant de control de asistencia biométrica** para empresas en Bolivia.

Captura marcajes desde relojes ZKTeco (protocolo ADMS), procesa turnos / permisos / feriados, y entrega reportes y dashboards. Cada empresa cliente es un tenant aislado por esquema de Postgres.

**Modelo de negocio:** suscripción mensual/anual con 3 paquetes base diferenciados por cantidad de empleados, con meses de regalo en promociones. Detalles de planes y límites se irán definiendo en código.

**Estado actual:** pre-lanzamiento. Prioridad inmediata = **mejorar UI/UX** para no verse genérico. Bugs y rendimiento van segundo. Refactor mayor (ej: dividir `main.py`) NO es prioridad — solo cuando se pida explícitamente.

---

## 🤖 Cómo se comporta Claude en este repo

- **Responde siempre en español.**
- Usa **"usted"** en todo texto al usuario (UI, mensajes, emails). Es un SaaS empresarial.
- **`main.py` tiene ~5,000 líneas. Edítalo quirúrgicamente — nunca lo reescribas completo.** Antes de modificar una sección, lee primero esa sección y las funciones que toca.
- **Pregunta antes de:**
  - Agregar dependencias nuevas a `requirements.txt`.
  - Agregar CDNs nuevos en HTML.
  - Tocar áreas marcadas como "🚫 NO TOCAR" abajo.
  - Cambios que afecten la API pública (firmas de endpoints).
- Cuando termines un cambio, indica qué archivos modificaste y qué hay que verificar manualmente en el navegador.
- **No inventes** tests, linter, build ni convenciones — usa solo las documentadas aquí.
- **Si detectas que una regla de este archivo ya no aplica al código real**, avísalo al usuario en lugar de actualizarlo solo.

---

## 🎨 Filosofía de diseño y UX (prioridad #1)

**Objetivo:** UI **minimalista, ordenada, agradable, con identidad propia**. Que NO se vea genérica de IA.

### Lo que hay que evitar (look genérico de SaaS / IA)
- Degradados morados o azules genéricos.
- Inter como única tipografía, sin pareja.
- Grid de tarjetas idénticas con sombras default.
- Iconos de Lucide/Heroicons sin curaduría.
- Botones primarios azul `#3B82F6` (azul Tailwind default — visto un millón de veces).

### Recomendaciones de identidad visual

**Paleta sugerida** (warm professional, distintiva):
- **Primario:** verde profundo `#0F766E` (teal-700) o `#14532D` (green-900) — asociado a check / puntualidad / trust.
- **Acento:** ámbar cálido `#D97706` (amber-600) para highlights y CTAs secundarios.
- **Surface (fondos):** off-white `#FAFAF9` (stone-50), no blanco puro.
- **Texto:** charcoal `#1C1917` (stone-900), no negro puro.
- **Estados:** rojo `#B91C1C` (red-700) solo para errores; amarillo `#CA8A04` (yellow-600) para warnings.

**Tipografía sugerida** (par distintivo, ambas en Google Fonts):
- **Display / Headings:** "Bricolage Grotesque" o "Manrope" (carácter, no genérica).
- **Body:** "Inter" o "Geist" (workhorse confiable).
- Combinar peso 700+ en headings con 400-500 en body para contraste fuerte.

**Principios de layout:**
- Mobile-first siempre. Probar en viewport ~375px ANTES que desktop.
- Espaciado generoso (Tailwind `p-6` mínimo en contenedores).
- Bordes sutiles `border-stone-200`, no sombras pesadas.
- Microinteracciones con propósito (transiciones 150-200ms en hovers).
- Tablas con zebra striping suave, no grid pesado.

**Audiencia:** mixta — administradores con manejo técnico hasta usuarios con poca exposición a software. La UI debe ser autoexplicativa.

---

## 🏗️ Arquitectura: backend inteligente, frontend tonto

Principio rector:

- **Toda la lógica de negocio vive en el backend.** El frontend solo renderiza datos y envía requests.
- El frontend NO toma decisiones sobre permisos, asistencia, cálculos, ni reglas de negocio.
- Los candados de módulos en el frontend son **solo UX** — la verdad oficial está en `requiere_modulo` del backend.
- Si una vista necesita lógica nueva → primero exponer endpoint, después consumir. **Nunca duplicar reglas en JS.**

---

## 🛠️ Stack y workflow de desarrollo

### Stack
- **Backend:** FastAPI mono-archivo en [main.py](main.py).
- **Frontend:** HTML estático + [menu.js](menu.js), JS vanilla, Tailwind por CDN, SweetAlert2 por CDN.
- **BD:** PostgreSQL en **Supabase** (BD administrada).
- **Deploy backend:** **Render.com** ([Procfile](Procfile)).
- **Posible migración futura:** VPS propio (sin decisión final).

### Workflow de trabajo
```
VS Code (edición) → git commit/push → GitHub → Render.com (auto-deploy) → Supabase (BD)
```

- Edito en VS Code con Claude Code activo.
- Hago commits y push a GitHub manualmente o con la skill `commit-commands` (`/commit-push-pr`).
- Render detecta el push y redespliega automáticamente.
- La conexión a Supabase ya está configurada vía `DATABASE_URL`.

### Comandos
- Instalar: `pip install -r requirements.txt`
- Dev local: `python -m uvicorn main:app --reload`
- Prod (Render lo corre): `python -m uvicorn main:app --host 0.0.0.0 --port $PORT`
- Env vars: `DATABASE_URL`, `SECRET_KEY` (cargadas desde `.env` con `python-dotenv`).
- Bootstrap inicial: `GET /setup/superadmin` siembra cuenta raíz (`admin@sistema.com` / `admin123`). **Cambiar password en cada despliegue real.** Ver [main.py:636](main.py#L636).
- Frontend: cada HTML tiene `API_URL` hardcodeado (actualmente `https://api-asistencia-sa13.onrender.com`).

### Reglas de aislamiento de plataforma
- Mantener todo lo específico de Supabase/Render aislado en variables de entorno.
- **No introducir dependencias específicas de Supabase** (ej: `supabase-py`) — usar SQL plano vía psycopg2.
- Eso mantiene la migración a VPS limpia cuando se decida.

---

## 📦 Skills recomendadas (instalar al inicio)

> **Cómo funciona `/plugin`:** primero se agrega un marketplace
> (`/plugin marketplace add <usuario>/<repo>`) y luego se instala el
> plugin (`/plugin install <plugin>@<marketplace>`).
> El marketplace `claude-plugins-official` viene auto-cargado en Claude Code.

### A. Plugins oficiales de Anthropic (marketplace auto-cargado)
```bash
/plugin install commit-commands@claude-plugins-official
/plugin install frontend-design@claude-plugins-official
/plugin install code-review@claude-plugins-official
/plugin install code-simplifier@claude-plugins-official
```

### B. Marketplace comunitario alirezarezvani (vía /plugin)
```bash
/plugin marketplace add alirezarezvani/claude-skills
/plugin install engineering-skills@claude-code-skills
/plugin install engineering-advanced-skills@claude-code-skills
/plugin install pw@claude-code-skills              # Playwright (antes "playwright-pro")
/plugin install a11y-audit@claude-code-skills      # Accesibilidad WCAG 2.2
```

### C. Marketplace de superpowers (obra)
```bash
/plugin marketplace add obra/superpowers-marketplace
/plugin install superpowers@superpowers-marketplace
```
Trae TDD, debugging disciplinado, `/brainstorm`, `/write-plan`, `/execute-plan`.

### D. Skills de seguridad (marketplaces y repos individuales)

**IMPORTANTE:** El ecosistema de skills tiene riesgos de supply chain (CVE-2025-59536, CVE-2026-21852). Solo instalar de fuentes confiables: Anthropic, Trail of Bits, mantenedores conocidos. Revisar el `SKILL.md` de cada una antes de usarla.

```bash
# Trail of Bits — análisis estático, CodeQL, insecure-defaults, sharp-edges
/plugin marketplace add trailofbits/skills
/plugin install code-audit@trailofbits-skills

# OWASP Top 10:2025 + ASVS 5.0 (clonar repo manualmente al proyecto)
git clone https://github.com/agamm/claude-code-owasp .claude/skills/owasp-security

# Security Audit OWASP/NIST CSF 2.0 (slash command standalone)
git clone https://github.com/afiqiqmal/claude-security-audit .claude/skills/security-audit
```

### E. Resumen por propósito

| Skill / Plugin | Para qué | Scope sugerido |
|---|---|---|
| `commit-commands` | Commits + PRs (`/commit`, `/commit-push-pr`) | User |
| `frontend-design` | UI distintiva (PRIORIDAD) | User |
| `code-review` | Revisión de PRs y cambios | User |
| `code-simplifier` | Refactor minimalista | User |
| `engineering-skills` | Patrones FastAPI, Pydantic, async | User |
| `engineering-advanced-skills` | Refactor, performance, arquitectura | User |
| `pw` | Testing browser con Playwright | Project |
| `a11y-audit` | Auditoría WCAG 2.2 | Project |
| `superpowers` (obra) | TDD, `/brainstorm`, `/write-plan`, `/execute-plan` | User |
| `code-audit` (Trail of Bits) | CodeQL, análisis estático profundo | Project |
| `owasp-security` (agamm) | OWASP Top 10:2025 checklists | Project |
| `claude-security-audit` (afiqiqmal) | `/security-audit` con OWASP + NIST CSF | Project |

### F. Bundled (ya incluidas, sin instalar)
- `/simplify` — refactor tras completar tarea.
- `/batch` — cambios paralelos en múltiples archivos.
- `/init` — regenera CLAUDE.md base.
- `/clear` — limpia contexto entre tareas.
- `/compact` — comprime conversación cuando se llena.

### G. Comandos personalizados activados al instalar las skills
- `/commit` — commit con mensaje generado por IA (de commit-commands).
- `/commit-push-pr` — commit + push + crear PR (de commit-commands).
- `/security-audit` — auditoría OWASP Top 10:2025 + NIST CSF 2.0 (de afiqiqmal).
- `/brainstorm`, `/write-plan`, `/execute-plan` — workflow disciplinado (de superpowers).

### H. Cómo elegir scope al instalar
- **User scope** (`~/.claude/skills/`): skills generales para TODOS tus proyectos.
- **Project scope** (`.claude/skills/`): skills específicas de ESTE proyecto, commiteables en git.

---

## ⚡ Comandos de optimización de créditos

Estos comandos reducen significativamente el consumo de tokens. **Úsalos siempre.**

### Slash commands esenciales

| Comando | Cuándo usarlo |
|---|---|
| `/clear` | **Al iniciar cada nueva tarea no relacionada.** Comando #1 para ahorrar. |
| `/compact` | Cuando el contexto pasa el 70% (visible en statusline). |
| `/context` | Ver cuánto contexto estás usando. |
| `/cost` | Ver cuánto llevas gastado en la sesión. |
| `/status` | Estado general (modelo, contexto, costo) en una línea. |
| `/model` | Cambiar de modelo. Ej: `/model sonnet` para tareas simples, `/model opus` para problemas complejos. |
| `/memory` | Editar memoria persistente del proyecto. |
| `/init` | Regenerar `CLAUDE.md` desde cero. |
| `/skills` | Ver skills instaladas. |
| `/plugin` | Gestionar plugins. |
| `/reload-plugins` | Recargar plugins sin reiniciar. |

### Niveles de pensamiento (thinking budget)

Mayor profundidad = más tokens. **Usar el mínimo necesario.**

| Keyword | Tokens de pensamiento |
|---|---|
| `think` | ~4,000 (default ligero) |
| `think hard` / `think more` | ~10,000 (medio) |
| `think harder` / `megathink` | ~10,000+ |
| `ultrathink` | ~31,999 (máximo, solo problemas arquitectónicos críticos) |

**Combo para problemas complejos:** Plan Mode (Shift+Tab × 2) + `ultrathink` + modelo Opus.

### Prefijos de comando
- `!comando` — ejecuta bash directamente sin consumir tokens del modelo (ej: `!git status`).
- `#texto` — guarda a memoria persistente.
- `@archivo` — agrega archivo específico al contexto.

### Buenas prácticas de sesión

1. **Una tarea = una sesión.** Al cambiar de tarea: `/clear`.
2. **Sé específico al pedir.** "Lee `main.py:2879` y refactoriza `calcular_dia_asistencia`" gasta 10x menos que "ayúdame con el motor de asistencia".
3. **Usa `@` para incluir archivos**, no copy-paste de código completo.
4. **Para cambios masivos**, usa `/batch` (paraleliza).
5. **Modelo según complejidad:** Sonnet para 80% de tareas, Opus solo para arquitectura/debugging duro.
6. **Crea `.claudeignore`** en la raíz para excluir archivos pesados:
   ```
   __pycache__/
   *.pyc
   .git/
   node_modules/
   .env
   *.log
   .venv/
   ```

---

## 📊 Volúmenes y escala esperada

- **Empresas (tenants):** 10+ esperadas en operación inicial.
- **Empleados por empresa típica:** 20-100, con outliers posibles.
- **Marcajes por empleado por día:** estándar = 4 (entrada/salida almuerzo + entrada/salida jornada).
- **Picos de tráfico ADMS:** concentración alta en horarios de entrada (7:30-9:00) y salida (17:00-19:00).
- **Reportes pesados:** los reportes mensuales por sucursal son la query más costosa — priorizar índices ahí.

**Implicaciones:**
- Toda lista que pueda crecer (`/empleados`, `/asistencia/...`) debe **paginar**.
- Queries que cruzan `eventos_brutos` con `asistencia_diaria` deben tener índices por `(empleado_id, fecha)`.
- En picos ADMS evitar lock contention — los inserts a `eventos_brutos` deben ser rápidos y el cálculo va a `BackgroundTasks`.

---

## 🌐 Idioma, tono y compatibilidad

### Idioma y tono
- **Idioma único:** español (Bolivia).
- **Tratamiento:** **"usted"** formal en toda la UI, mensajes, errores, confirmaciones, emails.
- **Tono:** profesional pero claro, sin jerga técnica.
  - ✅ "No se pudo guardar el registro. Intente nuevamente."
  - ❌ "Error 500: internal server error"
- **Términos consistentes:**
  - "empleado" (no "trabajador" ni "colaborador")
  - "marcaje" (no "fichaje")
  - "turno" (no "horario")
  - "permiso" para ausencias justificadas; "falta" para no justificadas
- **Comentarios en código:** español, para mantener coherencia.

### Navegadores soportados
- Chrome / Edge (Chromium): 110+
- Firefox: 110+
- Safari (macOS / iOS): 16+
- **NO soportar:** IE, navegadores legacy.
- **Mobile-first obligatorio.**

### Manejo de errores y feedback visible
- **Errores que requieren acción** → `mostrarError(mensaje)` (modal SweetAlert2 bloqueante).
- **Confirmaciones de éxito** → `mostrarExito(mensaje)`.
- **Acciones destructivas** → `pedirConfirmacion(...)` SIEMPRE antes de eliminar/suspender.
- **Errores de red transitorios** → toast no bloqueante (esquina inferior). NO usar SweetAlert.
- **HTTP 401** → ya manejado en `menu.js` (auto-redirect a login). No re-implementar.
- **Loaders** → spinner en cualquier acción >300ms.
- **Regla de oro:** ningún error muere en silencio. Si el backend devuelve error, el usuario lo ve.
- **Backend:** las HTTPException devuelven `{"detail": "mensaje en español listo para mostrar"}`.

---

## ⚠️ Reglas críticas (invariantes del sistema)

Romper cualquiera de estas rompe el sistema:

1. **Schema names nunca crudos.** Las queries usan f-strings tipo `f"SELECT ... FROM {schema}.empleados"` porque psycopg2 no parametriza nombres de esquema. Schemas se sanean al crear la empresa ([main.py:273](main.py#L273)). **Nunca aceptar schema name desde el body.**
2. **Toda mutación de un día de asistencia** debe disparar `procesar_asistencia_dia` (directo o vía `BackgroundTasks`).
3. **Días con `modificado_manualmente = TRUE`** no se sobrescriben al recalcular. No remover ese WHERE del upsert.
4. **Textos a pantalla ZKTeco:** ASCII, mayúsculas, ≤24 chars. Usar `limpiar_texto_zk` ([main.py:763](main.py#L763)).
5. **Parsear payloads ADMS con `split('=', 1)`.** Un split ingenuo corrompe el padding Base64 de las huellas.
6. **Toda acción privilegiada o que toque dinero** llama a `registrar_auditoria` ([main.py:89](main.py#L89)).
7. **Nuevas tablas por tenant:** agregarlas al DDL en `POST /empresas` Y escribir migración para tenants existentes.
8. **API en producción:** **nunca cambiar firma de endpoint existente.** Agregar campos opcionales sí; renombrar/eliminar requiere coordinación con frontend deployed.

---

## 🚫 NO TOCAR sin permiso explícito

Estas áreas funcionan. **Pedir confirmación antes de modificar:**

- **Migraciones y esquemas de BD** (`POST /empresas` DDL, estructura de tablas existentes).
- **Motor de asistencia:** `calcular_dia_asistencia` ([main.py:2879](main.py#L2879)) y `procesar_asistencia_dia` ([main.py:666](main.py#L666)).
- **Endpoints ADMS / hardware ZKTeco:** todo bajo `/iclock/*`.
- **Auth y JWT:** `verificar_token` ([main.py:104](main.py#L104)), `requiere_modulo` ([main.py:127](main.py#L127)), `/auth/login`.

Si una mejora de UI/UX requiere tocar lo anterior → **proponer primero, ejecutar después.**

---

## 🏢 Modelo multi-tenant por esquemas

Concepto clave: cada cliente ("empresa") tiene su esquema `empresa_<slug>`. Tablas SaaS globales en `public`:
- `empresas`, `usuarios`, `dispositivos`, `comandos_adms`, `huellas_adms`, `saas_auditoria`.

Todo acceso a BD pasa por `conectar_bd(schema_name)` ([main.py:75](main.py#L75)) que ajusta `search_path`. Pasar `"public"` para tablas globales o el `schema_name` del JWT para datos del tenant.

DDL canónico por tenant en `POST /empresas` ([main.py:238](main.py#L238)): `feriados`, `sucursales`, `secciones`, `turnos`, `empleados`, `eventos_brutos`, `asistencia_diaria`, `asistencia`, `ausencias`.

---

## 🔐 Auth y feature flags

- `verificar_token` decodifica `Authorization: Bearer <jwt>`. JWT lleva `id`, `email`, `rol`, `empresa_id`, `schema_name`, `empresa_nombre`, dict `modulos`. Expira en 8h.
- `requiere_modulo("nombre")` — fábrica de dependencias. 403 si `modulos[name] is False`. Superadmin (`rol == "superadmin"`) ignora chequeos.
- **Cambios de feature flags requieren re-login** porque `modulos` se incrusta en el JWT.
- Frontend espeja candados ([menu.js:184](menu.js#L184), [menu.js:249](menu.js#L249)) — solo UX.
- Suspendidos se bloquean en login con `estado_suscripcion == 'suspendido'`, no por módulos.

---

## 🧮 Motor de asistencia (cómo funciona, no tocar)

Una sola función decide cómo se ve un día laboral: **`procesar_asistencia_dia(schema, empleado_id, fecha)`** ([main.py:666](main.py#L666)).

Trae turno + marcajes brutos + ausencias aprobadas → llama `calcular_dia_asistencia` (matemática pura) → upsert en `asistencia_diaria`.

`calcular_dia_asistencia` ([main.py:2879](main.py#L2879)) clasifica: `Puntual` / `Tarde` / `Falta` / `Permiso` / `Descanso` / `Trabajando` / `Pendiente` / `Incompleto`. Calcula `deuda_generada_bs` si turno tiene `descuento=true`.

---

## 🔌 Hardware ZKTeco ADMS (cómo funciona, no tocar)

Endpoints bajo `/iclock/*`:
- `GET /iclock/cdata` — handshake, marca dispositivo `online`.
- `POST /iclock/cdata` ([main.py:914](main.py#L914)) — datos. Enruta por SN → `dispositivos.schema_name` → despacha por `table=`: `ATTLOG`, `FINGERTMP`/`OPERLOG`.
- `GET /iclock/getrequest` ([main.py:813](main.py#L813)) — heartbeat + cola comandos.
- `POST /iclock/devicecmd` — ack del reloj.

---

## 🗺️ Hoja de ruta del producto (3 fases)

**Siempre desarrollar pensando en estas tres**, aunque solo se trabaje en la actual.

### Fase 1 (ACTUAL): Versión navegador
- Frontend HTML servido como estático, backend FastAPI en Render.
- Pre-lanzamiento → enfoque en UI y estabilidad.

### Fase 2: Aplicación de escritorio (.exe Windows)
"Navegador disfrazado" — empaquetar la web actual en una ventana nativa (probablemente Electron, Tauri o WebView2).

**Sub-fase 2.1: Más marcas en modo ADMS o equivalente**
- Hikvision, Dahua. Mantener compatibilidad con `/iclock/*` actual donde sea posible.

**Sub-fase 2.2: Soporte TCP/IP (acceso a red local desde la app de escritorio)**
- ZKTeco no-ADMS, Hikvision, Dahua, genéricos tipo Realand.
- Requiere acceso a red local que el navegador no permite — por eso vive en el .exe.

**Implicación para el código actual:** mantener el frontend lo más estándar posible. Sin APIs específicas del navegador puro, sin localStorage abusivo, sin features que rompan al embeberlo en WebView.

### Fase 3: Acceso desde Android
- PWA o TWA (Trusted Web Activity).
- **Implicación para el código actual:** el frontend debe ser **PWA-ready desde ahora** — viewport correcto, `manifest.json`, service worker básico, íconos en distintos tamaños.

**Regla derivada:** todo lo que se haga ahora debe sobrevivir a las 3 fases.

---

## 👆 Estrategia biométrica multi-marca (crítica para Fase 2)

Realidad técnica que hay que tener clara:
- **Las plantillas (templates) NO son intercambiables entre marcas** ni siempre entre modelos — cada algoritmo produce un formato propio.
- **Hoy:** se trabaja con ZKTeco K50 Pro. La plantilla recibida ya viene procesada por el algoritmo del equipo.

**Estrategia recomendada al expandir a más marcas:**

1. **Una plantilla por marca/modelo, no compartir entre fabricantes.** En `huellas_adms`, agregar columna `tipo_algoritmo` o `marca_modelo` y guardar la plantilla del fabricante correspondiente.
2. **Matching del lado del dispositivo, no del servidor.** El servidor solo enruta y guarda; el reloj decide si la huella coincide. Eso evita reimplementar matching por marca.
3. **Capa de abstracción en el código:** una clase/módulo `BiometricAdapter` con implementaciones por marca (`ZKTecoAdapter`, `HikvisionAdapter`, `DahuaAdapter`). El resto del sistema habla con la interfaz, no con la marca.
4. **Si una marca soporta el estándar ISO 19794-2**, preferirlo. Pero no asumir compatibilidad — confirmar con el equipo físico antes.
5. **Re-enrolar al cambiar de marca.** Documentar al cliente que migrar de ZKTeco a Hikvision implica re-enrolar a todos los empleados. Es esperado, no un bug.

**No tomar decisiones de arquitectura biométrica sin consultar primero — afecta a todo el modelo.**

---

## 🔤 Convenciones del frontend

- [menu.js](menu.js) en cada página autenticada. Instala:
  - Wrapper de `window.fetch` que redirige a `index.html` en HTTP 401.
  - Helpers SweetAlert: `mostrarExito` / `mostrarError` / `pedirConfirmacion` / `pedirTexto` / `pedirClave`. **Usar estos en lugar de `alert`/`confirm`/`prompt`.**
  - `renderizarMenu(pantallaActiva)` — lee `localStorage.userData.modulos` para ocultar items.
  - `verificarAccesoPantalla()` — corre en `DOMContentLoaded`, redirige si el usuario no tiene el módulo.
- Tras login: `localStorage.token` y `localStorage.userData` (con `nombre`, `rol`, `empresa`, `modulos`).
- Ruteo por rol: `index.html` (login) → superadmin va a `dashboard_superadmin.html`; tenant a `dashboard_cliente.html`.

### Naming
- **Backend / BD:** `snake_case`.
- **JavaScript:** `camelCase`.
- **Archivos HTML/CSS:** `kebab-case` (ej: `dashboard-cliente.html`). Mantener nombres existentes hasta cambio coordinado.

---

## 📂 Mapa de `main.py`

`main.py` está organizado por banderas de comentario numeradas. **Para encontrar una sección, hacer `grep "# N\."` en `main.py`** en lugar de pedir el archivo completo.

Secciones: `1` setup/auth core, `5` ADMS hardware, `6/6.5` superadmin, `7` catálogos org, `8` empleados, `9` turnos, `10` ausencias, `11` motor matemático, `12` calendario asistencia, `13` feriados, `14` reporte diario, `15` edición manual, `16` dashboard/simulador, `17/18` lectores y sync ADMS, `19` facturación, `20-22` monitor hw / push feriados / auditoría, `23/24` dashboard financiero / feature flags.

---

## 📋 Patrón al agregar un endpoint

1. Abrir conexión con `conectar_bd(schema)` correcto (public o tenant).
2. Usar `RealDictCursor` si devuelves JSON.
3. Aplicar `requiere_modulo("X")` si es feature de tenant.
4. Llamar a `registrar_auditoria` en escrituras o acciones sensibles.
5. Si muta entradas de asistencia → disparar `procesar_asistencia_dia` (directo o `BackgroundTasks`).
6. Ubicarlo en la sección numerada que corresponda.
7. Errores con `HTTPException(status_code=N, detail="mensaje en español")`.

---

## 🕐 Zona horaria

- **Hora de Bolivia (UTC-4)** — el sistema opera y guarda en hora local.
- Todos los cálculos de retraso, turnos nocturnos y marcajes asumen hora Bolivia.
- **Si en algún momento se da soporte multi-país**, migrar a UTC en BD + conversión en presentación. Por ahora NO mezclar criterios.

---

## 📝 Logging

**TODO:** Claude debe revisar `main.py` y reportar qué se está usando hoy (probablemente `print()` o `logging` sin estructurar). Actualizar esta sección con la realidad encontrada.

**Convención propuesta una vez se decida:**
- `logging.info()` — flujo normal (login, creación de registros).
- `logging.warning()` — situaciones sospechosas (logins fallidos, payloads ADMS malformados).
- `logging.error()` — errores con stack trace.
- **Nunca `print()` en producción.**
- Considerar **Sentry** o similar antes del lanzamiento para captura de errores en producción.

---

## 🏷️ Versionado y releases

**Estado actual:** sin versionado.

**Propuesta a adoptar antes del lanzamiento:**
- **Semver:** `vMAJOR.MINOR.PATCH` (ej: `v0.1.0` para primera beta).
- **Tags en git** al desplegar a producción.
- **CHANGELOG.md** simple en raíz del repo, con secciones `### Added`, `### Changed`, `### Fixed`.
- Pre-lanzamiento: todo bajo `v0.x.y`. Lanzamiento público = `v1.0.0`.

---

## 🧪 Tests (a futuro)

Actualmente **no hay** suite de pruebas, linter ni build. **No inventar uno por iniciativa propia.**

Plan cuando se decida agregarlos:
1. Empezar por **`calcular_dia_asistencia`** — función pura, candidata ideal para tests unitarios con `pytest`.
2. Tests de integración para endpoints `/iclock/*` con SN mockeado.
3. Tests del flujo completo: marcaje crudo → `procesar_asistencia_dia` → `asistencia_diaria`.

Pedir antes de empezar a generar archivos de test.

---

## 🔒 Seguridad y datos personales

- **Huellas biométricas:** se guarda solo el **template procesado** que devuelve el algoritmo del lector (NO la imagen de la huella).
- **Credenciales:** nunca hardcodear. Cambiar `admin123` en cada despliegue real.
- **Logs:** no loguear contraseñas, tokens, ni payloads completos de huellas.
- **Auditoría:** toda acción privilegiada va a `saas_auditoria` vía `registrar_auditoria`.
- **HTTPS obligatorio** en producción (Render lo da por default).
- Antes del lanzamiento público → correr la skill `skill-security-auditor` y revisar findings.

---

## 📌 Sobre este archivo

- Este `CLAUDE.md` se mantiene **a mano**. No es generado automáticamente.
- Si Claude detecta que una regla aquí ya no aplica al código real → **avisar al usuario**, no actualizar el archivo solo.
- Para preferencias personales que no van al repo (estilo de commits, configs temporales) → crear `CLAUDE.local.md` y agregarlo a `.gitignore`.
- Mantener bajo ~500 líneas para que Claude lo lea en cada sesión nueva sin gastar contexto excesivo.