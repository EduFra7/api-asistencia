# Proyecto LEO — Design System & Guía de Estilos
**Versión:** 1.0 · **Fuente canónica:** `dashboard_superadmin_v7.html`
**Audiencia:** IAs y desarrolladores que construyan nuevas vistas del ecosistema.

---

## 1. ADN Visual y Estética

### Filosofía
El sistema visual de Proyecto LEO sigue un **minimalismo funcional de alta densidad informativa**. El objetivo es que la interfaz desaparezca y los datos sean los protagonistas. Se evita activamente cualquier decoración que no tenga función semántica.

### Reglas de oro
- **Cero gradientes decorativos.** Los fondos son planos. No hay degradados de marca, fondos con texturas ni overlays cromáticos.
- **Sombras solo para elevar, no para decorar.** Se usan `shadow-sm` (tarjetas) y `shadow-2xl` (drawers/dropdowns flotantes). Nunca sombras de color.
- **Bordes sutiles, no separadores pesados.** Los contenedores se definen por `border` de 1px en `#e2e8f0` (claro) o `#262626` (oscuro). Nunca `border-2` ni colores de borde saturados.
- **Cero emojis** en la interfaz de producción.
- **Tipografía como jerarquía.** El peso tipográfico (`font-medium`, `font-semibold`, `font-bold`) y el tamaño hacen la labor que en otros diseños hacen los colores.
- **El acento cromático (azul de marca) se reserva para acciones primarias y estados activos únicamente.** No se usa como decoración de fondo.
- **Microinteracciones con propósito:** las transiciones existen para orientar al usuario, no para entretenerlo. Duración máxima: 280ms.

---

## 2. Sistema de Colores (Tokens & Theming)

### 2.1 Tokens de marca (Tailwind config)

```js
colors: {
  brand: {
    blue: '#0c5078',   // Azul corporativo — acción primaria
    red:  '#c12425',   // Rojo corporativo — peligro, alertas críticas, suspensión
  }
}
```

### 2.2 Escala de superficies — Modo Claro

| Token | Hex | Uso |
|---|---|---|
| `light-50` / `bg-light-50` | `#f8fafc` | Fondo de página (`<body>`) |
| `white` | `#ffffff` | Superficie de tarjeta, sidebar, topbar |
| `slate-50` / `bg-slate-50` | `#f8fafc` | Fondo de inputs, filas de tabla alt, fondos de filtros |
| `slate-100` | `#f1f5f9` | Hover de items de menú, fondo activo de menú |
| `light-border` / `border-light-border` | `#e2e8f0` | **Borde universal en modo claro** — tablas, cards, sidebar, topbar, inputs |

### 2.3 Escala de superficies — Modo Oscuro

| Token | Hex | Uso |
|---|---|---|
| `dark-900` | `#0a0a0a` | Fondo de página (`<body>`) |
| `dark-800` | `#111111` | Superficie de tarjeta, sidebar, topbar, dropdowns |
| `dark-700` | `#1a1a1a` | Hover de items, fondo de inputs, filas de tabla alt |
| `dark-600` | `#222222` | Fondo secundario profundo |
| `dark-border` / `border-dark-border` | `#262626` | **Borde universal en modo oscuro** |
| `bg-dark-900/80` | `#0a0a0a` con 80% opacidad | Topbar con `backdrop-blur-sm` |

### 2.4 Colores de acento y cuándo usarlos

| Color | Hex | Cuándo usarlo |
|---|---|---|
| `brand-blue` | `#0c5078` | Botón primario, icono de marca, estado activo en menú, borde de foco en inputs (`focus:border-brand-blue`), loader ring, avatar brand icon |
| `hover:bg-blue-900` | `#1e3a5f` (Tailwind) | Estado hover del botón primario |
| `brand-blue/3` | `#0c5078` al 3% opacidad | Overlay hover sutil en tarjetas KPI especiales |
| `brand-blue/20` | `#0c5078` al 20% | Fondo de avatar/icono de empresa en tabla |
| `brand-red` | `#c12425` | Botón destructivo, estado "Suspendida", badge de errores críticos, banner de impersonación, punto de indicador de error, barra de uso al 100% |
| `red-50` / `red-900/20` | — | Fondo hover de botón de cerrar sesión (claro/oscuro) |

### 2.5 Colores semánticos (estados)

Todos los colores semánticos siguen el patrón: **fondo tenue / texto saturado en modo claro; fondo con opacidad baja / texto más claro en modo oscuro.**

| Estado | Fondo Claro | Texto Claro | Fondo Oscuro | Texto Oscuro |
|---|---|---|---|---|
| **Éxito / Online / Activa** | `bg-emerald-50` `#f0fdf4` | `text-emerald-700` `#047857` | `bg-emerald-900/20` | `text-emerald-300` / `text-emerald-400` |
| **Alerta / Vencimiento próximo** | `bg-amber-50` | `text-amber-600/700` | `bg-amber-900/20..30` | `text-amber-400` |
| **Error / Suspendida / Crítico** | `bg-red-50` / `bg-red-100` | `text-brand-red` `#c12425` | `bg-red-900/20..30` | `text-red-400` |
| **Información / Cobro pendiente** | `bg-sky-50` | `text-sky-600` | `bg-sky-900/20` | `text-sky-400` |
| **Neutral / Sin dispositivos** | `bg-slate-100` | `text-slate-400` | `bg-dark-700` | `text-slate-400` |

### 2.6 Colores de texto

| Clase Tailwind | Uso |
|---|---|
| `text-slate-900 dark:text-white` | Títulos, datos primarios, texto de alto contraste |
| `text-slate-800 dark:text-slate-200` | Texto de body principal |
| `text-slate-700 dark:text-slate-300` | Texto secundario, labels de formulario |
| `text-slate-600 dark:text-slate-400` | Subtítulos, metadatos |
| `text-slate-500 dark:text-slate-400` | Texto de apoyo, items de menú inactivos |
| `text-slate-400 dark:text-slate-500` | Placeholder, separadores, detalles de baja jerarquía |
| `text-brand-blue dark:text-blue-400` | Item de menú activo, links de acción, contadores KPI con acento |

### 2.7 Regla de inversión Claro ↔ Oscuro

El sistema usa **`darkMode: 'class'`** de Tailwind. La clase `dark` se agrega al `<html>`. El patrón es:
- **Fondos:** claro = `white` / `slate-50` → oscuro = `dark-800` / `dark-700`
- **Bordes:** claro = `#e2e8f0` → oscuro = `#262626` (aproximadamente 6x más oscuro)
- **Texto:** claro = `slate-900` → oscuro = `white`
- **Superficies semánticas:** en oscuro, los colores de estado usan **opacidad reducida** sobre el fondo oscuro: `bg-emerald-900/20`, `bg-amber-900/30`, `bg-red-900/20` en lugar de los tonos pastel del modo claro.
- **Anti-flash:** un script inline antes del primer render lee `localStorage.getItem('leo-theme')` y agrega la clase `dark` al `<html>` si corresponde, eliminando el parpadeo blanco al cargar.

---

## 3. Tipografía y Escala Responsive

### 3.1 Familias tipográficas

| Rol | Familia | Pesos | CDN |
|---|---|---|---|
| **Sans (interfaz)** | `Geist` | 300, 400, 500, 600, 700, 800 | Google Fonts |
| **Mono (código, datos, contadores)** | `Geist Mono` | 400, 500, 600 | Google Fonts |
| Fallback sans | `system-ui, sans-serif` | — | Nativo |
| Fallback mono | `monospace` | — | Nativo |

```html
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800&family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
```

Tailwind config:
```js
fontFamily: {
  sans: ['Geist', 'system-ui', 'sans-serif'],
  mono: ['Geist Mono', 'monospace'],
}
```

Geist Mono se usa en: contadores KPI (`text-4xl font-mono`), valores de métricas financieras, badges de conteo, timestamps de auditoría, shortcuts de teclado (`<kbd>`), y textos que representan datos exactos.

### 3.2 Tipografía fluida (Responsive Root)

El root `font-size` usa `clamp()` para escalar suavemente según el ancho del viewport. **Todas las clases Tailwind basadas en rem escalan en proporción** sin modificar el HTML.

```css
html {
  font-size: clamp(14px, 0.3vw + 12.5px, 18px);
}
```

| Viewport | font-size resultante | text-sm (0.875rem) | text-xs (0.75rem) |
|---|---|---|---|
| 375px (móvil) | **14px** | 12.25px | 10.5px |
| 768px (tablet) | **14.8px** | 12.95px | 11.1px |
| 1024px (laptop) | **15.6px** | 13.65px | 11.7px |
| 1280px (HD) | **16.3px** | 14.26px | 12.2px |
| **1440px (objetivo)** | **~16.8px** | ~14.7px | ~12.6px |
| 1920px+ | **18px (tope)** | 15.75px | 13.5px |

**Override de tamaños arbitrarios (px fijos):** Las clases `text-[Xpx]` de Tailwind no responden al root rem. Se escalan con media queries + `!important`:

```css
@media (min-width: 1280px) {
  .text-\[9px\]  { font-size: 10px  !important; }
  .text-\[10px\] { font-size: 11px  !important; }
  .text-\[11px\] { font-size: 12px  !important; }
  .text-\[12px\] { font-size: 13px  !important; }
  .text-\[13px\] { font-size: 14px  !important; }
}
@media (min-width: 1440px) {
  .text-\[9px\]  { font-size: 11px  !important; }
  .text-\[10px\] { font-size: 12px  !important; }
  .text-\[11px\] { font-size: 13px  !important; }
  .text-\[12px\] { font-size: 14px  !important; }
  .text-\[13px\] { font-size: 15px  !important; }
}
```

### 3.3 Jerarquía tipográfica

| Nivel | Clases Tailwind | Uso |
|---|---|---|
| **H1 / Título de vista** | `text-2xl font-semibold text-slate-900 dark:text-white tracking-tight` | Encabezado principal de cada sección |
| **H2 / Título de card** | `text-sm font-semibold text-slate-800 dark:text-white` | Encabezado de tarjeta o sección secundaria |
| **H3 / Drawer/Modal title** | `font-semibold text-base text-slate-900 dark:text-white` | Encabezado de drawer lateral |
| **Subtítulo / Descripción** | `text-sm text-slate-500 dark:text-slate-400 mt-1` | Párrafo descriptivo debajo del H1 |
| **Label de campo** | `text-[10px] font-bold uppercase tracking-wider text-slate-400` | Etiqueta de sección/campo en formularios y KPI |
| **Texto body** | `text-sm text-slate-800 dark:text-slate-200` | Contenido principal de tablas y listas |
| **Texto secundario** | `text-[11px] text-slate-500` | Metadatos, fechas, subtítulos de fila |
| **KPI número grande** | `text-4xl font-mono font-medium text-slate-900 dark:text-white` | Contador principal de tarjeta KPI |
| **KPI número mediano** | `text-3xl font-mono font-medium` | Contador secundario (ej. MRR) |
| **Código / timestamp** | `font-mono text-[12px]` | Datos técnicos, auditoría, schema names |
| **Badge / Chip** | `text-[10px] font-semibold` | Etiquetas de estado, contadores |
| **Keyboard shortcut** | `text-[9px] font-mono` | `<kbd>` en atajos de teclado |

### 3.4 Suavizado
```css
body { -webkit-font-smoothing: antialiased; }
```

---

## 4. Layout, Espaciado y Posicionamiento

### 4.1 Shell principal

```html
<body class="bg-light-50 dark:bg-dark-900 h-screen flex overflow-hidden">
  <aside id="sidebar" ...>     <!-- sidebar fijo izquierda -->
  <main class="flex-1 flex flex-col min-w-0 h-screen relative">
    <header class="h-14 ...">  <!-- topbar fijo superior -->
    <div id="content" class="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8"> <!-- área de scroll -->
```

- **`h-screen overflow-hidden`** en body evita scroll en la página completa; el scroll ocurre solo dentro de `#content`.
- **`min-w-0`** en `<main>` previene que el flexbox desborde al colapsar el sidebar.

### 4.2 Anchuras de contenedores de contenido

| Elemento | Clase | px aprox. |
|---|---|---|
| Drawer lateral | `w-full md:w-[500px]` | 500px en desktop |
| Dropdown de búsqueda / notificaciones | `w-80` | 320px |
| Contenedor principal de vista | `max-w-6xl mx-auto` | 1152px máximo |
| Input de búsqueda en topbar | `w-52` | 208px |
| Sidebar expandido | `w-64` | 256px |
| Sidebar colapsado | `w-16` | 64px |

### 4.3 Escala de espaciado

El espaciado usa la escala estándar de Tailwind. Los valores más frecuentes en el sistema:

| Contexto | Clases |
|---|---|
| **Padding interno de tarjeta** | `p-5` (20px) o `p-6` (24px) |
| **Padding de fila de tabla** | `px-5 py-3.5` |
| **Padding de item de menú** | `px-3 py-2.5` |
| **Padding de header de sección** | `px-5 py-4` o `px-6 py-4` |
| **Gap entre elementos en flex** | `gap-2` (8px), `gap-3` (12px), `gap-4` (16px) |
| **Gap entre tarjetas en grid** | `gap-4` (16px) |
| **Separador vertical en menú** | `my-2` con `border-t` |
| **Área de contenido (padding del scroll)** | `p-4 md:p-6 lg:p-8` |

### 4.4 Grids de tarjetas KPI y contenido

```css
/* KPI row: 2 cols en móvil, 4 en desktop */
grid grid-cols-2 md:grid-cols-4 gap-4

/* Secciones de contenido: 1 col en móvil, 2 en desktop grande */
grid grid-cols-1 lg:grid-cols-2 gap-4
```

### 4.5 Posicionamiento de elementos flotantes

- **Sidebar:** `absolute md:relative` — absoluto en móvil (overlay), relativo en desktop.
- **Drawer:** `fixed inset-y-0 right-0` — panel derecho full height.
- **Dropdowns (notificaciones, búsqueda):** `absolute right-0 mt-2` sobre el elemento padre con `relative`.
- **Z-index stack:**
  - `z-20`: topbar
  - `z-30`: overlay móvil
  - `z-40`: sidebar
  - `z-[45]`: drawer overlay
  - `z-50`: drawer panel, dropdowns
  - `z-200`: loading screen inicial

---

## 5. Breakpoints y Adaptabilidad

### 5.1 Breakpoints (estándar Tailwind)

| Prefijo | Min-width | Dispositivo objetivo |
|---|---|---|
| *(sin prefijo)* | 0px | Móvil base (~375px) |
| `sm:` | 640px | Móvil grande / phablet |
| `md:` | 768px | Tablet |
| `lg:` | 1024px | Laptop |
| `xl:` | 1280px | Monitor HD |
| `2xl:` | 1536px | Monitor ultrawide / 4K |

Breakpoints especiales **propios del sistema** (CSS puro, no Tailwind):
- `min-width: 1280px` → primera escala de `text-[Xpx]`
- `min-width: 1440px` → segunda escala de `text-[Xpx]` (objetivo 1440p)

### 5.2 Sidebar — comportamiento responsivo

| Viewport | Estado por defecto | Al hacer hover (desktop) | Con hamburger (móvil) |
|---|---|---|---|
| `< 768px` | Oculto (`-translate-x-full`) + overlay negro | N/A | Desliza a la vista, overlay detrás |
| `≥ 768px` | Colapsado (`w-16`, solo iconos) | Expande a `w-64` con fade de labels | N/A |
| Con clase `sb-pinned` | Fijado en `w-64` (se aplica al abrir SweetAlert) | — | — |

**Transición del sidebar:**
```css
#sidebar {
  transition: width 220ms cubic-bezier(0.16,1,0.3,1),
              transform 220ms cubic-bezier(0.16,1,0.3,1);
}
```

**Labels del sidebar** (`.sb-label`, `.sb-user-text`, `.sb-brand-text`, `.sb-logout`) usan opacity fade:
- Colapsado: `opacity: 0; pointer-events: none;`
- Hover expand: `opacity: 1; transition: opacity 150ms 80ms;` (80ms de delay)

### 5.3 Topbar — comportamiento responsivo

- Hamburger: visible solo en `< md` (`class="md:hidden"`).
- Breadcrumb: visible solo en `≥ md` (`class="hidden md:flex"`).
- Buscador global: visible en `≥ sm` (`class="hidden sm:block"`).

### 5.4 Tablas complejas en móvil — patrón card-flip

Las tablas con clase `.mobile-table` se transforman en tarjetas stack en `< 640px`:

```css
@media (max-width: 640px) {
  /* Ocultar thead visualmente (accesible) */
  .mobile-table thead tr { position: absolute; top: -9999px; left: -9999px; }
  
  /* Cada <tr> se convierte en una tarjeta */
  .mobile-table tr {
    background: white; border-radius: 12px;
    margin-bottom: 12px; padding: 4px 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.05);
  }
  
  /* Cada <td> se convierte en fila key:value */
  .mobile-table td {
    display: flex; justify-content: space-between;
    align-items: center; padding: 10px 0;
    border-bottom: 1px solid #e2e8f0;
  }
  
  /* Label generado desde data-label="…" en el HTML */
  .mobile-table td::before {
    content: attr(data-label);
    font-weight: 700; color: #64748b;
    font-size: 10px; text-transform: uppercase;
  }
}
```

**Regla de implementación:** Cada `<td>` de la tabla debe incluir `data-label="Nombre de columna"` para que el label aparezca automáticamente en móvil.

### 5.5 Área de contenido — padding responsivo

```html
<div id="content" class="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
```
- Móvil: 16px
- Tablet: 24px
- Desktop: 32px

### 5.6 Touch targets mínimos (accesibilidad móvil)

```css
@media (max-width: 768px) {
  input:not([type='checkbox']):not([type='radio']),
  select, button:not(.btn-icon) { min-height: 44px; }
}
```

---

## 6. Librería de Componentes UI

### 6.1 Botones

#### Primario (acción principal)
```html
<button class="flex items-center gap-2 px-3 py-2 text-sm font-semibold text-white
               bg-brand-blue hover:bg-blue-900 rounded-lg transition-colors shadow-sm">
  Texto acción
</button>
```
- Background: `#0c5078` → hover: Tailwind `blue-900` ≈ `#1e3a5f`
- Texto: blanco
- Border radius: `rounded-lg` (8px)
- Sombra: `shadow-sm`
- Fuente: `font-semibold`, `text-sm`
- Transición: `transition-colors` (150ms Tailwind default)

#### Secundario (acción auxiliar)
```html
<button class="flex items-center gap-2 px-3 py-2 text-sm font-medium
               text-slate-600 dark:text-slate-300
               bg-white dark:bg-dark-800
               border border-light-border dark:border-dark-border
               rounded-lg hover:bg-slate-50 dark:hover:bg-dark-700
               transition-colors shadow-sm">
  Exportar
</button>
```

#### Icono (ghost, sin texto)
```html
<button class="w-8 h-8 flex items-center justify-center rounded-lg
               border border-light-border dark:border-dark-border
               text-slate-500 hover:bg-slate-50 dark:hover:bg-dark-700
               transition-colors">
  <i class="fas fa-pencil text-xs"></i>
</button>
```
- Tamaño: `w-8 h-8` (32×32px)
- Sin texto visible, solo icono

#### Icono grande (topbar)
- Tamaño: `w-9 h-9` (36×36px)
- Mismo patrón ghost, sin borde

#### Destructivo / Cerrar sesión
```html
<button class="flex items-center py-2 px-3 rounded-lg
               text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20
               transition-colors">
```

#### Botón semántico de éxito
```html
<button class="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold
               text-emerald-700 dark:text-emerald-400
               bg-emerald-50 dark:bg-emerald-900/20
               border border-emerald-200 dark:border-emerald-700/40
               hover:bg-emerald-100 dark:hover:bg-emerald-900/30
               rounded-lg transition-colors shadow-sm">
```

#### Estado disabled
No existe una clase `.disabled` centralizada. Se maneja con `disabled` HTML + `opacity-50 cursor-not-allowed` donde sea necesario, o reemplazando el botón por texto estático durante operaciones async.

---

### 6.2 Tarjetas / Cards

#### Card estándar
```html
<div class="bg-white dark:bg-dark-800 rounded-xl border border-light-border
            dark:border-dark-border shadow-sm p-5">
```
- Background: `white` / `#111111`
- Border: `1px` en `#e2e8f0` / `#262626`
- Border radius: `rounded-xl` (12px)
- Sombra: `shadow-sm` (muy sutil, solo para elevar sobre el fondo de página)
- Padding interno: `p-5` (20px) o `p-6` (24px)

#### Card KPI (contador numérico)
```html
<div class="bg-white dark:bg-dark-800 p-5 rounded-xl border border-light-border
            dark:border-dark-border shadow-sm">
  <div class="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-2">
    <i class="fas fa-building text-[13px]"></i>
    <span class="text-[10px] font-semibold uppercase tracking-wider">Label</span>
  </div>
  <p class="text-4xl font-mono font-medium text-slate-900 dark:text-white">42</p>
</div>
```
El número usa `font-mono` explícitamente para dar sensación de dato técnico preciso.

#### Card con hover interactivo (KPI especial)
```html
<div class="... relative overflow-hidden group">
  <div class="absolute inset-0 bg-brand-blue/3 opacity-0 group-hover:opacity-100 transition-opacity"></div>
  <!-- contenido relativo al overlay -->
</div>
```
Overlay azul de 3% de opacidad que aparece al hacer hover.

#### Stat Pill (filtro compacto)
```css
.stat-pill {
  display: flex; flex-direction: column; gap: 2px;
  padding: 10px 16px;
  background: white; border: 1px solid #e2e8f0;
  border-radius: 10px; min-width: 72px;
}
.dark .stat-pill { background: #111111; border-color: #262626; }
```
Hover: `hover:border-brand-blue` — el borde cambia a azul de marca al enfocar.

---

### 6.3 Navegación — Sidebar

#### Item de menú inactivo
```html
<button class="menu-btn w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
               text-sm font-medium transition-all duration-150
               text-slate-500 dark:text-slate-400
               hover:bg-slate-50 dark:hover:bg-dark-700
               hover:text-slate-900 dark:hover:text-white">
  <i class="fas fa-building w-5 text-center shrink-0 text-[13px]"></i>
  <span class="sb-label whitespace-nowrap">Empresas</span>
</button>
```

#### Item de menú activo
```html
<button class="menu-btn ... text-brand-blue dark:text-white bg-slate-100 dark:bg-dark-700">
```
Diferencias con inactivo:
- Color texto: `text-brand-blue` (claro) / `text-white` (oscuro)
- Background: `bg-slate-100` (claro) / `bg-dark-700` (oscuro)
- Sin estados hover (ya está activo)

#### Separador en menú
```html
<div class="my-2 border-t border-light-border dark:border-dark-border"></div>
```

#### Item especial ⌘K (dashed)
```html
<button class="... border border-dashed border-light-border dark:border-dark-border text-slate-400">
```
Distingue visualmente el atajo de teclado del resto de la navegación.

---

### 6.4 Formularios / Inputs

#### Input de texto estándar
```html
<input type="text"
       class="w-full bg-slate-50 dark:bg-dark-900
              border border-light-border dark:border-dark-border
              rounded-lg px-3 py-2 text-sm
              text-slate-900 dark:text-white
              placeholder-slate-400 dark:placeholder-slate-600
              focus:outline-none focus:border-brand-blue dark:focus:border-brand-blue
              transition-colors">
```

Reglas clave:
- Background: `slate-50` / `dark-900` (más profundo que la tarjeta contenedora)
- Border: `#e2e8f0` / `#262626` → cambia a `#0c5078` en focus
- Placeholder: `slate-400` / `slate-600`
- **`focus:outline-none`**: siempre presente para eliminar el outline nativo del navegador; se reemplaza por el cambio de borde azul
- Padding: `px-3 py-2` estándar; `px-4 py-2.5` para inputs más grandes

#### Input compacto en topbar (wrapper con icono)
```html
<div class="flex items-center gap-2 ... bg-slate-50 dark:bg-dark-800 border
            border-light-border dark:border-dark-border rounded-lg px-3 py-1.5
            focus-within:border-brand-blue transition-colors">
  <i class="fas fa-magnifying-glass text-slate-400 text-xs shrink-0"></i>
  <input class="flex-1 bg-transparent focus:outline-none ...">
</div>
```
El border azul de focus se aplica al wrapper con `focus-within:border-brand-blue`, no al input.

#### Select / Dropdown de filtro
```html
<select class="px-3 py-2 text-sm
               bg-slate-50 dark:bg-dark-700
               border border-light-border dark:border-dark-border
               rounded-lg focus:outline-none focus:border-brand-blue
               text-slate-700 dark:text-slate-300 cursor-pointer">
```
Idéntico al input pero con `cursor-pointer`.

#### Textarea
```html
<textarea class="w-full bg-slate-50 dark:bg-dark-900 border border-light-border
                 dark:border-dark-border rounded-lg p-3 text-sm text-slate-700
                 dark:text-white resize-none focus:outline-none
                 focus:border-brand-blue transition-colors">
```

#### Label de campo en formularios
```html
<label class="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1.5">
  Nombre
</label>
```

---

### 6.5 Badges y Pills de estado

```html
<!-- Estado positivo -->
<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold
             bg-emerald-100 dark:bg-emerald-900/30
             text-emerald-700 dark:text-emerald-400">
  Activa
</span>

<!-- Estado de alerta -->
<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold
             bg-amber-100 dark:bg-amber-900/30
             text-amber-700 dark:text-amber-400">
  Vencida
</span>

<!-- Estado de error -->
<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold
             bg-red-100 dark:bg-red-900/30 text-brand-red">
  Suspendida
</span>
```

Patrón de badge de dispositivo con punto de color:
```html
<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium
             bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400">
  <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse inline-block"></span>
  En línea
</span>
```

### 6.6 Tablas de datos

#### Estructura base
```html
<div class="bg-white dark:bg-dark-800 rounded-xl border border-light-border
            dark:border-dark-border overflow-hidden shadow-sm">
  <table class="w-full mobile-table">
    <thead class="bg-slate-50 dark:bg-dark-900/60">
      <tr class="text-[10px] uppercase text-slate-500 border-b border-light-border dark:border-dark-border">
        <th class="px-5 py-3 text-left font-semibold tracking-wider">Columna</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-light-border dark:divide-dark-border">
      <tr class="hover:bg-slate-50 dark:hover:bg-dark-700 transition-colors group">
        <td class="px-5 py-3.5" data-label="Columna">valor</td>
      </tr>
    </tbody>
  </table>
</div>
```

Reglas de la tabla:
- Header: `bg-slate-50` / `bg-dark-900/60` — 60% de opacidad sobre fondo oscuro
- Separación entre filas: `divide-y` en `#e2e8f0` / `#262626`
- Hover de fila: `hover:bg-slate-50 dark:hover:bg-dark-700`
- Texto de header: `text-[10px] uppercase tracking-wider font-semibold`
- Cada `<td>` debe tener `data-label="..."` para el card-flip móvil

---

### 6.7 Drawer lateral (panel de gestión)

```html
<div id="drPanel"
     class="fixed inset-y-0 right-0 w-full md:w-[500px]
            bg-white dark:bg-dark-800 z-50
            transform translate-x-full
            transition-transform duration-250 ease-out
            flex flex-col border-l border-light-border dark:border-dark-border shadow-2xl">
```

- Ancho: `100%` en móvil, `500px` en desktop
- Posición: `fixed` a la derecha, ocupa toda la altura
- Animación: `translate-x-full` (oculto) → `translate-x-0` (visible), `duration-250 ease-out`
- Sombra: `shadow-2xl` (la más pesada del sistema, para máxima elevación)
- Header del drawer: `px-6 py-4 border-b`
- Body scrollable: `flex-1 overflow-y-auto p-6 space-y-5`
- Footer con acciones: `px-6 py-4 border-t flex gap-3 justify-end`

### 6.8 Dropdowns (notificaciones, búsqueda global)

```html
<div class="absolute right-0 mt-2 w-80
            bg-white dark:bg-dark-800 rounded-xl shadow-2xl
            border border-light-border dark:border-dark-border hidden z-50">
```

- `rounded-xl` + `shadow-2xl` + `border` definen el estilo flotante
- `mt-2`: separación del trigger (8px)
- `z-50`: siempre sobre el contenido de página

### 6.9 Indicadores de carga

#### Spinner (inline y pantalla completa)
```css
.loader-ring {
  width: 28px; height: 28px;
  border: 2px solid rgba(255,255,255,.12);
  border-top-color: #0c5078;  /* brand-blue */
  border-radius: 50%;
  animation: spin .7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
```

#### Skeleton shimmer
```css
.skel {
  background: linear-gradient(90deg, #f1f5f9 25%, #e2e8f0 50%, #f1f5f9 75%);
  background-size: 600px 100%;
  animation: shimmer 1.4s ease-in-out infinite;
  border-radius: 6px;
}
.dark .skel {
  background: linear-gradient(90deg, #1a1a1a 25%, #222222 50%, #1a1a1a 75%);
}
@keyframes shimmer {
  0%   { background-position: -600px 0; }
  100% { background-position:  600px 0; }
}
```

Uso: reemplaza el contenido real mientras carga. Se combina con la clase de tamaño (`h-7 w-48 rounded-lg`) para imitar la forma del elemento real.

### 6.10 Indicadores de estado con punto

```css
.dot { width: 8px; height: 8px; border-radius: 50%; }
.dot-ok   { background: #16a34a; }
.dot-err  { background: #c12425; }
.dot-warn { background: #d97706; }

@keyframes dot-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(22,163,74,.5); }
  60%       { box-shadow: 0 0 0 5px rgba(22,163,74,0); }
}
.dot-pulse { animation: dot-pulse 2s ease-in-out infinite; }
```

Barra de uso (capacidad/límite):
```css
.uso-bar  { height: 3px; background: #e2e8f0; border-radius: 99px; }
.uso-fill { background: #0c5078; /* brand-blue, normal */ }
.uso-fill.warn { background: #d97706; /* >70% */ }
.uso-fill.full { background: #c12425; /* >90% */ }
```

---

## 7. Microinteracciones y UX

### 7.1 Tiempos de transición

| Elemento | Duración | Easing | Clase Tailwind |
|---|---|---|---|
| Items de menú (hover color) | 150ms | — | `transition-all duration-150` |
| Colores (botones, inputs, hovers genéricos) | ~150ms (Tailwind default) | — | `transition-colors` |
| Sidebar expand/collapse | 220ms | `cubic-bezier(0.16,1,0.3,1)` | CSS manual |
| Labels del sidebar (fade) | 150ms / 80ms delay | linear | CSS manual |
| Drawer lateral open/close | 250ms | `ease-out` | `transition-transform duration-250 ease-out` |
| Drawer overlay (blur) | 200ms | — | `transition-opacity duration-200` |
| Loading screen fadeout | 220ms | `ease-out` | CSS manual |
| Entrada de vista nueva | 280ms | `cubic-bezier(0.16,1,0.3,1)` | `animate-fade-up` |
| KPI counter aparecer | 300ms | `cubic-bezier(0.16,1,0.3,1)` | `.kpi-ready` |
| Hover overlay en KPI especial | Tailwind default | — | `transition-opacity` |
| Spinner | 700ms | `linear infinite` | CSS manual |
| Shimmer skeleton | 1400ms | `ease-in-out infinite` | CSS manual |
| Dot pulse (sesión activa) | 2000ms | `ease-in-out infinite` | `.dot-pulse` |

**Regla general:** animaciones de entrada de contenido usan `cubic-bezier(0.16,1,0.3,1)` (spring suave). Transiciones de estado usan `ease-out` o la transición por defecto de Tailwind (150ms ease).

### 7.2 Animación de entrada de vistas

Cada vez que se carga una nueva vista, el contenedor recibe la clase `animate-fade-up`:

```css
@keyframes fadeInUp {
  0%:   { opacity: 0; transform: translateY(8px); }
  100%: { opacity: 1; transform: translateY(0); }
}
/* Tailwind config */
animation: { 'fade-up': 'fadeInUp 0.28s cubic-bezier(0.16,1,0.3,1) forwards' }
```

HTML: `<div class="max-w-6xl mx-auto space-y-5 animate-fade-up">`

### 7.3 Modales — SweetAlert2

Todos los modales del sistema usan SweetAlert2, configurado con:

```css
.swal2-popup {
  font-family: 'Geist', sans-serif !important;
  border-radius: 14px !important;  /* más pronunciado que el estándar del sistema */
}
/* Modo oscuro */
html.dark .swal2-popup {
  background-color: #111111 !important;
  color: #f8fafc !important;
  border: 1px solid #262626 !important;
}
/* Backdrop blur cuando hay modal abierto */
.swal2-container.swal2-backdrop-show { backdrop-filter: blur(4px) !important; }
```

**Parche crítico de sidebar:** Al abrir cualquier SweetAlert, se agrega automáticamente `sb-pinned` al sidebar para que no se colapse durante la interacción. Se quita al cerrar el modal.

**Helpers disponibles:** `mostrarExito(msg)`, `mostrarError(msg)`, `pedirConfirmacion(title, text, btn)`, `pedirTexto(title, placeholder)`, `pedirClave(title)`. Todos definidos en `menu.js`.

**Regla:** errores que requieren acción del usuario → `mostrarError()` (modal bloqueante). Errores de red transitorios → toast no bloqueante. HTTP 401 → auto-redirect a `index.html` (manejado en `apiFetch`).

### 7.4 Notificaciones in-app

El sistema tiene un dropdown de notificaciones en el topbar:
- Badge rojo (`bg-brand-red`, `w-2 h-2`) sobre el ícono de campana cuando hay notificaciones.
- Dropdown `w-80`, `rounded-xl`, `shadow-2xl`.
- Notificaciones tipo `critical` → `text-brand-red bg-red-50`; resto → `text-amber-500 bg-amber-50`.

### 7.5 Scrollbars personalizados

```css
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 99px; }
.dark ::-webkit-scrollbar-thumb { background: #3f3f46; }
::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
```

Scrollbars delgados (5px), sin track visible, thumb redondeado. En oscuro usa zinc oscuro en lugar del slate claro.

### 7.6 Prevención de layout shift por SweetAlert

```css
body.swal2-shown, body.swal2-height-auto {
  padding-right: 0 !important;
  height: 100vh !important;
  overflow: hidden !important;
}
```

SweetAlert2 agrega `height: auto !important` al body, colapsando `h-screen`. Este override lo contrarresta.

### 7.7 Command Palette ⌘K

Se activa con `Ctrl+K` / `Cmd+K` o el botón en el sidebar. Es una paleta de búsqueda semántica sobre las vistas del sistema. El item activo en la lista usa `background: rgba(12,80,120,0.08)` en claro y `rgba(12,80,120,0.15)` en oscuro — el color de marca con muy baja opacidad.

### 7.8 Banner de modo soporte (impersonación)

Cuando staff (superadmin/administrador) accede a la vista de un cliente vía impersonation:
```js
// En dashboard_cliente.html — aparece automáticamente si existe:
localStorage.getItem('token_superadmin_backup')
```

El banner es un div `fixed top-0 left-0 right-0 z-[9999]` con `background: #c12425` (brand-red), `height: 44px`. Incluye nombre de la empresa y botón "← Volver al panel". Al mostrarse, agrega `padding-top: 44px` al body para no tapar contenido.

---

## 8. Iconografía

**Librería:** Font Awesome 6.5.0 (`fas` = solid, `far` = regular).

```html
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
```

**Tamaños de icono:**
- Iconos en menú sidebar: `text-[13px]` con `w-5 text-center` para alineación perfecta con el texto
- Iconos en botones: `text-xs` o `text-sm`
- Iconos decorativos en KPI: `text-[13px]`
- Iconos en breadcrumb: `text-xs`

**Regla:** Los iconos siempre acompañan texto o tienen `title` para accesibilidad. No se usan como único elemento comunicativo sin alternativa textual.

---

## 9. Reglas para Nuevas Vistas

Al crear una nueva vista del ecosistema, respetar estos invariantes:

1. **Importar los mismos CDNs** en el mismo orden: Tailwind CDN → tailwind.config → SweetAlert2 → font Geist → FA 6.5 → anti-flash script.

2. **Incluir `menu.js`** en todas las vistas de tenant. Para el panel superadmin, el JS de auth es inline.

3. **Estructura de página:** `body.bg-light-50.dark:bg-dark-900.h-screen.flex.overflow-hidden` con sidebar + main (`flex-1.flex.flex-col.min-w-0`).

4. **El área de contenido** usa `flex-1 overflow-y-auto p-4 md:p-6 lg:p-8` — nunca hacer scroll en el body.

5. **Toda mutación de datos** muestra `mostrarExito()` al éxito y `mostrarError()` al fallo. Nada muere en silencio.

6. **Acciones destructivas** siempre precedidas de `pedirConfirmacion()`.

7. **`max-w-6xl mx-auto`** como contenedor máximo de contenido en vistas de dashboard.

8. **`animate-fade-up`** en el div raíz del contenido dinámico.

9. **`mobile-table` + `data-label`** en toda tabla que puede tener muchas columnas.

10. **Tipografía fluida:** copiar el bloque `<style>` de tipografía (sección `html { font-size: clamp(...) }` + media queries de override) en cada nuevo HTML.

11. **`darkMode: 'class'`** + anti-flash script en cada nuevo HTML que soporte modo oscuro.

12. **Nunca** azul `#3B82F6` (Tailwind blue-500 por defecto), gradientes decorativos, o Inter como tipografía exclusiva.
