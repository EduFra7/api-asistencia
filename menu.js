// ==============================================================================
// 🛡️ INTERCEPTOR GLOBAL DE PETICIONES (SEGURIDAD ANTI-CADUCIDAD)
// ==============================================================================

if (!window.interceptorActivado) {
    window.originalFetch = window.fetch;

    window.fetch = async function() {
        try {
            const response = await window.originalFetch.apply(this, arguments);
            
            if (response.status === 401) {
                console.warn("⚠️ [SEGURIDAD] Sesión expirada o token inválido.");
                localStorage.removeItem('token');
                localStorage.removeItem('userData');
                window.location.href = 'index.html'; 
                return new Promise(() => {}); 
            }
            
            return response; 
        } catch (error) {
            throw error;
        }
    };
    
    window.interceptorActivado = true; 
}

// ==============================================================================
// 💎 MOTOR GRÁFICO DE NOTIFICACIONES (Reemplazo de alert, confirm, prompt)
// ==============================================================================

if (!window.Swal) {
    const swalScript = document.createElement('script');
    swalScript.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
    document.head.appendChild(swalScript);
}

if (!window.ToastActivado) {
    window.addEventListener('load', () => {
        window.Toast = Swal.mixin({
            toast: true,
            position: 'bottom-end',
            showConfirmButton: false,
            timer: 3000,
            timerProgressBar: true,
            didOpen: (toast) => {
                toast.addEventListener('mouseenter', Swal.stopTimer)
                toast.addEventListener('mouseleave', Swal.resumeTimer)
            }
        });
    });
    window.ToastActivado = true;
}

// Funciones Globales para usar en todo el ERP
window.mostrarExito = function(mensaje) {
    if(window.Toast) window.Toast.fire({ icon: 'success', title: mensaje });
};

window.mostrarError = function(mensaje, titulo = "Operación Denegada") {
    Swal.fire({
        icon: 'error',
        title: titulo,
        text: mensaje,
        confirmButtonColor: '#3b82f6', 
        confirmButtonText: 'Entendido',
        heightAuto: false, 
        backdrop: 'rgba(15, 23, 42, 0.6)', 
        customClass: { 
            popup: 'rounded-2xl shadow-2xl border border-gray-100',
            backdrop: 'backdrop-blur-sm' 
        }
    });
};

window.pedirConfirmacion = async function(mensaje, titulo = "⚠️ ¿Estás seguro?", textoBoton = "Sí, continuar") {
    const result = await Swal.fire({
        title: titulo,
        text: mensaje,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ef4444', 
        cancelButtonColor: '#94a3b8', 
        confirmButtonText: textoBoton,
        cancelButtonText: 'Cancelar',
        reverseButtons: true, 
        heightAuto: false, 
        backdrop: 'rgba(15, 23, 42, 0.6)', 
        customClass: { 
            popup: 'rounded-2xl shadow-2xl border border-gray-100',
            backdrop: 'backdrop-blur-sm'
        }
    });
    return result.isConfirmed;
};

window.pedirTexto = async function(mensaje, valorActual = "", titulo = "Ingresar Información") {
    const { value: texto } = await Swal.fire({
        title: titulo,
        input: 'textarea',
        inputLabel: mensaje,
        inputValue: valorActual,
        showCancelButton: true,
        confirmButtonColor: '#3b82f6', 
        cancelButtonColor: '#94a3b8',
        confirmButtonText: 'Guardar',
        cancelButtonText: 'Cancelar',
        heightAuto: false,
        backdrop: 'rgba(15, 23, 42, 0.6)',
        customClass: { 
            popup: 'rounded-2xl shadow-2xl border border-gray-100',
            backdrop: 'backdrop-blur-sm'
        }
    });
    return texto; 
};

window.pedirClave = async function(mensaje = "Ingrese la contraseña de Administrador", titulo = "Autorización Requerida") {
    const { value: password } = await Swal.fire({
        title: titulo,
        text: mensaje,
        input: 'password',
        inputAttributes: {
            autocapitalize: 'off',
            autocorrect: 'off'
        },
        showCancelButton: true,
        confirmButtonColor: '#2563eb', 
        cancelButtonColor: '#94a3b8',
        confirmButtonText: '<i class="fas fa-unlock mr-2"></i>Desbloquear',
        cancelButtonText: 'Cancelar',
        heightAuto: false, 
        backdrop: 'rgba(15, 23, 42, 0.6)', 
        customClass: { 
            popup: 'rounded-2xl shadow-2xl border border-gray-100',
            backdrop: 'backdrop-blur-sm'
        }
    });
    return password; 
};

// ==============================================================================
// 📱 CONTROLADOR RESPONSIVO DEL MENÚ (Global)
// ==============================================================================
window.toggleMenu = function() {
    const menu = document.getElementById('menu-lateral');
    const overlay = document.getElementById('overlay-menu');
    if(menu && overlay) {
        menu.classList.toggle('-translate-x-full');
        overlay.classList.toggle('hidden');
    }
};

// ==============================================================================
// 🚪 CONTROLADOR GLOBAL DE SESIÓN
// ==============================================================================
window.cerrarSesion = function() {
    localStorage.clear(); // Borra el token y los datos del usuario
    window.location.href = 'index.html'; // Lo manda a la pantalla de login
};

// ==============================================================================
// COMPONENTE: MENÚ LATERAL DINÁMICO
// ==============================================================================

function renderizarMenu(pantallaActiva) {
    const userDataStr = localStorage.getItem('userData');
    let empresaNombre = "Cargando...";
    let rol = "Admin";
    let modulos = {}; // ⚡ AQUÍ VIVIRÁN LOS PERMISOS

    if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        empresaNombre = userData.empresa_nombre || userData.empresa || "Empresa"; 
        rol = userData.rol === 'admin' ? 'Administrador' : 'Usuario';
        modulos = userData.modulos || {}; // ⚡ EXTRAEMOS DEL LOCALSTORAGE
    }

    const claseActiva = "flex items-center px-3 py-2.5 bg-blue-600 rounded-lg text-white transition-colors shadow-sm text-sm font-medium";
    const claseInactiva = "flex items-center px-3 py-2.5 text-slate-300 hover:bg-slate-800 rounded-lg transition-colors text-sm font-medium";

    // ⚡ FUNCIÓN MÁGICA: Si no hay permiso, retorna un texto vacío (no dibuja el botón)
    const generarEnlace = (idModulo, icono, url, texto) => {
        // Si la base de datos dice que es 'false', lo ocultamos. 
        // (Asumimos 'true' por defecto si el módulo es nuevo y no está en la BD aún)
        if (modulos[idModulo] === false) return ''; 
        
        const activo = (pantallaActiva === idModulo) ? claseActiva : claseInactiva;
        return `<a href="${url}" class="${activo}"><i class="fas ${icono} w-5 mr-2 text-center"></i> ${texto}</a>`;
    };

    // Construimos los bloques. Si un bloque se queda vacío, no dibujamos ni el título.
    let linksAsistencia = 
        generarEnlace('dashboard_cliente', 'fa-chart-pie', 'dashboard_cliente.html', 'Dashboard') +
        generarEnlace('calendario', 'fa-calendar-alt', 'calendario.html', 'Calendario') +
        generarEnlace('reporte_dia', 'fa-file-alt', 'reporte_dia.html', 'Reporte del Día');

    let linksPlanilla = 
        generarEnlace('planilla', 'fa-users', 'planilla.html', 'Personal') +
        generarEnlace('ausencias', 'fa-plane-departure', 'ausencias.html', 'Vacaciones y Permisos');

    let linksOrganizacion = 
        generarEnlace('organizacion', 'fa-sitemap', 'organizacion.html', 'Sucursales / Secciones') +
        generarEnlace('turnos', 'fa-clock', 'turnos.html', 'Horarios y Turnos') +
        generarEnlace('feriado', 'fa-calendar-plus', 'feriados.html', 'Feriados');

    let linksAjustes = 
        generarEnlace('configuracion', 'fa-cogs', 'configuracion.html', 'Configuración') +
        generarEnlace('simulador', 'fa-satellite-dish', 'simulador.html', 'Simulador ADMS') +
        generarEnlace('lectores', 'fa-fingerprint', 'lectores.html', 'Lectores Biométricos');

    const menuHTML = `
        <div class="p-4 md:p-6 border-b border-slate-800 flex justify-between items-center shrink-0">
            <div class="min-w-0">
                <h2 class="text-lg font-bold text-blue-400 truncate"><i class="fas fa-fingerprint mr-2"></i>${empresaNombre}</h2>
                <p class="text-[10px] md:text-xs text-slate-400 mt-1 uppercase tracking-wider truncate">${rol}</p>
            </div>
            <button onclick="toggleMenu()" class="xl:hidden text-slate-400 hover:text-white p-2 outline-none"><i class="fas fa-times text-xl"></i></button>
        </div>
        
        <div class="flex-1 overflow-y-auto py-4 scrollbar-thin scrollbar-thumb-slate-700">
            <nav class="space-y-1 px-3">
                ${linksAsistencia ? `<div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-2 px-3 text-slate-500">Control de Asistencia</div>${linksAsistencia}` : ''}
                
                ${linksPlanilla ? `<div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 text-slate-500">Gestión de Planilla</div>${linksPlanilla}` : ''}
                
                ${linksOrganizacion ? `<div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 text-slate-500">Organización</div>${linksOrganizacion}` : ''}
                
                ${linksAjustes ? `<div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 text-yellow-500">Ajustes (Admin)</div>${linksAjustes}` : ''}
            </nav>
        </div>
        
        <div class="p-4 border-t border-slate-800 shrink-0">
            <button onclick="cerrarSesion()" class="flex items-center justify-center md:justify-start w-full p-2.5 text-red-400 hover:bg-slate-800 rounded-lg transition-colors text-sm font-bold">
                <i class="fas fa-sign-out-alt w-5 mr-2 text-center"></i> Salir
            </button>
        </div>
    `;

    const contenedorMenu = document.getElementById('menu-lateral');
    if (contenedorMenu) contenedorMenu.innerHTML = menuHTML;
}

// ==============================================================================
// 🛡️ ESCUDO GLOBAL FRONTEND: VERIFICADOR DE RUTAS
// ==============================================================================
function verificarAccesoPantalla() {
    const url = window.location.pathname.toLowerCase();
    
    // Ignoramos el login y el panel del superadmin
    if (url.includes('index.html') || url.includes('dashboard_superadmin.html')) return;

    const userDataStr = localStorage.getItem('userData');
    if (!userDataStr) return;
    const modulos = JSON.parse(userDataStr).modulos || {};

    // 🗺️ Mapa de "Pantalla -> Permiso Necesario"
    const mapaSeguridad = {
        'planilla.html': 'planilla',
        'ausencias.html': 'ausencias',
        'calendario.html': 'calendario',
        'feriados.html': 'feriado',
        'lectores.html': 'lectores',
        'organizacion.html': 'organizacion',
        'reporte_dia.html': 'reporte_dia',
        'simulador.html': 'simulador',
        'turnos.html': 'turnos',
        'configuracion.html': 'configuracion'
    };

    // Revisamos en qué página está el usuario y si tiene permiso
    for (const [archivo, moduloRequerido] of Object.entries(mapaSeguridad)) {
        if (url.includes(archivo)) {
            if (modulos[moduloRequerido] === false) {
                // 🚨 ¡Intrusión detectada! Lo pateamos de vuelta al inicio
                Swal.fire({
                    icon: 'warning',
                    title: 'Acceso Denegado',
                    text: 'Su plan actual no incluye el módulo de ' + moduloRequerido.toUpperCase(),
                    allowOutsideClick: false
                }).then(() => {
                    window.location.href = 'dashboard_cliente.html';
                });
            }
        }
    }
}

// Activamos el escudo en cuanto cargue cualquier página
document.addEventListener('DOMContentLoaded', verificarAccesoPantalla);