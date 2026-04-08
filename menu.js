// ==============================================================================
// 🛡️ INTERCEPTOR GLOBAL DE PETICIONES (SEGURIDAD ANTI-CADUCIDAD)
// ==============================================================================
const originalFetch = window.fetch;

window.fetch = async function() {
    try {
        const response = await originalFetch.apply(this, arguments);
        
        if (response.status === 401) {
            console.warn("⚠️ [SEGURIDAD] Sesión expirada o token inválido. Expulsando usuario...");
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

// ==============================================================================
// 💎 MOTOR GRÁFICO DE NOTIFICACIONES (Reemplazo de alert, confirm, prompt)
// ==============================================================================

// 1. Inyección Dinámica de SweetAlert2 (Para no tener que editar cada HTML)
if (!window.Swal) {
    const swalScript = document.createElement('script');
    swalScript.src = 'https://cdn.jsdelivr.net/npm/sweetalert2@11';
    document.head.appendChild(swalScript);
}

// 2. Configuración del "Toast" (Notificación flotante estilo WhatsApp)
// Esperamos a que la librería cargue para definir el Toast global
let Toast;
window.addEventListener('load', () => {
    Toast = Swal.mixin({
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

// 3. Funciones Globales para usar en todo el ERP
window.mostrarExito = function(mensaje) {
    if(Toast) Toast.fire({ icon: 'success', title: mensaje });
};

window.mostrarError = function(mensaje, titulo = "Operación Denegada") {
    Swal.fire({
        icon: 'error',
        title: titulo,
        text: mensaje,
        confirmButtonColor: '#3b82f6', // blue-500
        confirmButtonText: 'Entendido',
        customClass: { popup: 'rounded-xl shadow-2xl' }
    });
};

// Reemplaza a confirm() - Devuelve true o false
window.pedirConfirmacion = async function(mensaje, titulo = "⚠️ ¿Estás seguro?", textoBoton = "Sí, continuar") {
    const result = await Swal.fire({
        title: titulo,
        text: mensaje,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#ef4444', // red-500 para peligro
        cancelButtonColor: '#94a3b8', // slate-400 para cancelar
        confirmButtonText: textoBoton,
        cancelButtonText: 'Cancelar',
        reverseButtons: true, // Pone el botón de cancelar a la izquierda (UX moderno)
        customClass: { popup: 'rounded-xl shadow-2xl' }
    });
    return result.isConfirmed;
};

// Reemplaza a prompt() - Devuelve el texto escrito o null
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
        customClass: { popup: 'rounded-xl shadow-2xl' }
    });
    return texto; // Será undefined si el usuario cancela
};


// ==============================================================================
// COMPONENTE: MENÚ LATERAL DINÁMICO
// ==============================================================================

function renderizarMenu(pantallaActiva) {
    const userDataStr = localStorage.getItem('userData');
    let empresaNombre = "Cargando...";
    let rol = "Admin";

    if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        empresaNombre = userData.empresa_nombre || userData.empresa || "Empresa"; 
        rol = userData.rol === 'admin' ? 'Administrador' : 'Usuario';
    }

    const claseActiva = "flex items-center px-3 py-2 bg-blue-600 rounded-lg text-white transition-colors shadow-sm";
    const claseInactiva = "flex items-center px-3 py-2 text-slate-300 hover:bg-slate-800 rounded-lg transition-colors";

    const menuHTML = `
        <div class="p-6 border-b border-slate-800">
            <h2 class="text-xl font-bold text-blue-400 truncate"><i class="fas fa-fingerprint mr-2"></i>${empresaNombre}</h2>
            <p class="text-xs text-slate-400 mt-1 uppercase tracking-wider">${rol}</p>
        </div>
        
        <div class="flex-1 overflow-y-auto py-4">
            <nav class="space-y-1 px-3">
                
                <!-- ── SECCIÓN: ASISTENCIA ── -->
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-4 px-3 ${pantallaActiva === 'dashboard' ? 'text-blue-400' : 'text-slate-500'}">Control de Asistencia</div>
                <a href="dashboard_cliente.html" class="${pantallaActiva === 'dashboard' ? claseActiva : claseInactiva}">
                    <i class="fas fa-chart-pie w-5 mr-2"></i> Dashboard
                </a>
                <a href="#" class="${claseInactiva}">
                    <i class="fas fa-calendar-alt w-5 mr-2"></i> Calendario
                </a>
                <a href="#" class="${claseInactiva}">
                    <i class="fas fa-file-alt w-5 mr-2"></i> Reporte del Día
                </a>

                <!-- ── SECCIÓN: PLANILLA ── -->
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-6 px-3 ${(pantallaActiva === 'planilla' || pantallaActiva === 'ausencias')? 'text-blue-400' : 'text-slate-500'}">Gestión de Planilla</div>
                <a href="planilla.html" class="${pantallaActiva === 'planilla' ? claseActiva : claseInactiva}">
                    <i class="fas fa-users w-5 mr-2"></i> Personal
                </a>
                <a href="ausencias.html" class="${pantallaActiva === 'ausencias' ? claseActiva : claseInactiva}">
                    <i class="fas fa-plane-departure w-5 mr-2"></i> Vacaciones y Permisos
                </a>

                <!-- ── SECCIÓN: ORGANIZACIÓN ── -->
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-6 px-3 ${(pantallaActiva === 'organizacion' || pantallaActiva === 'turnos')? 'text-blue-400' : 'text-slate-500'}">Organización</div>
                <a href="organizacion.html" class="${pantallaActiva === 'organizacion' ? claseActiva : claseInactiva}">
                    <i class="fas fa-sitemap w-5 mr-2"></i> Sucursales y Secciones
                </a>
                <a href="turnos.html" class="${pantallaActiva === 'turnos' ? claseActiva : claseInactiva}">
                    <i class="fas fa-clock w-5 mr-3 text-center"></i> Horarios y Turnos
                </a>

                <!-- ── SECCIÓN: AJUSTES ── -->
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-6 px-3 ${pantallaActiva === 'ajustes' ? 'text-yellow-500' : 'text-slate-500'}">Ajustes (Admin)</div>
                <a href="ajustes.html" class="${pantallaActiva === 'ajustes' ? claseActiva : claseInactiva}">
                    <i class="fas fa-cogs w-5 mr-2"></i> Configuraciones
                </a>
                
                <a href="#" class="${claseInactiva}">
                    <i class="fas fa-fingerprint w-5 mr-2"></i> Lectores Biométricos
                </a>
                
            </nav>
        </div>
        
        <div class="p-4 border-t border-slate-800">
            <button onclick="cerrarSesion()" class="flex items-center w-full p-2 text-red-400 hover:bg-slate-800 rounded-lg transition-colors">
                <i class="fas fa-sign-out-alt w-5 mr-2"></i> Salir
            </button>
        </div>
    `;

    const contenedorMenu = document.getElementById('menu-lateral');
    if (contenedorMenu) {
        contenedorMenu.innerHTML = menuHTML;
    }
}