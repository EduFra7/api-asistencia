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

    if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        empresaNombre = userData.empresa_nombre || userData.empresa || "Empresa"; 
        rol = userData.rol === 'admin' ? 'Administrador' : 'Usuario';
    }

    // ⚡ Clases actualizadas para verse bien en móvil y PC
    const claseActiva = "flex items-center px-3 py-2.5 bg-blue-600 rounded-lg text-white transition-colors shadow-sm text-sm font-medium";
    const claseInactiva = "flex items-center px-3 py-2.5 text-slate-300 hover:bg-slate-800 rounded-lg transition-colors text-sm font-medium";

    const menuHTML = `
        <!-- ⚡ Cabecera con Botón de Cierre (Solo visible en móvil) -->
        <div class="p-4 md:p-6 border-b border-slate-800 flex justify-between items-center shrink-0">
            <div class="min-w-0">
                <h2 class="text-lg font-bold text-blue-400 truncate"><i class="fas fa-fingerprint mr-2"></i>${empresaNombre}</h2>
                <p class="text-[10px] md:text-xs text-slate-400 mt-1 uppercase tracking-wider truncate">${rol}</p>
            </div>
            <button onclick="toggleMenu()" class="xl:hidden text-slate-400 hover:text-white p-2 outline-none">
                <i class="fas fa-times text-xl"></i>
            </button>
        </div>
        
        <div class="flex-1 overflow-y-auto py-4 scrollbar-thin scrollbar-thumb-slate-700">
            <nav class="space-y-1 px-3">
                
                <!-- ── SECCIÓN: ASISTENCIA ── -->
                <div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-2 px-3 ${(pantallaActiva === 'dashboard' || pantallaActiva === 'asistencia') ? 'text-blue-400' : 'text-slate-500'}">Control de Asistencia</div>
                <a href="dashboard_cliente.html" class="${pantallaActiva === 'dashboard' ? claseActiva : claseInactiva}">
                    <i class="fas fa-chart-pie w-5 mr-2 text-center"></i> Dashboard
                </a>
                <a href="calendario.html" class="${pantallaActiva === 'asistencia' ? claseActiva : claseInactiva}">
                    <i class="fas fa-calendar-alt w-5 mr-2 text-center"></i> Calendario
                </a>
                <a href="reporte_dia.html" class="${pantallaActiva === 'reporte' ? claseActiva : claseInactiva}">
                    <i class="fas fa-file-alt w-5 mr-2 text-center"></i> Reporte del Día
                </a>

                <!-- ── SECCIÓN: PLANILLA ── -->
                <div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 ${(pantallaActiva === 'planilla' || pantallaActiva === 'ausencias')? 'text-blue-400' : 'text-slate-500'}">Gestión de Planilla</div>
                <a href="planilla.html" class="${pantallaActiva === 'planilla' ? claseActiva : claseInactiva}">
                    <i class="fas fa-users w-5 mr-2 text-center"></i> Personal
                </a>
                <a href="ausencias.html" class="${pantallaActiva === 'ausencias' ? claseActiva : claseInactiva}">
                    <i class="fas fa-plane-departure w-5 mr-2 text-center"></i> Vacaciones y Permisos
                </a>

                <!-- ── SECCIÓN: ORGANIZACIÓN ── -->
                <div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 ${(pantallaActiva === 'organizacion' || pantallaActiva === 'turnos' || pantallaActiva === 'feriados')? 'text-blue-400' : 'text-slate-500'}">Organización</div>
                <a href="organizacion.html" class="${pantallaActiva === 'organizacion' ? claseActiva : claseInactiva}">
                    <i class="fas fa-sitemap w-5 mr-2 text-center"></i> Sucursales y Secciones
                </a>
                <a href="turnos.html" class="${pantallaActiva === 'turnos' ? claseActiva : claseInactiva}">
                    <i class="fas fa-clock w-5 mr-2 text-center"></i> Horarios y Turnos
                </a>
                <a href="feriados.html" class="${pantallaActiva === 'feriados' ? claseActiva : claseInactiva}">
                    <i class="fas fa-calendar-plus w-5 mr-2 text-center"></i> Feriados
                </a>

                <!-- ── SECCIÓN: AJUSTES ── -->
                <div class="text-[10px] md:text-xs font-bold uppercase tracking-wider mb-2 mt-6 px-3 ${(pantallaActiva === 'ajustes' || pantallaActiva === 'simulador' || pantallaActiva === 'lectores')? 'text-yellow-500' : 'text-slate-500'}">Ajustes (Admin)</div>
                <a href="ajustes.html" class="${pantallaActiva === 'ajustes' ? claseActiva : claseInactiva}">
                    <i class="fas fa-cogs w-5 mr-2 text-center"></i> Configuraciones
                </a>
                <a href="simulador.html" class="${pantallaActiva === 'simulador' ? claseActiva : claseInactiva}">
                    <i class="fas fa-satellite-dish w-5 mr-2 text-center"></i> Simulador ADMS
                </a>
                <a href="lectores.html" class="${pantallaActiva === 'lectores' ? claseActiva : claseInactiva}">
                    <i class="fas fa-fingerprint w-5 mr-2 text-center"></i> Lectores Biométricos
                </a>
                
            </nav>
        </div>
        
        <div class="p-4 border-t border-slate-800 shrink-0">
            <button onclick="cerrarSesion()" class="flex items-center justify-center md:justify-start w-full p-2.5 text-red-400 hover:bg-slate-800 rounded-lg transition-colors text-sm font-bold">
                <i class="fas fa-sign-out-alt w-5 mr-2 text-center"></i> Salir
            </button>
        </div>
    `;

    const contenedorMenu = document.getElementById('menu-lateral');
    if (contenedorMenu) {
        contenedorMenu.innerHTML = menuHTML;
    }
}