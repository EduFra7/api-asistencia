// ==============================================================================
// COMPONENTE: MENÚ LATERAL DINÁMICO
// Este archivo inyecta el menú en todas las pantallas y gestiona la pestaña activa.
// ==============================================================================

function renderizarMenu(pantallaActiva) {
    // 1. Obtener datos del usuario desde la memoria del navegador
    const userDataStr = localStorage.getItem('userData');
    let empresaNombre = "Cargando...";
    let rol = "Admin";

    if (userDataStr) {
        const userData = JSON.parse(userDataStr);
        // Soporte para variables antiguas y nuevas
        empresaNombre = userData.empresa_nombre || userData.empresa || "Empresa"; 
        rol = userData.rol === 'admin' ? 'Administrador' : 'Usuario';
    }

    // 2. Definir las clases CSS (Estilos) para cuando un botón está presionado o suelto
    const claseActiva = "flex items-center px-3 py-2 bg-blue-600 rounded-lg text-white transition-colors shadow-sm";
    const claseInactiva = "flex items-center px-3 py-2 text-slate-300 hover:bg-slate-800 rounded-lg transition-colors";

    // 3. Construir el bloque de HTML del Menú
    const menuHTML = `
        <div class="p-6 border-b border-slate-800">
            <h2 class="text-xl font-bold text-blue-400 truncate"><i class="fas fa-fingerprint mr-2"></i>${empresaNombre}</h2>
            <p class="text-xs text-slate-400 mt-1 uppercase tracking-wider">${rol}</p>
        </div>
        
        <div class="flex-1 overflow-y-auto py-4">
            <nav class="space-y-1 px-3">
                
                <!-- ── SECCIÓN: ASISTENCIA ── -->
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-4 px-3 uppercase tracking-wider mb-2 mt-6 px-3 ${pantallaActiva === 'dashboard' ? 'text-blue-400' : 'text-slate-500'}">Control de Asistencia</div>
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
                <div class="text-xs font-semibold uppercase tracking-wider mb-2 mt-6 px-3 ${pantallaActiva === 'planilla' ? 'text-blue-400' : 'text-slate-500'}">Gestión de Planilla</div>
                <a href="planilla.html" class="${pantallaActiva === 'planilla' ? claseActiva : claseInactiva}">
                    <i class="fas fa-users w-5 mr-2"></i> Personal
                </a>
                <a href="#" class="${claseInactiva}">
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

    // 4. Inyectar este HTML dentro del contenedor vacío en la pantalla actual
    const contenedorMenu = document.getElementById('menu-lateral');
    if (contenedorMenu) {
        contenedorMenu.innerHTML = menuHTML;
    } else {
        console.error("No se encontró el <aside id='menu-lateral'> en esta página.");
    }
}