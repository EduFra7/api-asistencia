# ==============================================================================
# 1. IMPORTACIÓN DE LIBRERÍAS (Las herramientas que usamos)
# ==============================================================================

# -- Framework Web (FastAPI) --
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer

# -- Manejo de Tiempo y Fechas (Nativas y Externas) --
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta  # Instalado vía pip

# -- Seguridad y Base de Datos --
import psycopg2          # Librería para hablar con PostgreSQL (Supabase)
import psycopg2.extras   # Herramientas extra para PostgreSQL (como diccionarios)
import bcrypt            # Librería para encriptar contraseñas
import jwt               # Librería para generar "Tokens" de sesión

# -- Utilidades del Sistema --
from dotenv import load_dotenv
import os                # Librería para leer variables del sistema operativo
import re                # Librería para buscar y limpiar textos (Expresiones regulares)
import json              # Asegúrate de que esto esté al inicio de tu main.py

# ==============================================================================
# 2. CONFIGURACIÓN INICIAL DE LA APLICACIÓN
# ==============================================================================
# load_dotenv() busca un archivo llamado '.env' y carga sus variables secretas.
load_dotenv() 

# app = FastAPI() es la línea más importante. Crea el servidor web.
app = FastAPI()

# ── CORS (Cross-Origin Resource Sharing) ──
# El CORS es un guardia de seguridad del navegador. Por defecto, un navegador no 
# permite que una web (index.html) pida datos a una API que está en otra dirección.
# Al poner allow_origins=["*"], le decimos a la API: "Acepta peticiones de cualquier página web".
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Obtenemos la llave maestra para firmar tokens. Si no existe en el .env, usa una por defecto.
SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_cambiar_en_produccion")


# ==============================================================================
# 3. FUNCIONES CORE (Funciones que se reutilizan en todo el código)
# ==============================================================================

# ── CONEXIÓN DINÁMICA A LA BASE DE DATOS ──
def conectar_bd(schema_name="public"):
    """
    Esta función abre el puente entre Python y Supabase.
    El parámetro 'schema_name' es crucial para el multitenant: le dice a la base de datos
    a qué "carpeta" privada debe entrar antes de buscar tablas.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL no encontrada")
    
    # search_path es un comando de PostgreSQL que le indica qué esquema usar.
    return psycopg2.connect(url, options=f"-c search_path={schema_name}")


# ── VERIFICACIÓN DE IDENTIDAD (MIDDLEWARE DE SEGURIDAD) ──
def verificar_token(request: Request):
    """
    Cada vez que un usuario intenta entrar a una ruta protegida (ej. crear empresa),
    esta función intercepta la petición, busca el 'token' en la cabecera, 
    y lo descifra para ver quién es.
    """
    # Extraemos el token que el frontend manda oculto en las cabeceras.
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    
    try:
        # jwt.decode() intenta abrir el token con nuestra llave maestra.
        # Si alguien alteró el token, la firma no coincidirá y fallará.
        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return datos # Retorna el diccionario con los datos del usuario (id, rol, schema, etc.)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado. Inicie sesión de nuevo.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido o manipulado.")


# ==============================================================================
# 4. RUTAS O ENDPOINTS (Las "puertas" de tu servidor)
# ==============================================================================

# ── SISTEMA DE LOGIN ──
# @app.post significa que esta ruta espera recibir datos (en este caso, email y password)
@app.post("/auth/login")
async def login(request: Request):
    # 'async' permite que el servidor no se congele mientras espera datos.
    try:
        data     = await request.json() # Leemos los datos que mandó el navegador
        email    = data.get("email", "").strip().lower()
        password = data.get("password", "")

        # 1. Buscamos al usuario siempre en la tabla global ('public')
        conn = conectar_bd("public")
        # RealDictCursor hace que los resultados salgan como diccionarios {"nombre": "Juan"}
        # en lugar de simples tuplas ("Juan",)
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Hacemos un JOIN para traer tanto los datos del usuario como el esquema de su empresa
        cur.execute("""
            SELECT u.*, e.nombre as empresa_nombre, e.schema_name
            FROM usuarios u
            JOIN empresas e ON e.id = u.empresa_id
            WHERE u.email = %s AND u.activo = TRUE
        """, (email,))
        usuario = cur.fetchone() # Trae el primer resultado encontrado
        cur.close()
        conn.close()

        # 2. Validaciones de seguridad
        if not usuario:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        # bcrypt.checkpw() compara la contraseña que escribió el usuario con el hash raro de la BD.
        if not bcrypt.checkpw(password.encode(), usuario["password_hash"].encode()):
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        # 3. Creación del "Pasaporte" (Token JWT)
        # Este token viaja al navegador y es la única prueba de que el usuario ya inició sesión.
        token = jwt.encode({
            "id":             usuario["id"],
            "email":          usuario["email"],
            "rol":            usuario["rol"],
            "empresa_id":     usuario["empresa_id"],
            "schema_name":    usuario["schema_name"], # Esto es vital para saber a qué esquema enviarlo luego
            "empresa_nombre": usuario["empresa_nombre"],
            "exp":            datetime.utcnow() + timedelta(hours=8) # El token caduca en 8 horas
        }, SECRET_KEY, algorithm="HS256")

        # Devolvemos el token y los datos básicos para que el frontend arme la interfaz
        return {
            "token":          token,
            "nombre":         usuario["nombre"],
            "rol":            usuario["rol"],
            "empresa_nombre": usuario["empresa_nombre"],
            "schema_name":    usuario["schema_name"]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── RUTA DE PRUEBA DE IDENTIDAD ──
# Observa el 'Depends(verificar_token)'. Esto fuerza a que la función verificar_token()
# se ejecute ANTES de entrar a esta ruta. Si el token falla, nunca llega aquí.
@app.get("/auth/me")
def mi_perfil(usuario = Depends(verificar_token)):
    return usuario # Devuelve lo que la función verificar_token descifró


# ── MOTOR DE APROVISIONAMIENTO (CREAR EMPRESAS NUEVAS) ──
@app.post("/empresas")
async def crear_empresa(request: Request, usuario = Depends(verificar_token)):
    # 1. Filtro de seguridad: ¿Es el dueño del sistema?
    if usuario["rol"] != "superadmin":
        raise HTTPException(status_code=403, detail="Sin permisos. Solo SuperAdmin.")
    
    try:
        data = await request.json()
        nombre         = data.get("nombre")
        admin_nombre   = data.get("admin_nombre")
        admin_email    = data.get("admin_email")
        admin_password = data.get("admin_password")

        # 2. Preparar un nombre seguro para el esquema en PostgreSQL (sin espacios ni símbolos)
        schema_limpio = re.sub(r'[^a-z0-9_]', '', nombre.lower().replace(' ', '_'))
        schema_name   = f"empresa_{schema_limpio}" 

        # Encriptamos la contraseña del cliente antes de guardarla
        password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()

        conn = conectar_bd("public")
        # autocommit=True es necesario porque PostgreSQL no deja crear esquemas dentro de una "transacción" normal.
        conn.autocommit = True 
        cur  = conn.cursor()

        # 3. Guardar en el directorio maestro de empresas
        cur.execute(
            "INSERT INTO empresas (nombre, schema_name) VALUES (%s, %s) RETURNING id",
            (nombre, schema_name)
        )
        empresa_id = cur.fetchone()[0] # Obtenemos el ID que se le asignó

        # 4. Crear al Administrador principal de este nuevo cliente
        cur.execute("""
            INSERT INTO usuarios (empresa_id, nombre, email, password_hash, rol)
            VALUES (%s, %s, %s, %s, 'admin')
        """, (empresa_id, admin_nombre, admin_email, password_hash))

        # 5. LA MAGIA: Crear el esquema y sus tablas privadas (VERSIÓN 2.0)
        from psycopg2 import sql
        
        # ATENCIÓN: El orden de creación importa. Primero los catálogos (sin dependencias), 
        # luego los empleados, y al final los eventos.
        script_sql = sql.SQL("""
            CREATE SCHEMA {schema};

            -- ==========================================
            -- 1. TABLAS DE CATÁLOGOS (Datos Fijos)
            -- ==========================================
            CREATE TABLE {schema}.sucursales (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                direccion TEXT,
                telefono VARCHAR(50) DEFAULT '',
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                eliminado BOOLEAN DEFAULT FALSE
            );

            -- ¡NUEVA TABLA DE SECCIONES!
            CREATE TABLE {schema}.secciones (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                descripcion TEXT,
                estado BOOLEAN DEFAULT TRUE,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                eliminado BOOLEAN DEFAULT FALSE
            );
             
            CREATE TABLE {schema}.turnos (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                hora_ingreso TIME NOT NULL,
                hora_salida TIME NOT NULL,
                dias JSONB NOT NULL,
                almuerzo BOOLEAN DEFAULT FALSE,
                hora_inicio_almuerzo TIME,       -- ⚡ NUEVO
                hora_fin_almuerzo TIME,          -- ⚡ NUEVO
                almuerzo_min INTEGER DEFAULT 0,
                tolerancia BOOLEAN DEFAULT FALSE,
                tolerancia_min INTEGER DEFAULT 0,
                tolerancia_mensual_min INTEGER DEFAULT 0,
                descuento BOOLEAN DEFAULT TRUE,
                horas_extras BOOLEAN DEFAULT FALSE,
                medio_tiempo_fines BOOLEAN DEFAULT FALSE
                eliminado BOOLEAN DEFAULT FALSE
            )

            -- ==========================================
            -- 2. TABLA PRINCIPAL DE EMPLEADOS (Planilla)
            -- ==========================================
            CREATE TABLE {schema}.empleados (
                id SERIAL PRIMARY KEY,
                bio_id INT UNIQUE,                     -- ID Numérico del Lector Biométrico
                foto_perfil TEXT,                      -- ⚡ NUEVO: CAMPO PARA LA FOTO BASE64
                nombres VARCHAR(100) NOT NULL,
                apellidos VARCHAR(100) NOT NULL,
                ci VARCHAR(30) UNIQUE NOT NULL,        -- Carnet de Identidad (único)
                sexo VARCHAR(20),
                celular VARCHAR(20),
                correo VARCHAR(100),
                direccion TEXT,
                fecha_ingreso DATE,
                fecha_antiguedad DATE,                 -- Para cálculo de vacaciones/bonos
                cargo VARCHAR(100),                    -- Texto libre (apoyado por el datalist del HTML)
                sucursal_id INT REFERENCES {schema}.sucursales(id), -- Conexión Física
                seccion_id INT REFERENCES {schema}.secciones(id),   -- ¡NUEVA! Conexión Lógica
                tipo_contrato VARCHAR(50),
                turno_id INT REFERENCES {schema}.turnos(id),      -- Conexión a su horario
                salario_base NUMERIC(10, 2) DEFAULT 0.00,           -- Permite decimales (Ej. 2500.50)
                bono NUMERIC(10, 2) DEFAULT 0.00,
                
                -- Control de Estado (Soft Delete y Bajas)
                activo BOOLEAN DEFAULT TRUE,           -- El interruptor principal
                fecha_retiro DATE,                     -- Se llena solo si activo pasa a FALSE
                motivo_retiro TEXT,
                eliminado BOOLEAN DEFAULT FALSE,       -- Para el botón "Eliminar" (Borrado Lógico)
                
                huella_template TEXT,                  -- Aquí guardaremos el string de la huella dactilar
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                historial_movimientos TEXT DEFAULT ''   -- Caja negra de registro de movimiento
            );

            -- ==========================================
            -- 3. TABLAS DE HARDWARE Y ASISTENCIA
            -- ==========================================
            CREATE TABLE {schema}.eventos_brutos (
                id SERIAL PRIMARY KEY,
                device_no VARCHAR(50),                 -- Número de serie del reloj ZKTeco
                item VARCHAR(50),                      -- El bio_id del empleado que marcó
                verify_mode VARCHAR(20),               -- Huella, Tarjeta, Rostro o Clave
                action VARCHAR(20),                    -- Entrada, Salida, etc.
                fecha_hora TIMESTAMP,                  -- El momento exacto del marcaje
                raw_data JSONB,                        -- El paquete de datos original por si hay que depurar
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
                             
            -- ⚡ NUEVA TABLA MAESTRA DE CÁLCULO DIARIO ⚡
            CREATE TABLE {schema}.asistencia_diaria (
                id SERIAL PRIMARY KEY, -- Usamos SERIAL para mantener el estándar de tu BD
                empleado_id INT REFERENCES {schema}.empleados(id) NOT NULL,
                fecha DATE NOT NULL,
                turno_id INT REFERENCES {schema}.turnos(id), 
                
                -- Marcajes limpios
                hora_entrada TIME,
                hora_inicio_almuerzo TIME,
                hora_fin_almuerzo TIME,
                hora_salida TIME,
                
                -- Desglose de Cálculos
                minutos_retraso_entrada INT DEFAULT 0,
                minutos_exceso_almuerzo INT DEFAULT 0,
                minutos_salida_temprano INT DEFAULT 0,
                horas_trabajadas NUMERIC(5,2) DEFAULT 0.00,
                
                -- Veredicto y Finanzas
                estado VARCHAR(20) NOT NULL DEFAULT 'Incompleto', 
                deuda_generada_bs NUMERIC(10, 2) DEFAULT 0.00, 
                
                -- Auditoría
                modificado_manualmente BOOLEAN DEFAULT FALSE,
                observaciones TEXT,
                actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(empleado_id, fecha) -- Evita duplicados del mismo día
            );

            CREATE TABLE {schema}.asistencia (
                id SERIAL PRIMARY KEY,
                empleado_id INT REFERENCES {schema}.empleados(id),
                fecha DATE,
                hora_marcaje TIMESTAMP,
                tipo VARCHAR(20),                      -- Ej: 'Entrada_Normal', 'Salida_Almuerzo'
                estado VARCHAR(20),                    -- Ej: 'A_Tiempo', 'Retraso', 'Falta'
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
                             
            -- ⚡ ¡AQUÍ AGREGAMOS LA TABLA QUE FALTABA PARA LAS VACACIONES! ⚡
            CREATE TABLE {schema}.ausencias (
                id SERIAL PRIMARY KEY,
                empleado_id INT REFERENCES {schema}.empleados(id) NOT NULL,
                tipo VARCHAR(20) NOT NULL,
                fecha_inicio DATE NOT NULL,
                fecha_fin DATE NOT NULL,
                hora_inicio TIME,
                hora_fin TIME,
                horas_totales NUMERIC(5,2) DEFAULT 0.00,
                dias_descontados NUMERIC(5,2) DEFAULT 0.00,
                motivo TEXT,
                requiere_reposicion BOOLEAN DEFAULT FALSE,
                estado VARCHAR(20) DEFAULT 'aprobado',
                eliminado BOOLEAN DEFAULT FALSE,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """).format(schema=sql.Identifier(schema_name))

        cur.execute(script_sql) # Ejecutamos todo el bloque para crear la empresa

        cur.close()
        conn.close()

        return {
            "mensaje": "Empresa aprovisionada correctamente", 
            "empresa_id": empresa_id, 
            "schema_name": schema_name
        }

    except psycopg2.errors.DuplicateSchema:
        raise HTTPException(status_code=400, detail="Ya existe una empresa con un nombre similar")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


# ── LISTAR EMPRESAS ──
@app.get("/empresas")
def ver_empresas(usuario = Depends(verificar_token)):
    if usuario["rol"] != "superadmin":
        raise HTTPException(status_code=403, detail="Sin permisos")
    
    conn = conectar_bd("public")
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM empresas ORDER BY creado_en DESC")
    empresas = cur.fetchall()
    cur.close()
    conn.close()
    return list(empresas)


# ── SETUP INICIAL (CREAR TU CUENTA) ──
@app.get("/setup/superadmin")
def crear_superadmin():
    """Esta ruta se usa solo una vez para crear al dueño del sistema."""
    try:
        password_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        conn = conectar_bd("public")
        cur  = conn.cursor()
        
        # ON CONFLICT DO NOTHING evita que el código se rompa si "Sistema" ya existe
        cur.execute("INSERT INTO empresas (id, nombre, schema_name) VALUES (1, 'Sistema', 'public') ON CONFLICT (id) DO NOTHING")
        
        cur.execute("""
            INSERT INTO usuarios (empresa_id, nombre, email, password_hash, rol)
            VALUES (1, 'Super Admin', 'admin@sistema.com', %s, 'superadmin')
            ON CONFLICT (email) DO UPDATE SET password_hash = %s
        """, (password_hash, password_hash))
        
        conn.commit() # Guardar cambios en la base de datos
        cur.close()
        conn.close()
        return {"mensaje": "Superadmin creado. Email: admin@sistema.com / Pass: admin123"}
    except Exception as e:
        return {"error": str(e)}


# ==============================================================================
# 5. RUTAS PARA COMUNICACIÓN CON HARDWARE (ZKTeco ADMS)
# ==============================================================================

# ── INICIALIZACIÓN DEL LECTOR ZKTECO ──
# Cuando un lector ZK se conecta a internet, busca esta ruta constantemente (GET).
@app.get("/iclock/cdata")
async def iclock_init(request: Request):
    sn = request.query_params.get("SN", "") # Extrae el Número de Serie del lector
    print(f"✅ Lector conectado SN={sn}")
    
    # El lector espera instrucciones en texto plano, no en JSON.
    return PlainTextResponse(
        f"GET OPTION FROM: {sn}\n"
        "ATTLOGStamp=None\nOPERLOGStamp=9999\n"
        "Realtime=1\nEncrypt=None\n"
    )

# ── RECEPCIÓN DE MARCAJES DEL LECTOR ──
# Cuando alguien pone su huella, el lector envía los datos a esta ruta (POST).
@app.post("/iclock/cdata")
async def iclock_data(request: Request):
    table = request.query_params.get("table", "") # Nos dice qué tipo de dato envía (ej. ATTLOG = marcaje)
    sn    = request.query_params.get("SN", "")
    body  = await request.body()
    texto = body.decode("utf-8", errors="ignore")
    
    # TODO: En el futuro, tendremos que modificar esto para que busque a qué cliente (esquema) 
    # pertenece este Número de Serie (SN) y guarde el evento en la carpeta correcta.
    if table == "ATTLOG":
        for linea in texto.strip().splitlines():
            partes = linea.strip().split("\t")
            if len(partes) >= 2:
                try:
                    conn = conectar_bd("public") # Temporalmente guarda todo en 'public'
                    cur  = conn.cursor()
                    cur.execute("""
                        INSERT INTO eventos_brutos
                            (device_no, item, verify_mode, action, fecha_hora, raw_data)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (sn, partes[0], partes[3] if len(partes)>3 else "1",
                          partes[2] if len(partes)>2 else "0",
                          partes[1], psycopg2.extras.Json({"raw": linea})))
                    conn.commit()
                    cur.close()
                    conn.close()
                except Exception as e:
                    print(f"❌ {e}")
                    
    return PlainTextResponse("OK") # Siempre hay que decirle "OK" al lector o se asustará y reenviará el dato.

# ==============================================================================
# 6. RUTA PARA ELIMINAR UNA EMPRESA (SOLO SUPERADMIN) ──
# ==============================================================================

@app.delete("/empresas/{empresa_id}")
def eliminar_empresa(empresa_id: int, usuario = Depends(verificar_token)):
    # 1. SEGURIDAD: Verificamos usando tu propia función de seguridad
    if usuario.get("rol") != "superadmin":
        raise HTTPException(status_code=403, detail="Acceso denegado. Solo SuperAdmin puede eliminar empresas.")

    # 2. Conectamos a la base de datos maestra (public)
    conn = conectar_bd("public")
    cur = conn.cursor()
    
    try:
        # 3. BUSCAR EL OBJETIVO: Obtenemos el nombre del esquema (carpeta) de esa empresa
        cur.execute("SELECT schema_name FROM empresas WHERE id = %s", (empresa_id,))
        empresa = cur.fetchone()
        
        if not empresa:
            raise HTTPException(status_code=404, detail="La empresa no existe.")
            
        schema_name = empresa[0] # Extraemos el texto, ej: "empresa_industrias_prueba"

        # 4. LA EXPLOSIÓN CONTROLADA (DROP SCHEMA CASCADE)
        from psycopg2 import sql
        cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema_name)))
        
        # 5. LIMPIEZA DE RASTROS
        cur.execute("DELETE FROM usuarios WHERE empresa_id = %s", (empresa_id,))
        cur.execute("DELETE FROM empresas WHERE id = %s", (empresa_id,))
        
        # 6. CONFIRMAR CAMBIOS
        conn.commit()
        
        return {"mensaje": f"La empresa y toda su información fueron eliminadas de raíz."}
        
    except Exception as e:
        conn.rollback() # Si algo falla, cancelamos la explosión
        raise HTTPException(status_code=500, detail=f"Error al eliminar: {str(e)}")
    finally:
        cur.close()
        conn.close()

# ==============================================================================
# 7. RUTAS DE CATÁLOGOS (ESTRUCTURA ORGANIZACIONAL Y TIEMPO)
# ==============================================================================

# ------------------------------------------------------------------------------
# A. SUCURSALES (Físico)
# ------------------------------------------------------------------------------
@app.get("/sucursales")
def obtener_sucursales(usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"SELECT * FROM {schema}.sucursales WHERE eliminado = FALSE ORDER BY nombre")
    sucursales = cur.fetchall()
    cur.close()
    conn.close()
    return list(sucursales)

@app.post("/sucursales")
async def crear_sucursal(data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # Asegúrate de que el query tenga 3 campos y 3 %s
        cur.execute(f"""
            INSERT INTO {schema}.sucursales (nombre, direccion, telefono) 
            VALUES (%s, %s, %s)
        """, (
            data.get("nombre"), 
            data.get("direccion"), 
            data.get("telefono", "") # Capturamos el teléfono
        ))
        conn.commit()
        return {"mensaje": "Sucursal creada exitosamente"}
    except Exception as e:
        conn.rollback()
        # Esto imprimirá el error real en los logs de Railway
        print(f"ERROR CRÍTICO EN POST SUCURSALES: {e}") 
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

# --- RUTA PARA ACTUALIZAR SUCURSAL (EDICIÓN) ---
@app.put("/sucursales/{sucursal_id}")
async def actualizar_sucursal(sucursal_id: int, data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # Ejecutamos la actualización de los 3 campos principales
        cur.execute(f"""
            UPDATE {schema}.sucursales 
            SET nombre = %s, direccion = %s, telefono = %s 
            WHERE id = %s
        """, (
            data.get("nombre"), 
            data.get("direccion"), 
            data.get("telefono", ""), 
            sucursal_id
        ))
        
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sucursal no encontrada")
            
        conn.commit()
        return {"mensaje": "Sucursal actualizada correctamente"}
    except Exception as e:
        conn.rollback()
        print(f"Error al actualizar sucursal: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/sucursales/{sucursal_id}")
def eliminar_sucursal(sucursal_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # Soft Delete: En lugar de borrar la fila, la ocultamos de la interfaz
        cur.execute(f"UPDATE {schema}.sucursales SET eliminado = TRUE WHERE id = %s", (sucursal_id,))
        conn.commit()
        return {"mensaje": "Sucursal eliminada correctamente"}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Operación denegada: No puedes eliminar esta sucursal porque existen empleados registrados (activos o inactivos) asignados a ella. Transfiérelos a otra sucursal primero.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# B. SECCIONES (Lógico)
# ------------------------------------------------------------------------------
@app.get("/secciones")
def obtener_secciones(usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f"SELECT * FROM {schema}.secciones WHERE eliminado = FALSE ORDER BY nombre")
    secciones = cur.fetchall()
    cur.close()
    conn.close()
    return list(secciones)

@app.post("/secciones")
async def crear_seccion(request: Request, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    data = await request.json()
    nombre = data.get("nombre")
    descripcion = data.get("descripcion", "")
    
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(
            f"INSERT INTO {schema}.secciones (nombre, descripcion) VALUES (%s, %s) RETURNING id",
            (nombre, descripcion)
        )
        nuevo_id = cur.fetchone()[0]
        conn.commit()
        return {"mensaje": "Sección registrada con éxito", "id": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# --- RUTA PARA ACTUALIZAR SECCIÓN (EDICIÓN) ---
@app.put("/secciones/{seccion_id}")
async def actualizar_seccion(seccion_id: int, data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            UPDATE {schema}.secciones 
            SET nombre = %s, descripcion = %s 
            WHERE id = %s
        """, (
            data.get("nombre"), 
            data.get("descripcion"), 
            seccion_id
        ))
        
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sección no encontrada")
            
        conn.commit()
        return {"mensaje": "Sección actualizada correctamente"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/secciones/{seccion_id}")
def eliminar_seccion(seccion_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(f"UPDATE {schema}.secciones SET eliminado = TRUE WHERE id = %s", (seccion_id,))
        conn.commit()
        return {"mensaje": "Sección eliminada correctamente"}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Operación denegada: No puedes eliminar esta sección (departamento) porque tienes personal asignado a la misma. Reasigna al personal primero.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ==============================================================================
# 8. GESTIÓN DE PLANILLA (EMPLEADOS)
# ==============================================================================

@app.get("/empleados")
async def obtener_empleados(usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # ⚡ AHORA TRAEMOS HORA_INGRESO, HORA_SALIDA Y ALMUERZO DEL TURNO
        cur.execute(f"""
            SELECT e.*, 
                   s.nombre as sucursal_nombre, 
                   sec.nombre as seccion_nombre,
                   t.nombre as turno_nombre,
                   t.hora_ingreso as turno_ingreso,
                   t.hora_salida as turno_salida,
                   t.almuerzo as turno_almuerzo,
                   t.almuerzo_min as turno_almuerzo_min,
                   (SELECT tipo 
                    FROM {schema}.ausencias a 
                    WHERE a.empleado_id = e.id 
                      AND a.estado = 'aprobado' 
                      AND a.eliminado = FALSE 
                      AND CURRENT_DATE BETWEEN a.fecha_inicio AND a.fecha_fin 
                    LIMIT 1) as estado_ausencia
            FROM {schema}.empleados e
            LEFT JOIN {schema}.sucursales s ON e.sucursal_id = s.id
            LEFT JOIN {schema}.secciones sec ON e.seccion_id = sec.id
            LEFT JOIN {schema}.turnos t ON e.turno_id = t.id
            WHERE e.eliminado = FALSE
            ORDER BY e.id ASC
        """)
        empleados = cur.fetchall()
        # Convertimos las horas a string para evitar errores JSON
        for emp in empleados:
            if emp: emp = str(emp)
            if emp: emp = str(emp)
        return empleados
    finally:
        cur.close()
        conn.close()

@app.post("/empleados")
async def registrar_empleado(request: Request, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    data = await request.json()
    
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        ci = data.get("ci")
        bio_id = data.get("bio_id") or None
        turno_id_raw = data.get("turno_id")
        turno_id_final = int(turno_id_raw) if turno_id_raw else None
        
        # ⚡ Capturamos la foto Base64 enviada por el frontend
        foto_perfil = data.get("foto_perfil") 

        cur.execute(f"SELECT id, eliminado FROM {schema}.empleados WHERE ci = %s", (ci,))
        existe = cur.fetchone()

        if existe:
            id_db, esta_eliminado = existe
            if not esta_eliminado:
                # ⚡ ALERTA MEJORADA (409)
                raise HTTPException(status_code=409, detail="ERROR: Ese C.I. ya existe. Si fue retirado, búscalo en 'Inactivos' y cámbialo a 'Activo'.")
            else:
                cur.execute(f"""
                    UPDATE {schema}.empleados 
                    SET bio_id = %s, foto_perfil = %s, nombres = %s, apellidos = %s, 
                        sucursal_id = %s, seccion_id = %s, cargo = %s, turno_id = %s,
                        eliminado = FALSE, activo = TRUE
                    WHERE id = %s
                """, (bio_id, foto_perfil, data.get("nombres"), data.get("apellidos"), 
                      data.get("sucursal_id"), data.get("seccion_id"), data.get("cargo"), turno_id_final, id_db))
                msg = "Empleado reactivado correctamente."
        else:
            cur.execute(f"""
            INSERT INTO {schema}.empleados 
            (bio_id, foto_perfil, nombres, apellidos, ci, sucursal_id, seccion_id, cargo, turno_id, activo,
             sexo, celular, correo, direccion, fecha_ingreso, fecha_antiguedad, tipo_contrato, salario_base, bono) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            bio_id, 
            foto_perfil,          # ⚡ Inyectamos la foto aquí
            data.get("nombres"), 
            data.get("apellidos"), 
            ci, 
            data.get("sucursal_id"), 
            data.get("seccion_id"), 
            data.get("cargo"), 
            turno_id_final,       
            True,                 
            data.get("sexo"), 
            data.get("celular"), 
            data.get("correo"), 
            data.get("direccion"),
            data.get("fecha_ingreso"), 
            data.get("fecha_antiguedad"), 
            data.get("tipo_contrato"),
            data.get("salario_base", 0), 
            data.get("bono", 0)   
        ))
            msg = "Personal registrado con éxito."

        conn.commit()
        return {"mensaje": msg}
        
    except psycopg2.IntegrityError:
        conn.rollback()
        # ⚡ ALERTA MEJORADA (409)
        raise HTTPException(status_code=409, detail="El ID Biométrico ya está ocupado por otro empleado activo.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.put("/empleados/{empleado_id}")
async def actualizar_empleado(empleado_id: int, request: Request, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    data = await request.json()
    
    # --- 1. SEGURIDAD ESTRICTA: VERIFICAR CONTRASEÑA DE BAJA ---
    activo_nuevo = data.get("activo", True)
    
    if not activo_nuevo: # Si la orden es "Apagar" al empleado
        admin_password = data.get("admin_password")
        if not admin_password:
            raise HTTPException(status_code=409, detail="Contraseña de administrador requerida para ejecutar la baja.")
        
        # Conectamos a la base maestra para ver la contraseña del usuario que está intentando hacer esto
        conn_pub = conectar_bd("public")
        cur_pub = conn_pub.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur_pub.execute("SELECT password_hash FROM usuarios WHERE id = %s", (usuario["id"],))
        user_db = cur_pub.fetchone()
        cur_pub.close()
        conn_pub.close()

        # Comparamos la contraseña digitada contra el Hash de la Base de Datos
        if not user_db or not bcrypt.checkpw(admin_password.encode(), user_db["password_hash"].encode()):
            raise HTTPException(status_code=409, detail="Contraseña incorrecta. Operación de baja denegada.")

    # --- 2. ACTUALIZACIÓN Y CAJA NEGRA ---
    conn = conectar_bd(schema)
    cur = conn.cursor()
    # --- 2. ACTUALIZACIÓN Y CAJA NEGRA ---
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # A. Consultamos el estado ACTUAL antes de guardar los cambios
        cur.execute(f"SELECT activo, fecha_retiro, motivo_retiro, historial_movimientos, foto_perfil FROM {schema}.empleados WHERE id = %s", (empleado_id,))
        estado_db = cur.fetchone()
        
        activo_actual = estado_db[0]
        historial_existente = estado_db[3] or ""
        foto_actual_bd = estado_db[4] # Guardamos la foto que ya existe
        nuevo_historial = historial_existente
        
        fecha_retiro_final = data.get("fecha_retiro")
        motivo_retiro_final = data.get("motivo_retiro")
        
        fecha_auditoria = datetime.now().strftime("%Y-%m-%d")

        # B. LÓGICA DE AUDITORÍA (CAJA NEGRA)
        if not activo_actual and activo_nuevo:
            # CASO: RECONTRATACIÓN
            old_fecha = estado_db[1] or "Desconocida"
            old_motivo = estado_db[2] or "Sin motivo especificado"
            if old_fecha != "Desconocida":
                anotacion = f"RECONTRATADO EL {fecha_auditoria}: Su baja anterior fue el {old_fecha} por '{old_motivo}'.\n"
                nuevo_historial = anotacion + historial_existente
            
            fecha_retiro_final = None
            motivo_retiro_final = None

        elif activo_actual and not activo_nuevo:
            # CASO: DESPIDO / RETIRO
            anotacion = f"➤ [DADO DE BAJA EL {fecha_auditoria}]: Motivo registrado: {motivo_retiro_final}.\n"
            nuevo_historial = anotacion + historial_existente

        # ⚡ BLINDAJE DE FOTO UNIFICADO (El embudo perfecto)
        foto_perfil = data.get("foto_perfil")
        
        if foto_perfil == "ELIMINAR":
            foto_a_guardar = None  # 1. El usuario hizo clic en la 'X' roja, limpiamos la foto
        elif foto_perfil:
            foto_a_guardar = foto_perfil  # 2. El usuario subió una cámara/archivo nuevo
        else:
            foto_a_guardar = foto_actual_bd  # 3. El usuario no tocó nada, conservamos la que ya estaba en BD

        # C. GUARDAMOS TODO EN POSTGRESQL EN UNA SOLA PETICIÓN
        cur.execute(f"""
            UPDATE {schema}.empleados 
            SET bio_id = %s, nombres = %s, apellidos = %s, ci = %s, 
                sucursal_id = %s, seccion_id = %s, cargo = %s, activo = %s,
                sexo = %s, celular = %s, correo = %s, direccion = %s,
                fecha_ingreso = %s, fecha_antiguedad = %s, tipo_contrato = %s, 
                salario_base = %s, bono = %s,
                fecha_retiro = %s, motivo_retiro = %s,
                turno_id = %s,
                historial_movimientos = %s,
                foto_perfil = %s
            WHERE id = %s
        """, (
            data.get("bio_id"), data.get("nombres"), data.get("apellidos"), 
            data.get("ci"), data.get("sucursal_id"), data.get("seccion_id"), 
            data.get("cargo"), activo_nuevo,
            data.get("sexo"), data.get("celular"), data.get("correo"), data.get("direccion"),
            data.get("fecha_ingreso"), data.get("fecha_antiguedad"), data.get("tipo_contrato"),
            data.get("salario_base", 0), data.get("bono", 0),
            fecha_retiro_final, motivo_retiro_final,
            data.get("turno_id"),
            nuevo_historial,
            foto_a_guardar, # ⚡ Aquí entra nuestra variable ya definida y procesada
            empleado_id
        ))
        
        conn.commit()
        return {"mensaje": "Perfil actualizado y bitácora registrada con éxito."}
        
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="El C.I. o ID Biométrico ya está siendo usado por otro empleado en el sistema.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/empleados/{empleado_id}")
async def eliminar_empleado(empleado_id: int, request: Request, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # TRUCO SENIOR: Renombramos el CI para liberarlo y ponemos bio_id en NULL
        cur.execute(f"""
            UPDATE {schema}.empleados 
            SET eliminado = TRUE, 
                activo = FALSE, 
                bio_id = NULL,
                ci = ci || '-DEL-' || id  -- Agrega "-DEL-ID" al carnet para liberar el número original
            WHERE id = %s
        """, (empleado_id,))
        
        conn.commit()
        return {"mensaje": "Registro de prueba eliminado. C.I. y ID Biométrico liberados."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ==========================================
# 9. MÓDULO: TURNOS Y HORARIOS
# ==========================================

@app.get("/turnos")
async def obtener_turnos(usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f"SELECT * FROM {schema}.turnos WHERE eliminado = FALSE ORDER BY id ASC")
        return cur.fetchall()
    finally:
        cur.close()
        conn.close()

@app.post("/turnos")
async def crear_turno(data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            INSERT INTO {schema}.turnos 
            (nombre, hora_ingreso, hora_salida, dias, almuerzo, hora_inicio_almuerzo, hora_fin_almuerzo, almuerzo_min, 
             tolerancia, tolerancia_min, tolerancia_mensual_min, descuento, horas_extras, medio_tiempo_fines) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data.get("nombre"), data.get("hora_ingreso"), data.get("hora_salida"),
            json.dumps(data.get("dias")),
            data.get("almuerzo", False), 
            data.get("hora_inicio_almuerzo"), data.get("hora_fin_almuerzo"), # ⚡ NUEVAS
            data.get("almuerzo_min", 0),
            data.get("tolerancia", False), data.get("tolerancia_min", 0),
            data.get("tolerancia_mensual_min", 0),
            data.get("descuento", True), data.get("horas_extras", False),
            data.get("medio_tiempo_fines", False)
        ))
        conn.commit()
        return {"mensaje": "Turno creado exitosamente"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.put("/turnos/{turno_id}")
async def actualizar_turno(turno_id: int, data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            UPDATE {schema}.turnos SET 
                nombre=%s, hora_ingreso=%s, hora_salida=%s, dias=%s, 
                almuerzo=%s, hora_inicio_almuerzo=%s, hora_fin_almuerzo=%s, almuerzo_min=%s, 
                tolerancia=%s, tolerancia_min=%s, tolerancia_mensual_min=%s, 
                descuento=%s, horas_extras=%s, medio_tiempo_fines=%s
            WHERE id=%s
        """, (
            data.get("nombre"), data.get("hora_ingreso"), data.get("hora_salida"),
            json.dumps(data.get("dias")),
            data.get("almuerzo", False), 
            data.get("hora_inicio_almuerzo"), data.get("hora_fin_almuerzo"),
            data.get("almuerzo_min", 0),
            data.get("tolerancia", False), data.get("tolerancia_min", 0),
            data.get("tolerancia_mensual_min", 0), # ⚡ NUEVO
            data.get("descuento", True), data.get("horas_extras", False),
            data.get("medio_tiempo_fines", False), # ⚡ NUEVO
            turno_id
        ))
        conn.commit()
        return {"mensaje": "Turno actualizado exitosamente"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/turnos/{turno_id}")
async def eliminar_turno(turno_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        # Primero, verificamos si hay empleados usando este turno (Protección adicional)
        cur.execute(f"SELECT id FROM {schema}.empleados WHERE turno_id = %s AND eliminado = FALSE LIMIT 1", (turno_id,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="No puedes eliminar este turno porque hay empleados activos que lo están usando. Reasígnales otro turno primero.")

        # Si está libre, aplicamos el Soft Delete
        cur.execute(f"UPDATE {schema}.turnos SET eliminado = TRUE WHERE id = %s", (turno_id,))
        conn.commit()
        return {"mensaje": "Turno eliminado exitosamente."}
    except HTTPException:
        # Si fue nuestro error personalizado, lo dejamos pasar tal cual
        conn.rollback()
        raise
    except psycopg2.IntegrityError:
         conn.rollback()
         raise HTTPException(status_code=409, detail="Error de Integridad: Este turno está vinculado a registros históricos.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
    finally:
        cur.close()
        conn.close()

# ==============================================================================
# 10. MÓDULO: VACACIONES Y PERMISOS
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. KARDEX (Calcula los días disponibles matemáticamente)
# ------------------------------------------------------------------------------
@app.get("/empleados/{empleado_id}/kardex_vacaciones")
async def calcular_vacaciones(empleado_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Traer datos del empleado
        cur.execute(f"SELECT fecha_antiguedad, saldo_vacaciones_inicial FROM {schema}.empleados WHERE id = %s", (empleado_id,))
        emp = cur.fetchone()
        
        if not emp or not emp["fecha_antiguedad"]:
            return {"dias_disponibles": 0, "mensaje": "Sin fecha de antigüedad configurada"}

        fecha_ant = emp["fecha_antiguedad"]
        saldo_inicial = float(emp["saldo_vacaciones_inicial"] or 0)
        hoy = date.today()

        # Calcular tiempo de servicio
        diferencia = relativedelta(hoy, fecha_ant)
        anios_totales = diferencia.years
        meses_extra = diferencia.months

        # Escala Laboral
        if anios_totales < 5:
            dias_por_anio = 15
        elif anios_totales < 10:
            dias_por_anio = 20
        else:
            dias_por_anio = 30

        # Cálculo Progresivo (Devengo mensual)
        dias_ganados_por_anios = anios_totales * dias_por_anio
        dias_ganados_por_meses = (dias_por_anio / 12) * meses_extra
        total_acumulado = saldo_inicial + dias_ganados_por_anios + dias_ganados_por_meses

        # Restar los días ya tomados
        cur.execute(f"""
            SELECT SUM(dias_descontados) as tomados 
            FROM {schema}.ausencias 
            WHERE empleado_id = %s AND tipo = 'vacacion' AND estado = 'aprobado' AND eliminado = FALSE
        """, (empleado_id,))
        tomados_db = cur.fetchone()
        total_tomados = float(tomados_db["tomados"] or 0)

        dias_disponibles = round(total_acumulado - total_tomados, 2)

        return {
            "antiguedad": f"{anios_totales} años y {meses_extra} meses",
            "tasa_actual": f"{dias_por_anio} días/año",
            "total_acumulado": round(total_acumulado, 2),
            "total_tomados": total_tomados,
            "dias_disponibles": dias_disponibles
        }
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# 2. HISTORIAL DE AUSENCIAS (Trae la lista de vacaciones/permisos tomados)
# ------------------------------------------------------------------------------
# ⚡ AQUÍ ESTABA EL ERROR 404: Faltaba esta línea exacta de @app.get
@app.get("/empleados/{empleado_id}/ausencias")
async def obtener_historial_ausencias(empleado_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f"""
            SELECT id, tipo, fecha_inicio, fecha_fin, hora_inicio, hora_fin, 
                   horas_totales, dias_descontados, motivo, estado
            FROM {schema}.ausencias
            WHERE empleado_id = %s AND eliminado = FALSE
            ORDER BY fecha_inicio DESC
        """, (empleado_id,))
        return cur.fetchall()
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# 3. SEGURIDAD: AJUSTAR SALDO INICIAL (Requiere Contraseña de Admin)
# ------------------------------------------------------------------------------
# ⚡ ESTA ES LA NUEVA RUTA QUE FALTABA PARA QUE FUNCIONE EL BOTÓN DEL FRONTEND
@app.put("/empleados/{empleado_id}/saldo_inicial")
async def actualizar_saldo_inicial(empleado_id: int, data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    nuevo_saldo = data.get("saldo_inicial")
    admin_password = data.get("admin_password")

    if nuevo_saldo is None or not admin_password:
        raise HTTPException(status_code=409, detail="El saldo y la contraseña son obligatorios.")

    # Verificación de Seguridad (Contraseña en Base Maestra)
    conn_pub = conectar_bd("public")
    cur_pub = conn_pub.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur_pub.execute("SELECT password_hash FROM usuarios WHERE id = %s", (usuario["id"],))
    user_db = cur_pub.fetchone()
    cur_pub.close()
    conn_pub.close()

    # Comparamos la contraseña digitada
    if not user_db or not bcrypt.checkpw(admin_password.encode(), user_db["password_hash"].encode()):
        raise HTTPException(status_code=409, detail="Contraseña de Administrador incorrecta. Operación denegada.")

    # Guardar el nuevo saldo
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            UPDATE {schema}.empleados 
            SET saldo_vacaciones_inicial = %s 
            WHERE id = %s
        """, (nuevo_saldo, empleado_id))
        conn.commit()
        return {"mensaje": "Saldo inicial ajustado correctamente."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# 4. REGISTRAR UNA NUEVA AUSENCIA (Motor de Guardado Inteligente)
# ------------------------------------------------------------------------------
@app.post("/ausencias")
async def registrar_ausencia(data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) 
    try:
        empleado_id = data.get("empleado_id")
        tipo = data.get("tipo")  
        fecha_inicio = data.get("fecha_inicio")
        fecha_fin = data.get("fecha_fin")
        motivo = data.get("motivo", "")
        
        # ⚡ Nuevos campos recibidos desde el Frontend
        por_dias = data.get("por_dias", False)
        requiere_reposicion = data.get("requiere_reposicion", False)

        dias_descontados = 0
        horas_totales = 0
        hora_inicio = None
        hora_fin = None

        # ⚡ LÓGICA MEJORADA: Si es vacación O permiso por días completos
        # ⚡ LÓGICA MEJORADA: Si es vacación O permiso por días completos
        if tipo == "vacacion" or (tipo == "permiso" and por_dias):
            f_inicio = datetime.strptime(fecha_inicio, "%Y-%m-%d")
            f_fin = datetime.strptime(fecha_fin, "%Y-%m-%d")
            
            cur.execute(f"SELECT * FROM {schema}.empleados e JOIN {schema}.turnos t ON e.turno_id = t.id WHERE e.id = %s", (empleado_id,))
            turno_emp = cur.fetchone()

            if not turno_emp:
                raise HTTPException(status_code=409, detail="El empleado no tiene un turno asignado.")

            dias_laborales_json = turno_emp["dias"] 
            es_medio_tiempo_fines = turno_emp["medio_tiempo_fines"]
            mapa_dias = {0: 'L', 1: 'M', 2: 'X', 3: 'J', 4: 'V', 5: 'S', 6: 'D'}
            dia_actual = f_inicio
            
            # ⚡ Variables para el motor matemático del ERP
            minutos_totales_deuda = 0
            
            while dia_actual <= f_fin:
                letra_dia = mapa_dias[dia_actual.weekday()]
                if dias_laborales_json.get(letra_dia, False):
                    # 1. Contamos el día para el Frontend y Kardex
                    factor_dia = 0.5 if (letra_dia in ['S', 'D'] and es_medio_tiempo_fines) else 1.0
                    dias_descontados += factor_dia
                    
                    # 2. ⚡ CALCULAMOS LAS HORAS EXACTAS DE ESE DÍA PARA LA DEUDA
                    # Convertimos todo a minutos para evitar errores de reloj
                    in_h, in_m = turno_emp["hora_ingreso"].hour, turno_emp["hora_ingreso"].minute
                    out_h, out_m = turno_emp["hora_salida"].hour, turno_emp["hora_salida"].minute
                    
                    mins_ingreso = (in_h * 60) + in_m
                    mins_salida = (out_h * 60) + out_m
                    if mins_salida < mins_ingreso: mins_salida += 1440 # Cruce de madrugada
                    
                    mins_trabajo_dia = mins_salida - mins_ingreso
                    
                    # Restamos el almuerzo de este día específico
                    if turno_emp["almuerzo"] and turno_emp.get("hora_inicio_almuerzo"):
                        alm_in_h, alm_in_m = turno_emp["hora_inicio_almuerzo"].hour, turno_emp["hora_inicio_almuerzo"].minute
                        alm_out_h, alm_out_m = turno_emp["hora_fin_almuerzo"].hour, turno_emp["hora_fin_almuerzo"].minute
                        
                        mins_alm_in = (alm_in_h * 60) + alm_in_m
                        mins_alm_out = (alm_out_h * 60) + alm_out_m
                        if mins_alm_out < mins_alm_in: mins_alm_out += 1440
                        
                        mins_trabajo_dia -= (mins_alm_out - mins_alm_in)
                    
                    # Aplicamos factor de medio tiempo si es fin de semana
                    mins_trabajo_dia = mins_trabajo_dia * factor_dia
                    
                    # Sumamos a la bolsa total de deuda
                    minutos_totales_deuda += mins_trabajo_dia

                dia_actual += timedelta(days=1) 

            if dias_descontados == 0:
                raise HTTPException(status_code=409, detail="El rango no contiene días laborales.")
                
            # ⚡ Guardamos las horas exactas en la BD
            horas_totales = round(minutos_totales_deuda / 60.0, 2)
        else:
            # ⚡ MOTOR ERP: Lógica de Permiso por Horas Multidía y Almuerzos
            fecha_ini_str = data.get("fecha_inicio_permiso")
            hora_ini_str = data.get("hora_inicio_permiso")
            fecha_fin_str = data.get("fecha_fin_permiso")
            hora_fin_str = data.get("hora_fin_permiso")
            
            # Unificamos Fechas y Horas para cálculo
            dt_inicio = datetime.strptime(f"{fecha_ini_str} {hora_ini_str}", "%Y-%m-%d %H:%M")
            dt_fin = datetime.strptime(f"{fecha_fin_str} {hora_fin_str}", "%Y-%m-%d %H:%M")
            
            if dt_fin < dt_inicio:
                raise HTTPException(status_code=409, detail="La fecha de retorno no puede ser en el pasado.")

            cur.execute(f"SELECT t.* FROM {schema}.empleados e JOIN {schema}.turnos t ON e.turno_id = t.id WHERE e.id = %s", (empleado_id,))
            turno_emp = cur.fetchone()

            segundos_totales = 0
            mapa_dias = {0: 'L', 1: 'M', 2: 'X', 3: 'J', 4: 'V', 5: 'S', 6: 'D'}
            dias_json = turno_emp["dias"]
            
            def combinar_dt(d, t): return datetime.combine(d, t) if t else None

            dia_cursor = dt_inicio.date()
            while dia_cursor <= dt_fin.date():
                letra_dia = mapa_dias[dia_cursor.weekday()]
                
                # Si ese día el empleado trabaja, calculamos cruces
                if dias_json.get(letra_dia, False):
                    w_start = combinar_dt(dia_cursor, turno_emp["hora_ingreso"])
                    w_end = combinar_dt(dia_cursor, turno_emp["hora_salida"])
                    
                    if w_end < w_start: w_end += timedelta(days=1) # Turnos nocturnos
                    
                    # Intersección entre [El permiso] y [El turno laboral]
                    p_start = max(w_start, dt_inicio)
                    p_end = min(w_end, dt_fin)
                    
                    if p_start < p_end:
                        overlap_secs = (p_end - p_start).total_seconds()
                        
                        # ⚡ RESTA DEL ALMUERZO SI SE CRUZA
                        if turno_emp["almuerzo"] and turno_emp.get("hora_inicio_almuerzo"):
                            l_start = combinar_dt(dia_cursor, turno_emp["hora_inicio_almuerzo"])
                            l_end = combinar_dt(dia_cursor, turno_emp["hora_fin_almuerzo"])
                            if l_end < l_start: l_end += timedelta(days=1)
                            
                            lunch_o_start = max(p_start, l_start)
                            lunch_o_end = min(p_end, l_end)
                            if lunch_o_start < lunch_o_end:
                                overlap_secs -= (lunch_o_end - lunch_o_start).total_seconds()
                                
                        segundos_totales += overlap_secs
                dia_cursor += timedelta(days=1)
            
            horas_totales = round(segundos_totales / 3600.0, 2)
            
            # ⚡ NUEVA BARRERA DE SEGURIDAD ERP
            if horas_totales <= 0:
                raise HTTPException(
                    status_code=409, 
                    detail="Operación denegada: El permiso cae en el día libre del empleado, está fuera de su horario de trabajo, o es anulado por su hora de almuerzo. Horas a descontar: 0."
                )

            # Formateamos para guardar en DB
            fecha_inicio = fecha_ini_str
            fecha_fin = fecha_fin_str
            hora_inicio = hora_ini_str
            hora_fin = hora_fin_str

        # ⚡ INSERT ACTUALIZADO (Incluye requiere_reposicion)
        cur.execute(f"""
            INSERT INTO {schema}.ausencias 
            (empleado_id, tipo, fecha_inicio, fecha_fin, hora_inicio, hora_fin, horas_totales, dias_descontados, motivo, requiere_reposicion)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (empleado_id, tipo, fecha_inicio, fecha_fin, hora_inicio, hora_fin, horas_totales, dias_descontados, motivo, requiere_reposicion))
        
        conn.commit()
        return {"mensaje": f"{tipo.capitalize()} registrada correctamente."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# 5. ANULAR AUSENCIA (Soft Delete con Protección de Auditoría)
# ------------------------------------------------------------------------------
@app.delete("/ausencias/{ausencia_id}")
async def anular_ausencia(ausencia_id: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(f"SELECT fecha_inicio FROM {schema}.ausencias WHERE id = %s", (ausencia_id,))
        ausencia = cur.fetchone()
        
        if not ausencia:
            raise HTTPException(status_code=404, detail="Registro no encontrado.")
            
        hoy = date.today()
        if ausencia["fecha_inicio"] <= hoy and usuario["rol"] != "superadmin":
             raise HTTPException(status_code=403, detail="No puedes borrar ausencias pasadas o en curso. Solo el SuperAdministrador tiene este privilegio.")

        cur.execute(f"UPDATE {schema}.ausencias SET eliminado = TRUE, estado = 'anulado' WHERE id = %s", (ausencia_id,))
        
        conn.commit()
        return {"mensaje": "Registro anulado. El saldo ha sido restituido al empleado."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ------------------------------------------------------------------------------
# 6. EDITAR OBSERVACIONES DE AUSENCIA
# ------------------------------------------------------------------------------
@app.put("/ausencias/{ausencia_id}")
async def editar_ausencia(ausencia_id: int, data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor()
    try:
        nuevo_motivo = data.get("motivo")
        
        cur.execute(f"""
            UPDATE {schema}.ausencias 
            SET motivo = %s 
            WHERE id = %s
        """, (nuevo_motivo, ausencia_id))
        
        conn.commit()
        return {"mensaje": "Observaciones actualizadas."}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ==============================================================================
# 11. MOTOR MATEMÁTICO DE ASISTENCIA (CORE ERP)
# ==============================================================================

def calcular_dia_asistencia(marcajes_brutos: list, turno: dict, permisos: list, salario_base: float):
    """
    Motor matemático que procesa una lista de objetos datetime (marcajes) 
    y devuelve un diccionario listo para guardar en asistencia_diaria.
    """
    # 1. Filtro Anti-Ansiedad (Debounce de 3 minutos)
    marcajes_limpios = []
    for m in sorted(marcajes_brutos):
        if not marcajes_limpios:
            marcajes_limpios.append(m)
        else:
            if (m - marcajes_limpios[-1]).total_seconds() > 180:
                marcajes_limpios.append(m)

    resumen = {
        "hora_entrada": marcajes_limpios[0].time() if len(marcajes_limpios) > 0 else None,
        "hora_inicio_almuerzo": marcajes_limpios[1].time() if len(marcajes_limpios) > 1 else None,
        "hora_fin_almuerzo": marcajes_limpios[2].time() if len(marcajes_limpios) > 2 else None,
        "hora_salida": marcajes_limpios[-1].time() if len(marcajes_limpios) > 3 else (marcajes_limpios[-1].time() if len(marcajes_limpios) > 1 else None),
        "minutos_retraso_entrada": 0,
        "minutos_exceso_almuerzo": 0,
        "estado": "Incompleto",
        "deuda_generada_bs": 0.00
    }

    if not resumen["hora_entrada"]:
        resumen["estado"] = "Falta"
        return resumen

    # 2. Evaluación de Tolerancia (Solo ingreso)
    hora_oficial = turno['hora_ingreso']
    min_llegada = (resumen["hora_entrada"].hour * 60) + resumen["hora_entrada"].minute
    min_oficial = (hora_oficial.hour * 60) + hora_oficial.minute
    
    retraso = min_llegada - min_oficial
    
    if retraso > turno.get('tolerancia_min', 0):
        resumen["minutos_retraso_entrada"] = retraso

    # 3. Evaluación de Almuerzo (Duración Estricta)
    if resumen["hora_inicio_almuerzo"] and resumen["hora_fin_almuerzo"]:
        alm_in = (resumen["hora_inicio_almuerzo"].hour * 60) + resumen["hora_inicio_almuerzo"].minute
        alm_out = (resumen["hora_fin_almuerzo"].hour * 60) + resumen["hora_fin_almuerzo"].minute
        duracion = alm_out - alm_in
        
        limite_alm = turno.get('almuerzo_min', 0)
        if duracion > limite_alm and limite_alm > 0:
            resumen["minutos_exceso_almuerzo"] = duracion - limite_alm

    # 4. Regla Estricta de Permisos (Neutraliza deuda si cubre la hora)
    if permisos:
        for p in permisos:
            if p['hora_inicio'] and p['hora_fin']:
                p_in = (p['hora_inicio'].hour * 60) + p['hora_inicio'].minute
                p_out = (p['hora_fin'].hour * 60) + p['hora_fin'].minute
                # Si el empleado llega tarde pero DENTRO de su permiso, perdonamos el retraso matutino
                if min_llegada <= p_out:
                    resumen["minutos_retraso_entrada"] = 0 
                # NOTA: Si llega DESPUÉS de que acabe el permiso, el retraso ya fue sumado arriba y no se perdona.

    # 5. Cálculo Financiero (Valor por minuto)
    # Fórmula: Salario / 30 días / 8 horas / 60 minutos
    valor_minuto = (float(salario_base) / 30 / 8 / 60) if salario_base > 0 else 0
    total_min_deuda = resumen["minutos_retraso_entrada"] + resumen["minutos_exceso_almuerzo"]
    
    resumen["deuda_generada_bs"] = round(total_min_deuda * valor_minuto, 2)

    # 6. Estado Final
    if total_min_deuda > 0:
        resumen["estado"] = "Tarde"
    elif len(marcajes_limpios) >= 4 or (len(marcajes_limpios) >= 2 and not turno.get('almuerzo')):
        resumen["estado"] = "Puntual"

    return resumen

# ==============================================================================
# 12. LECTURA DE ASISTENCIA (PARA EL CALENDARIO FRONTEND)
# ==============================================================================

@app.get("/empleados/{empleado_id}/asistencia/{anio}/{mes}")
async def obtener_asistencia_mensual(empleado_id: int, anio: int, mes: int, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # 1. Traer todos los días calculados (Sin cambios)
        cur.execute(f"SELECT * FROM {schema}.asistencia_diaria WHERE empleado_id = %s AND EXTRACT(YEAR FROM fecha) = %s AND EXTRACT(MONTH FROM fecha) = %s ORDER BY fecha ASC", (empleado_id, anio, mes))
        dias_procesados = cur.fetchall()
        for dia in dias_procesados:
            dia = str(dia)
            dia = str(dia) if dia else None
            dia = str(dia) if dia else None
            dia = str(dia) if dia else None
            dia = str(dia) if dia else None
            dia = float(dia or 0)
            dia = float(dia or 0)

        # 2. Calcular KPIs (Sin cambios)
        cur.execute(f"SELECT COUNT(id) as dias_trabajados, SUM(horas_trabajadas) as total_horas, SUM(minutos_retraso_entrada + minutos_exceso_almuerzo) as retraso_total_min, SUM(deuda_generada_bs) as deuda_total FROM {schema}.asistencia_diaria WHERE empleado_id = %s AND EXTRACT(YEAR FROM fecha) = %s AND EXTRACT(MONTH FROM fecha) = %s", (empleado_id, anio, mes))
        kpis_raw = cur.fetchone()
        
        kpis = {
            "dias_trabajados": kpis_raw.get("dias_trabajados") or 0 if kpis_raw else 0,
            "total_horas": float(kpis_raw.get("total_horas") or 0) if kpis_raw else 0.0,
            "retraso_total_min": int(kpis_raw.get("retraso_total_min") or 0) if kpis_raw else 0,
            "deuda_total": float(kpis_raw.get("deuda_total") or 0) if kpis_raw else 0.0
        }
        
        # ⚡ 3. TRAER DÍAS LABORALES DEL TURNO (Para pintar fines de semana de gris)
        cur.execute(f"SELECT t.dias FROM {schema}.empleados e LEFT JOIN {schema}.turnos t ON e.turno_id = t.id WHERE e.id = %s", (empleado_id,))
        turno_data = cur.fetchone()
        dias_laborales = turno_data if turno_data and turno_data else {}

        # ⚡ 4. TRAER AUSENCIAS DEL MES (Vacaciones, Permisos, Bajas médicas)
        cur.execute(f"""
            SELECT tipo, fecha_inicio, fecha_fin, estado 
            FROM {schema}.ausencias 
            WHERE empleado_id = %s AND eliminado = FALSE AND estado = 'aprobado'
            AND (
                (EXTRACT(YEAR FROM fecha_inicio) = %s AND EXTRACT(MONTH FROM fecha_inicio) = %s)
                OR (EXTRACT(YEAR FROM fecha_fin) = %s AND EXTRACT(MONTH FROM fecha_fin) = %s)
            )
        """, (empleado_id, anio, mes, anio, mes))
        ausencias = cur.fetchall()
        for a in ausencias:
            a = str(a)
            a = str(a)

        # Enviamos el paquete completo al Frontend
        return {
            "dias": dias_procesados, 
            "kpis": kpis, 
            "dias_laborales": dias_laborales, 
            "ausencias": ausencias
        }
    finally:
        cur.close()
        conn.close()

# ==============================================================================
# 1x. MÓDULO: SIMULADOR DE HARDWARE (DEV / QA)
# ==============================================================================

@app.post("/simulador/evento")
async def simular_evento_hardware(data: dict, usuario = Depends(verificar_token)):
    schema = usuario["schema_name"]
    conn = conectar_bd(schema)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        device_no = data.get("device_no", "SIMULADOR-01")
        bio_id = data.get("bio_id")
        fecha = data.get("fecha")
        hora = data.get("hora")
        fecha_hora_str = f"{fecha} {hora}:00" 
        
        # 1. Validar Empleado y Turno
        cur.execute(f"SELECT id, nombres, salario_base, turno_id FROM {schema}.empleados WHERE bio_id = %s AND eliminado = FALSE", (bio_id,))
        emp = cur.fetchone()
        if not emp:
            raise HTTPException(status_code=404, detail="Empleado inactivo o no encontrado.")
            
        cur.execute(f"SELECT * FROM {schema}.turnos WHERE id = %s", (emp['turno_id'],))
        turno = cur.fetchone()
        if not turno:
            raise HTTPException(status_code=409, detail="El empleado no tiene un turno asignado para calcular.")

        # 2. Guardar Marcaje Bruto (Caja Negra)
        raw_string = f"{bio_id}\t{fecha_hora_str}\t0\t1\tSIMULADO"
        cur.execute(f"""
            INSERT INTO {schema}.eventos_brutos (device_no, item, action, fecha_hora, raw_data)
            VALUES (%s, %s, %s, %s, %s)
        """, (device_no, bio_id, "0", fecha_hora_str, psycopg2.extras.Json({"raw": raw_string})))

        # 3. EXTRAER TODOS LOS MARCAJES DE ESE DÍA Y PROCESARLOS
        cur.execute(f"""
            SELECT fecha_hora FROM {schema}.eventos_brutos 
            WHERE item = %s AND DATE(fecha_hora) = %s 
            ORDER BY fecha_hora ASC
        """, (bio_id, fecha))
        marcajes_db = cur.fetchall()
        marcajes_dt = [m['fecha_hora'] for m in marcajes_db]

        # Extraer Permisos (Si tiene alguno para hoy)
        cur.execute(f"""
            SELECT hora_inicio, hora_fin FROM {schema}.ausencias 
            WHERE empleado_id = %s AND tipo = 'permiso' AND estado = 'aprobado' AND eliminado = FALSE
            AND %s BETWEEN fecha_inicio AND fecha_fin
        """, (emp['id'], fecha))
        permisos = cur.fetchall()

        # 🚀 4. EJECUTAR EL MOTOR MATEMÁTICO 🚀
        resumen = calcular_dia_asistencia(marcajes_dt, turno, permisos, emp['salario_base'])

        # 5. ACTUALIZAR O INSERTAR EN ASISTENCIA DIARIA (UPSERT)
        cur.execute(f"""
            INSERT INTO {schema}.asistencia_diaria 
            (empleado_id, fecha, turno_id, hora_entrada, hora_inicio_almuerzo, hora_fin_almuerzo, hora_salida, 
             minutos_retraso_entrada, minutos_exceso_almuerzo, estado, deuda_generada_bs, actualizado_en)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (empleado_id, fecha) 
            DO UPDATE SET 
                hora_entrada = EXCLUDED.hora_entrada,
                hora_inicio_almuerzo = EXCLUDED.hora_inicio_almuerzo,
                hora_fin_almuerzo = EXCLUDED.hora_fin_almuerzo,
                hora_salida = EXCLUDED.hora_salida,
                minutos_retraso_entrada = EXCLUDED.minutos_retraso_entrada,
                minutos_exceso_almuerzo = EXCLUDED.minutos_exceso_almuerzo,
                estado = EXCLUDED.estado,
                deuda_generada_bs = EXCLUDED.deuda_generada_bs,
                actualizado_en = CURRENT_TIMESTAMP
            WHERE {schema}.asistencia_diaria.modificado_manualmente = FALSE;
        """, (
            emp['id'], fecha, emp['turno_id'], resumen['hora_entrada'], resumen['hora_inicio_almuerzo'], 
            resumen['hora_fin_almuerzo'], resumen['hora_salida'], resumen['minutos_retraso_entrada'], 
            resumen['minutos_exceso_almuerzo'], resumen['estado'], resumen['deuda_generada_bs']
        ))

        conn.commit()
        return {"mensaje": f"Marcaje registrado. Asistencia de {emp['nombres']} actualizada."}

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ── RUTA DE ESTADO (Para saber si la API está viva) ──
@app.get("/")
def inicio():
    return {"estado": "API funcionando", "version": "2.0 (Multitenant Base)"}