from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
import bcrypt
import jwt
import os
import re

load_dotenv()
app = FastAPI()

# Permitir conexiones desde el navegador y el instalador
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_cambiar_en_produccion")

# ── CONEXIÓN DINÁMICA POR ESQUEMA ─────────────────────────────────────────────
def conectar_bd(schema_name="public"):
    """
    Se conecta a Supabase y le dice a PostgreSQL que use un esquema específico.
    Si no se pasa ninguno, usa 'public' por defecto.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL no encontrada")
    
    # Inyectamos el search_path en la conexión
    return psycopg2.connect(url, options=f"-c search_path={schema_name}")

# ── VERIFICACIÓN DE TOKEN ─────────────────────────────────────────────────────
def verificar_token(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    try:
        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return datos
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# ── LOGIN ─────────────────────────────────────────────────────────────────────
@app.post("/auth/login")
async def login(request: Request):
    try:
        data     = await request.json()
        email    = data.get("email", "").strip().lower()
        password = data.get("password", "")

        # Nos conectamos al esquema 'public' para el login global
        conn = conectar_bd("public")
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # IMPORTANTE: Asumimos que la tabla empresas ahora tiene la columna 'schema_name'
        cur.execute("""
            SELECT u.*, e.nombre as empresa_nombre, e.schema_name
            FROM usuarios u
            JOIN empresas e ON e.id = u.empresa_id
            WHERE u.email = %s AND u.activo = TRUE
        """, (email,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

        if not usuario:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        if not bcrypt.checkpw(password.encode(), usuario["password_hash"].encode()):
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")

        token = jwt.encode({
            "id":             usuario["id"],
            "email":          usuario["email"],
            "rol":            usuario["rol"],
            "empresa_id":     usuario["empresa_id"],
            "schema_name":    usuario["schema_name"], # Agregado para multitenant
            "empresa_nombre": usuario["empresa_nombre"],
            "exp":            datetime.utcnow() + timedelta(hours=8)
        }, SECRET_KEY, algorithm="HS256")

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

# ── RUTA PROTEGIDA DE PRUEBA ──────────────────────────────────────────────────
@app.get("/auth/me")
def mi_perfil(usuario = Depends(verificar_token)):
    return usuario

# ── CREAR EMPRESA + ADMIN + ESQUEMA (Motor de Aprovisionamiento) ──────────────
@app.post("/empresas")
async def crear_empresa(request: Request, usuario = Depends(verificar_token)):
    # Solo el SuperAdmin puede crear nuevas empresas
    if usuario["rol"] != "superadmin":
        raise HTTPException(status_code=403, detail="Sin permisos")
    
    try:
        data = await request.json()
        nombre         = data.get("nombre")
        admin_nombre   = data.get("admin_nombre")
        admin_email    = data.get("admin_email")
        admin_password = data.get("admin_password")

        # 1. Limpiar el nombre para crear un esquema SQL seguro (solo letras, números y guiones bajos)
        schema_limpio = re.sub(r'[^a-z0-9_]', '', nombre.lower().replace(' ', '_'))
        schema_name   = f"empresa_{schema_limpio}" 

        # Hashear la contraseña del nuevo admin
        password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()

        conn = conectar_bd("public")
        # Usamos autocommit para poder ejecutar CREATE SCHEMA sin problemas de transacciones
        conn.autocommit = True 
        cur  = conn.cursor()

        # 2. Registrar la empresa en la tabla global
        cur.execute(
            "INSERT INTO empresas (nombre, schema_name) VALUES (%s, %s) RETURNING id",
            (nombre, schema_name)
        )
        empresa_id = cur.fetchone()[0]

        # 3. Crear el usuario Admin en la tabla global
        cur.execute("""
            INSERT INTO usuarios (empresa_id, nombre, email, password_hash, rol)
            VALUES (%s, %s, %s, %s, 'admin')
        """, (empresa_id, admin_nombre, admin_email, password_hash))

        # 4. LA MAGIA: Crear el esquema y sus tablas privadas
        # Usamos psycopg2.sql para evitar inyecciones SQL en nombres de esquemas
        from psycopg2 import sql
        
        script_sql = sql.SQL("""
            CREATE SCHEMA {schema};

            CREATE TABLE {schema}.empleados (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(150) NOT NULL,
                documento VARCHAR(50) UNIQUE,
                rfid VARCHAR(50) UNIQUE,
                huella_template TEXT,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE {schema}.horarios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(50) NOT NULL,
                hora_entrada TIME NOT NULL,
                hora_salida TIME NOT NULL,
                tolerancia_minutos INT DEFAULT 0
            );

            CREATE TABLE {schema}.eventos_brutos (
                id SERIAL PRIMARY KEY,
                device_no VARCHAR(50),
                item VARCHAR(50),
                verify_mode VARCHAR(20),
                action VARCHAR(20),
                fecha_hora TIMESTAMP,
                raw_data JSONB,
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE {schema}.asistencia (
                id SERIAL PRIMARY KEY,
                empleado_id INT REFERENCES {schema}.empleados(id),
                fecha DATE,
                hora_marcaje TIMESTAMP,
                tipo VARCHAR(20), 
                estado VARCHAR(20), 
                creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """).format(schema=sql.Identifier(schema_name))

        cur.execute(script_sql)

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

# ── VER EMPRESAS (solo superadmin) ────────────────────────────────────────────
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

# ── CREAR SUPERADMIN ──────────────────────────────────────────────────────────
@app.get("/setup/superadmin")
def crear_superadmin():
    try:
        password_hash = bcrypt.hashpw(
            "admin123".encode(), bcrypt.gensalt()
        ).decode()
        conn = conectar_bd("public")
        cur  = conn.cursor()
        
        # Aseguramos que exista una empresa "Sistema" en el esquema public
        cur.execute("INSERT INTO empresas (id, nombre, schema_name) VALUES (1, 'Sistema', 'public') ON CONFLICT (id) DO NOTHING")
        
        cur.execute("""
            INSERT INTO usuarios (empresa_id, nombre, email, password_hash, rol)
            VALUES (1, 'Super Admin', 'admin@sistema.com', %s, 'superadmin')
            ON CONFLICT (email) DO UPDATE SET password_hash = %s
        """, (password_hash, password_hash))
        conn.commit()
        cur.close()
        conn.close()
        return {"mensaje": "Superadmin creado. Email: admin@sistema.com / Pass: admin123"}
    except Exception as e:
        return {"error": str(e)}

# ── ICLOCK (Lector biométrico ZKTeco - Pendiente de adaptar a esquemas) ───────
@app.get("/iclock/cdata")
async def iclock_init(request: Request):
    sn = request.query_params.get("SN", "")
    print(f"✅ Lector conectado SN={sn}")
    return PlainTextResponse(
        f"GET OPTION FROM: {sn}\n"
        "ATTLOGStamp=None\nOPERLOGStamp=9999\n"
        "Realtime=1\nEncrypt=None\n"
    )

@app.post("/iclock/cdata")
async def iclock_data(request: Request):
    table = request.query_params.get("table", "")
    sn    = request.query_params.get("SN", "")
    body  = await request.body()
    texto = body.decode("utf-8", errors="ignore")
    if table == "ATTLOG":
        for linea in texto.strip().splitlines():
            partes = linea.strip().split("\t")
            if len(partes) >= 2:
                try:
                    conn = conectar_bd("public") # Por ahora lo dejamos apuntando a public
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
    return PlainTextResponse("OK")

# ── DIAGNÓSTICO ───────────────────────────────────────────────────────────────
@app.get("/")
def inicio():
    return {"estado": "API funcionando", "version": "2.0 (Multitenant Base)"}