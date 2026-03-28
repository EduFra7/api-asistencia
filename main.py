from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from dotenv import load_dotenv
from datetime import datetime
import psycopg2
import psycopg2.extras
import os

load_dotenv()
app = FastAPI()

def conectar_bd():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL no encontrada")
    return psycopg2.connect(url)

# ── 1. INICIALIZACIÓN — el lector llega aquí primero ──────────────────────────
@app.get("/iclock/cdata")
async def iclock_init(request: Request):
    sn = request.query_params.get("SN", "")
    print(f"Lector conectado. SN={sn}")
    # Respuesta que el lector espera para empezar a enviar datos
    respuesta = (
        f"GET OPTION FROM: {sn}\n"
        "ATTLOGStamp=None\n"
        "OPERLOGStamp=9999\n"
        "ATTPHOTOStamp=None\n"
        "ErrorDelay=30\n"
        "Delay=10\n"
        "TransTimes=00:00;14:05\n"
        "TransInterval=1\n"
        "TransFlag=TransData AttLog\n"
        "Realtime=1\n"
        "Encrypt=None\n"
    )
    return PlainTextResponse(content=respuesta)

# ── 2. HEARTBEAT — el lector avisa que sigue vivo ─────────────────────────────
@app.post("/iclock/cdata")
async def iclock_data(request: Request):
    table = request.query_params.get("table", "")
    sn    = request.query_params.get("SN", "")
    body  = await request.body()
    texto = body.decode("utf-8", errors="ignore")
    print(f"POST /iclock/cdata tabla={table} SN={sn}")
    print(f"BODY: {texto}")

    if table == "ATTLOG":
        # Cada línea es un evento: PIN TIME STATUS VERIFY
        for linea in texto.strip().splitlines():
            partes = linea.strip().split("\t")
            if len(partes) >= 2:
                try:
                    pin        = partes[0]
                    fecha_hora = partes[1]
                    status     = partes[2] if len(partes) > 2 else "0"
                    verify     = partes[3] if len(partes) > 3 else "0"

                    # Convertir status a texto legible
                    acciones = {"0":"Clock in","1":"Clock out","2":"Out",
                                "3":"Return","4":"OT in","5":"OT out"}
                    action = acciones.get(status, status)

                    modos = {"0":"Password","1":"Fingerprint","2":"Card","15":"Face"}
                    verify_mode = modos.get(verify, verify)

                    conn = conectar_bd()
                    cur  = conn.cursor()
                    cur.execute("""
                        INSERT INTO eventos_brutos
                            (device_no, item, verify_mode, action, fecha_hora, raw_data)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (sn, pin, verify_mode, action, fecha_hora,
                          psycopg2.extras.Json({"raw": linea, "sn": sn})))
                    nuevo_id = cur.fetchone()[0]
                    conn.commit()
                    cur.close()
                    conn.close()
                    print(f"Evento guardado id={nuevo_id} pin={pin} accion={action}")
                except Exception as e:
                    print(f"Error guardando evento: {e}")

    return PlainTextResponse(content="OK")

# ── 3. VER EVENTOS ────────────────────────────────────────────────────────────
@app.get("/eventos")
def ver_eventos():
    try:
        conn = conectar_bd()
        cur  = conn.cursor()
        cur.execute("""
            SELECT id, device_no, item, verify_mode, action, fecha_hora, creado_en
            FROM eventos_brutos
            ORDER BY creado_en DESC LIMIT 20
        """)
        filas = cur.fetchall()
        cur.close()
        conn.close()
        return [{"id": f[0], "device_no": f[1], "item": f[2],
                 "verify_mode": f[3], "action": f[4],
                 "fecha_hora": str(f[5]), "creado_en": str(f[6])} for f in filas]
    except Exception as e:
        return {"error": str(e)}

# ── 4. DIAGNÓSTICO ────────────────────────────────────────────────────────────
@app.get("/")
def inicio():
    return {"estado": "API funcionando correctamente"}

@app.get("/debug")
def debug():
    url = os.getenv("DATABASE_URL", "NO ENCONTRADA")
    if "@" in url:
        return {"database_url": "***@" + url.split("@")[1]}
    return {"database_url": url}


from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
# (ya los tienes importados arriba, solo asegúrate de no duplicar)

# ── X. CAPTURA GENÉRICA PARA EL M1 / MINERVA ─────────────────────────────────
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def minerva_catch_all(full_path: str, request: Request):
    method = request.method
    headers = dict(request.headers)
    query   = dict(request.query_params)
    body    = await request.body()

    print("\n================= NUEVA PETICIÓN M1 =================")
    print(f"Metodo: {method}")
    print(f"Path: /{full_path}")
    print(f"Query: {query}")
    print(f"Headers: {headers}")
    print(f"Body (raw): {body}")
    try:
        texto = body.decode("utf-8")
        print(f"Body (texto): {texto}")
    except Exception:
        print("Body no es texto UTF-8 legible.")
    print("=====================================================\n")

    # Siempre responder 200 para que el M1 no se queje
    return PlainTextResponse(content="OK")