from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from datetime import datetime
import psycopg2
import psycopg2.extras
import os

load_dotenv()

app = FastAPI()

def conectar_bd():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

@app.get("/")
def inicio():
    return {"estado": "API funcionando correctamente"}

@app.post("/push/asistencia")
async def recibir_evento(request: Request):
    try:
        data = await request.json()

        device_no   = data.get("device_no")   or data.get("DeviceNo")
        item        = data.get("item")         or data.get("Item")
        verify_mode = data.get("verify_mode")  or data.get("VerifyMode")
        action      = data.get("action")       or data.get("Action")
        fecha_hora  = data.get("datetime")     or data.get("DateTime") or datetime.now().isoformat()

        conn = conectar_bd()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO eventos_brutos (device_no, item, verify_mode, action, fecha_hora, raw_data)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (device_no, item, verify_mode, action, fecha_hora, psycopg2.extras.Json(data)))
        nuevo_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        return JSONResponse(
            status_code=200,
            content={"mensaje": "Evento guardado", "id": nuevo_id}
        )

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/eventos")
def ver_eventos():
    try:
        conn = conectar_bd()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, device_no, item, verify_mode, action, fecha_hora, creado_en
            FROM eventos_brutos
            ORDER BY creado_en DESC
            LIMIT 20
        """)
        filas = cur.fetchall()
        cur.close()
        conn.close()

        eventos = []
        for fila in filas:
            eventos.append({
                "id":          fila[0],
                "device_no":   fila[1],
                "item":        fila[2],
                "verify_mode": fila[3],
                "action":      fila[4],
                "fecha_hora":  str(fila[5]),
                "creado_en":   str(fila[6])
            })
        return eventos

    except Exception as e:
        return {"error": str(e)}