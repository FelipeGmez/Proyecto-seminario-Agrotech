from fastapi import FastAPI, Body, Header, Query, Request, Security
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    JSONResponse,
    Response
)
from fastapi.security import APIKeyHeader
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from datetime import datetime, timedelta
from xml.sax.saxutils import escape as escapar_xml
from pathlib import Path

import csv
import hashlib
import hmac
import io
import math
import os
import zipfile
import secrets

from database import (
    conectar,
    crear_tabla_datos,
    crear_tabla_fotos,
    crear_tabla_fotos_fijas,
    crear_tabla_configuracion,
    crear_configuracion_inicial,
    crear_tabla_usuarios,
    crear_usuarios_iniciales,
    crear_tabla_registros_actividad,
    crear_tabla_alertas
)


# ============================================================
# DOCUMENTACIÓN DE /docs (Swagger)
#
# Esta sección SOLO organiza los endpoints en /docs (grupos y
# títulos). No cambia el funcionamiento de la API.
#
# /docs queda dividido en dos partes, en este orden:
#
#   1) RASPBERRY -> NUBE : lo que envía/consulta la Raspberry
#                          (se autentica con X-API-Key)
#   2) DASHBOARD         : lo que usa el navegador
#                          (se autentica con usuario y contraseña)
# ============================================================

TAG_RASPBERRY = "RASPBERRY → NUBE"
TAG_SESION = "DASHBOARD · Sesión y páginas"
TAG_NODOS = "DASHBOARD · Nodos y mediciones"
TAG_ALERTAS = "DASHBOARD · Alertas"
TAG_FOTOS = "DASHBOARD · Fotos"
TAG_HORARIOS = "DASHBOARD · Horarios de medición"
TAG_USUARIOS = "DASHBOARD · Usuarios y actividad"


TAGS_DOCS = [
    {"name": TAG_RASPBERRY},
    {"name": TAG_SESION},
    {"name": TAG_NODOS},
    {"name": TAG_ALERTAS},
    {"name": TAG_FOTOS},
    {"name": TAG_HORARIOS},
    {"name": TAG_USUARIOS}
]


# Candado de /docs para los endpoints de la Raspberry.
# La validación real de la clave sigue haciéndose dentro de cada endpoint.
esquema_api_key = APIKeyHeader(
    name="X-API-Key",
    scheme_name="X-API-Key",
    description=(
        "Clave de los nodos: contenido del archivo `api_key_nodos.txt` "
        "(o de la variable de entorno `API_KEY_NODOS`)."
    ),
    auto_error=False
)

RESPUESTA_401_RASPBERRY = {
    401: {
        "description": "API key inválida o ausente (falta `X-API-Key`)."
    }
}


EJEMPLO_LECTURA = {
    "tipo": "lectura",
    "nodo_id": "nodo4",
    "timestamp": "2026-10-15 18:30:00",
    "dht": {"t": 24.5, "h": 61.0},
    "suelo": {
        "N": 20, "P": 15, "K": 30,
        "hum": 42.0, "temp": 22.0,
        "ec": 520, "ph": 6.4
    },
    "bateria": {"porcentaje": 80},
    "piramometro": {"rad": 650.0}
}

EJEMPLO_CONFIRMAR = {
    "version": 3,
    "estado": "publicada",
    "detalle": ""
}

EJEMPLO_ALERTA = {
    "timestamp": "2026-10-15 18:30:00",
    "tipo": "Patrón Multivariable",
    "puntuacion": -0.182,
    "severidad": "Crítica",
    "descripcion": (
        "Patrón multivariable inusual detectado. Score: -0.182. "
        "Revisar condiciones de suelo y ambiente."
    )
}

EJEMPLO_ESTADO_ALERTA = {
    "estado": "Reconocida"
}

EJEMPLO_LOGIN = {
    "usuario": "admin",
    "password": "su_contraseña"
}

EJEMPLO_ACTUALIZAR_NODO = {
    "ubicacion": "Lote 1",
    "cultivo": "Tomate"
}

EJEMPLO_CREAR_USUARIO = {
    "usuario": "nuevo_usuario",
    "password": "ClaveNueva123",
    "rol": "usuario"
}

EJEMPLO_ACTUALIZAR_USUARIO = {
    "rol": "administrador"
}

EJEMPLO_HORARIOS = {
    "horarios": ["06:00", "10:00", "14:00", "18:00"]
}


# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

app = FastAPI(
    title="AGROTECH API",
    openapi_tags=TAGS_DOCS
)

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates")
)


# ============================================================
# SECRETOS
# ============================================================

def cargar_o_crear_secreto(
    nombre_env,
    nombre_archivo
):
    """
    Busca el secreto en este orden:

    1. Variable de entorno
    2. Archivo local
    3. Si no existe, genera uno nuevo
    """

    valor = os.environ.get(nombre_env)

    if valor:
        return valor

    ruta = BASE_DIR / nombre_archivo

    if ruta.exists():

        valor = ruta.read_text().strip()

        if valor:
            return valor

    valor = secrets.token_urlsafe(48)

    ruta.write_text(valor)

    try:
        ruta.chmod(0o600)
    except Exception:
        pass

    return valor


SECRET_KEY = cargar_o_crear_secreto(
    "SECRET_KEY",
    "secret_key.txt"
)


API_KEY_NODOS = cargar_o_crear_secreto(
    "API_KEY_NODOS",
    "api_key_nodos.txt"
)


# ============================================================
# SESIONES
# ============================================================

DURACION_SESION = 60 * 60 * 8


app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=DURACION_SESION,
    same_site="lax"
)


# ============================================================
# CONFIGURACIÓN DE TIEMPO
# ============================================================

# Colombia UTC-5
ZONA_HORARIA = timedelta(hours=-5)

# Tiempo máximo para considerar un nodo activo
TIEMPO_MAXIMO = 60


# ============================================================
# INICIALIZACIÓN DE BASE DE DATOS
# ============================================================

crear_tabla_datos()

crear_tabla_fotos()

crear_tabla_fotos_fijas()

crear_tabla_configuracion()

crear_configuracion_inicial()

crear_tabla_usuarios()

crear_usuarios_iniciales()

crear_tabla_registros_actividad()

crear_tabla_alertas()


# ============================================================
# CONTRASEÑAS
# ============================================================

ITERACIONES = 240_000


def hashear_password(password):
    """
    Genera un hash PBKDF2 con sal.
    """

    sal = secrets.token_hex(16)

    hash_hex = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        sal.encode("utf-8"),
        ITERACIONES
    ).hex()

    return (
        f"pbkdf2$"
        f"{ITERACIONES}$"
        f"{sal}$"
        f"{hash_hex}"
    )


def verificar_password(
    password,
    almacenado
):
    """
    Devuelve:

        (correcta, necesita_actualizar_hash)
    """

    if not almacenado:
        return False, False

    # --------------------------------------------------------
    # HASH PBKDF2
    # --------------------------------------------------------

    if almacenado.startswith("pbkdf2$"):

        try:

            (
                _,
                iteraciones,
                sal,
                hash_guardado
            ) = almacenado.split("$")

            calculado = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                sal.encode("utf-8"),
                int(iteraciones)
            ).hex()

            correcta = hmac.compare_digest(
                calculado,
                hash_guardado
            )

            return correcta, False

        except Exception:

            return False, False

    # --------------------------------------------------------
    # HASH ANTIGUO SHA-256
    # --------------------------------------------------------

    hash_antiguo = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    correcta = hmac.compare_digest(
        hash_antiguo,
        almacenado
    )

    return correcta, correcta


# ============================================================
# FUNCIONES DE SESIÓN
# ============================================================

def verificar_sesion(request: Request):

    """
    Comprueba la sesión contra la base de datos en cada petición:

    - Si el usuario fue eliminado o desactivado, la sesión se cierra.
    - Si le cambiaron el rol, el cambio se aplica de inmediato
      (sin esperar a que vuelva a iniciar sesión).
    """

    usuario_id = request.session.get("usuario_id")

    if usuario_id is None:

        request.session.clear()

        return False

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT usuario, rol, activo
        FROM usuarios
        WHERE id = ?
    """, (
        usuario_id,
    ))

    fila = cursor.fetchone()

    conexion.close()

    if fila is None or not fila["activo"]:

        request.session.clear()

        return False

    request.session["usuario"] = fila["usuario"]

    request.session["rol"] = fila["rol"]

    return True


# ============================================================
# MODO INVITADO
# ============================================================
#
# Con MODO_INVITADO = True, quien entra a la página sin iniciar
# sesión ve el dashboard como "invitado": puede consultar nodos,
# gráficas, fotos, histórico y alertas, pero no puede descargar
# el histórico ni modificar nada.
#
# Con MODO_INVITADO = False todo vuelve a exigir inicio de sesión.

MODO_INVITADO = True


def acceso_lectura(request: Request):
    """
    Permiso para los endpoints de solo consulta.

    - Con sesión válida: permitido (y se refresca usuario/rol).
    - Sin sesión: permitido solo si el modo invitado está activo.

    Los endpoints que descargan o modifican siguen usando
    verificar_sesion / verificar_admin / es_principal.
    """

    con_sesion = verificar_sesion(request)

    return con_sesion or MODO_INVITADO


def obtener_ip(request: Request):
    """
    IP real de quien hace la petición.

    En PythonAnywhere la aplicación está detrás de un proxy, por lo que
    request.client suele venir vacío o ser la IP interna del proxy; la
    IP del visitante llega en X-Forwarded-For / X-Real-IP.
    """

    for cabecera in ("x-forwarded-for", "x-real-ip"):

        valor = request.headers.get(cabecera)

        if valor:

            # X-Forwarded-For puede traer varias IP: la primera es el cliente
            ip = valor.split(",")[0].strip()

            if ip:

                return ip[:64]

    if request.client is not None:

        return request.client.host

    return None


def es_principal(request: Request):

    return (
        request.session.get("rol")
        == "principal"
    )


def es_administrador(request: Request):

    return request.session.get("rol") in (
        "principal",
        "administrador"
    )


def verificar_admin(request: Request):
    """
    Compatibilidad con el código existente.

    A partir de ahora:
    - principal puede administrar
    - administrador puede administrar
    - usuario no puede administrar
    """

    return es_administrador(request)


def no_autorizado():

    return JSONResponse(
        status_code=401,
        content={
            "error": "No autorizado"
        }
    )


def prohibido():

    return JSONResponse(
        status_code=403,
        content={
            "error": (
                "No tiene permisos para realizar "
                "esta operación"
            )
        }
    )


def registrar_actividad(
    request: Request,
    accion: str,
    detalle: str = ""
):
    """
    Registra acciones importantes realizadas por usuarios.
    La hora se almacena en Colombia (UTC-5).
    """

    try:

        usuario = request.session.get(
            "usuario",
            "ANONIMO"
        )

        usuario_id = request.session.get(
            "usuario_id"
        )

        ip = obtener_ip(request)

        fecha_hora = (
            datetime.utcnow()
            + ZONA_HORARIA
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        conexion = conectar()
        cursor = conexion.cursor()

        cursor.execute("""
            INSERT INTO registros_actividad (
                usuario_id,
                usuario,
                accion,
                detalle,
                fecha_hora,
                ip
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            usuario_id,
            str(usuario),
            str(accion),
            str(detalle)[:500],
            fecha_hora,
            ip
        ))

        conexion.commit()
        conexion.close()

    except Exception:
        # La auditoría nunca debe tumbar una operación principal.
        pass


def sin_cache(response):

    response.headers["Cache-Control"] = (
        "no-store, "
        "no-cache, "
        "must-revalidate, "
        "max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    return response


# ============================================================
# FUNCIONES DE NODOS
# ============================================================

def convertir_nodo_id(nodo_id):
    """
    Convierte:

        nodo1 -> 1
        nodo2 -> 2
        nodo3 -> 3
        nodo4 -> 4
    """

    if not isinstance(nodo_id, str):

        raise ValueError(
            "nodo_id debe ser texto"
        )

    if not nodo_id.startswith("nodo"):

        raise ValueError(
            "nodo_id debe tener el formato "
            "nodo1, nodo2, nodo3 o nodo4"
        )

    try:

        numero = int(
            nodo_id[4:]
        )

    except ValueError:

        raise ValueError(
            "nodo_id inválido"
        )

    if numero not in [1, 2, 3, 4]:

        raise ValueError(
            "El nodo debe estar entre 1 y 4"
        )

    return numero


def nombre_nodo(id_nodo):

    return f"nodo{id_nodo}"


def nodo_activo(timestamp):

    if not timestamp:
        return False

    try:

        fecha = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

        ahora = (
            datetime.utcnow()
            + ZONA_HORARIA
        )

        diferencia = (
            ahora - fecha
        ).total_seconds()

        return (
            0 <= diferencia <= TIEMPO_MAXIMO
        )

    except Exception:

        return False


# ============================================================
# LOGIN - PÁGINA
# ============================================================

@app.get(
    "/login",
    response_class=HTMLResponse,
    tags=[TAG_SESION],
    summary="Página de inicio de sesión"
)
def login_page(
    request: Request
):

    if verificar_sesion(request):

        return RedirectResponse(
            "/dashboard",
            status_code=302
        )

    respuesta = templates.TemplateResponse(
        request,
        "login.html"
    )

    return sin_cache(respuesta)


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse,
    tags=[TAG_SESION],
    summary="Página del dashboard · con sesión o como invitado"
)
def dashboard(
    request: Request
):

    con_sesion = verificar_sesion(request)

    # Sin sesión solo se entra si el modo invitado está activo
    if not con_sesion and not MODO_INVITADO:

        return RedirectResponse(
            "/login",
            status_code=302
        )

    respuesta = templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "usuario": request.session.get(
                "usuario"
            ),
            "rol": (
                request.session.get("rol")
                if con_sesion
                else "invitado"
            )
        }
    )

    return sin_cache(respuesta)


# ============================================================
# INICIO
# ============================================================

@app.get(
    "/",
    tags=[TAG_SESION],
    summary="Inicio: redirige al dashboard (invitado o con sesión)"
)
def inicio(
    request: Request
):

    if verificar_sesion(request) or MODO_INVITADO:

        return RedirectResponse(
            "/dashboard",
            status_code=302
        )

    return RedirectResponse(
        "/login",
        status_code=302
    )


# ============================================================
# LOGIN API
# ============================================================

@app.post(
    "/api/login",
    tags=[TAG_SESION],
    summary="Iniciar sesión"
)
def realizar_login(
    request: Request,
    datos: dict = Body(..., examples=[EJEMPLO_LOGIN])
):

    usuario = datos.get("usuario")
    password = datos.get("password")

    if (
        not usuario
        or not password
        or not isinstance(usuario, str)
        or not isinstance(password, str)
    ):

        return {
            "ok": False,
            "mensaje": (
                "Usuario y contraseña "
                "son obligatorios"
            )
        }

    usuario = usuario.strip()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM usuarios
        WHERE usuario = ?
    """, (
        usuario,
    ))

    usuario_db = cursor.fetchone()

    correcta = False
    actualizar = False

    if usuario_db is not None:

        correcta, actualizar = verificar_password(
            password,
            usuario_db["password_hash"]
        )

    # --------------------------------------------------------
    # USUARIO INEXISTENTE O CONTRASEÑA INCORRECTA
    # --------------------------------------------------------

    if usuario_db is None or not correcta:

        conexion.close()

        # El registro se hace sin sesión.
        try:
            fecha_hora = (
                datetime.utcnow()
                + ZONA_HORARIA
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            ip = obtener_ip(request)

            conexion_log = conectar()
            cursor_log = conexion_log.cursor()

            cursor_log.execute("""
                INSERT INTO registros_actividad (
                    usuario_id,
                    usuario,
                    accion,
                    detalle,
                    fecha_hora,
                    ip
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                usuario_db["id"] if usuario_db else None,
                usuario,
                "LOGIN_FALLIDO",
                "Credenciales incorrectas",
                fecha_hora,
                ip
            ))

            conexion_log.commit()
            conexion_log.close()

        except Exception:
            pass

        return {
            "ok": False,
            "mensaje": (
                "Usuario o contraseña "
                "incorrectos"
            )
        }

    # --------------------------------------------------------
    # CUENTA DESACTIVADA
    # --------------------------------------------------------

    if "activo" in usuario_db.keys() and not usuario_db["activo"]:

        conexion.close()

        try:
            fecha_hora = (
                datetime.utcnow()
                + ZONA_HORARIA
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            ip = obtener_ip(request)

            conexion_log = conectar()
            cursor_log = conexion_log.cursor()

            cursor_log.execute("""
                INSERT INTO registros_actividad (
                    usuario_id,
                    usuario,
                    accion,
                    detalle,
                    fecha_hora,
                    ip
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                usuario_db["id"],
                usuario,
                "LOGIN_BLOQUEADO",
                "Cuenta desactivada",
                fecha_hora,
                ip
            ))

            conexion_log.commit()
            conexion_log.close()

        except Exception:
            pass

        return {
            "ok": False,
            "mensaje": "Esta cuenta está desactivada"
        }

    # --------------------------------------------------------
    # MIGRAR SHA-256 ANTIGUO
    # --------------------------------------------------------

    if actualizar:

        nuevo_hash = hashear_password(
            password
        )

        cursor.execute("""
            UPDATE usuarios
            SET password_hash = ?
            WHERE id = ?
        """, (
            nuevo_hash,
            usuario_db["id"]
        ))

    conexion.commit()
    conexion.close()

    # --------------------------------------------------------
    # CREAR SESIÓN
    # --------------------------------------------------------

    request.session.clear()

    request.session["usuario_id"] = (
        usuario_db["id"]
    )

    request.session["usuario"] = (
        usuario_db["usuario"]
    )

    request.session["rol"] = (
        usuario_db["rol"]
    )

    registrar_actividad(
        request,
        "LOGIN",
        "Inicio de sesión correcto"
    )

    return {
        "ok": True,
        "mensaje": (
            "Inicio de sesión correcto"
        ),
        "usuario": (
            usuario_db["usuario"]
        ),
        "rol": (
            usuario_db["rol"]
        )
    }


# ============================================================
# LOGOUT
# ============================================================

@app.post(
    "/api/logout",
    tags=[TAG_SESION],
    summary="Cerrar sesión (API)"
)
def cerrar_sesion_api(
    request: Request
):

    if verificar_sesion(request):
        registrar_actividad(
            request,
            "LOGOUT",
            "Cierre de sesión"
        )

    request.session.clear()

    return {
        "ok": True,
        "mensaje": "Sesión cerrada"
    }


@app.get(
    "/logout",
    tags=[TAG_SESION],
    summary="Cerrar sesión y volver al inicio"
)
def cerrar_sesion(
    request: Request
):

    if verificar_sesion(request):
        registrar_actividad(
            request,
            "LOGOUT",
            "Cierre de sesión"
        )

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=302
    )


# ============================================================
# SESIÓN ACTUAL
# ============================================================

@app.get(
    "/api/sesion",
    tags=[TAG_SESION],
    summary="Ver quién tiene la sesión abierta y su rol"
)
def sesion_actual(
    request: Request
):

    if not verificar_sesion(request):

        return {
            "logueado": False,
            "invitado": MODO_INVITADO,
            "rol": "invitado" if MODO_INVITADO else None
        }

    return {
        "logueado": True,
        "usuario": (
            request.session.get(
                "usuario"
            )
        ),
        "rol": (
            request.session.get(
                "rol"
            )
        )
    }


# ============================================================
# CONSTRUIR JSON DE LECTURA
# ============================================================

def construir_json_lectura(
    medicion
):

    return {

        "tipo": medicion["tipo"],

        "nodo_id": nombre_nodo(
            medicion["nodo"]
        ),

        "timestamp": (
            medicion["timestamp"]
        ),

        "dht": {

            "t": (
                medicion[
                    "temperatura_dht"
                ]
            ),

            "h": (
                medicion[
                    "humedad_dht"
                ]
            )

        },

        "suelo": {

            "N": (
                medicion[
                    "nitrogeno"
                ]
            ),

            "P": (
                medicion[
                    "fosforo"
                ]
            ),

            "K": (
                medicion[
                    "potasio"
                ]
            ),

            "hum": (
                medicion[
                    "humedad_suelo"
                ]
            ),

            "temp": (
                medicion[
                    "temperatura_suelo"
                ]
            ),

            "ec": (
                medicion["ec"]
            ),

            "ph": (
                medicion["ph"]
            )

        },

        "bateria": {

            "porcentaje": (
                medicion["bateria"]
            )

        },

        "piramometro": {

            "rad": (
                medicion["radiacion"]
                if "radiacion" in medicion.keys()
                else None
            )

        }

    }


# ============================================================
# LISTAR LOS 4 NODOS
# ============================================================

@app.get(
    "/api/nodos",
    tags=[TAG_NODOS],
    summary="Listar los 4 nodos con su última lectura y estado"
)
def listar_nodos(
    request: Request
):

    if not acceso_lectura(request):

        return no_autorizado()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM nodos
        ORDER BY id
    """)

    nodos = cursor.fetchall()

    resultado = []

    for nodo in nodos:

        cursor.execute("""
            SELECT *
            FROM mediciones
            WHERE nodo = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            nodo["id"],
        ))

        medicion = cursor.fetchone()

        datos = None

        if medicion:

            datos = (
                construir_json_lectura(
                    medicion
                )
            )

        activo = nodo_activo(
            nodo["ultima_conexion"]
        )

        resultado.append({

            "id": nodo["id"],

            "nodo_id": nombre_nodo(
                nodo["id"]
            ),

            "ubicacion": (
                nodo["ubicacion"]
            ),

            "cultivo": (
                nodo["cultivo"]
            ),

            "estado": (
                "activo"
                if activo
                else "inactivo"
            ),

            "ultima_conexion": (
                nodo["ultima_conexion"]
            ),

            "datos": datos

        })

    conexion.close()

    return resultado


# ============================================================
# INFORMACIÓN DE UN NODO
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}",
    tags=[TAG_NODOS],
    summary="Información de un nodo"
)
def obtener_nodo(
    request: Request,
    id_nodo: int
):

    if not acceso_lectura(request):

        return no_autorizado()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "error": "Nodo inválido"
        }

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM nodos
        WHERE id = ?
    """, (
        id_nodo,
    ))

    nodo = cursor.fetchone()

    conexion.close()

    if nodo is None:

        return {
            "error": "Nodo no encontrado"
        }

    activo = nodo_activo(
        nodo["ultima_conexion"]
    )

    return {

        "id": nodo["id"],

        "nodo_id": nombre_nodo(
            nodo["id"]
        ),

        "ubicacion": (
            nodo["ubicacion"]
        ),

        "cultivo": (
            nodo["cultivo"]
        ),

        "estado": (
            "activo"
            if activo
            else "inactivo"
        ),

        "ultima_conexion": (
            nodo["ultima_conexion"]
        )

    }


# ============================================================
# ACTUALIZAR INFORMACIÓN DEL NODO
# ============================================================

@app.put(
    "/api/nodos/{id_nodo}",
    tags=[TAG_NODOS],
    summary="Cambiar ubicación y cultivo de un nodo · administrador"
)
def actualizar_nodo(
    request: Request,
    id_nodo: int,
    datos: dict = Body(..., examples=[EJEMPLO_ACTUALIZAR_NODO])
):

    if not verificar_sesion(request):

        return no_autorizado()

    if not verificar_admin(request):

        return prohibido()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "error": "Nodo inválido"
        }

    ubicacion = datos.get(
        "ubicacion",
        ""
    )

    cultivo = datos.get(
        "cultivo",
        ""
    )

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE nodos
        SET ubicacion = ?,
            cultivo = ?
        WHERE id = ?
    """, (
        ubicacion,
        cultivo,
        id_nodo
    ))

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "ACTUALIZAR_NODO",
        (
            f"Nodo {id_nodo}: "
            f"ubicacion={ubicacion}, cultivo={cultivo}"
        )
    )

    return {
        "ok": True,
        "mensaje": (
            "Nodo actualizado correctamente"
        )
    }


# ============================================================
# RECIBIR LECTURA DESDE RASPBERRY
# ============================================================

@app.post(
    "/api/nodos/{id_nodo}/datos",
    tags=[TAG_RASPBERRY],
    summary="1 · Enviar una lectura de sensores",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY
)
def recibir_datos(
    request: Request,
    id_nodo: int,
    datos: dict = Body(..., examples=[EJEMPLO_LECTURA])
):

    # --------------------------------------------------------
    # AUTENTICAR RASPBERRY
    # --------------------------------------------------------

    api_key = request.headers.get(
        "X-API-Key",
        ""
    )

    if not hmac.compare_digest(
        api_key,
        API_KEY_NODOS
    ):

        return JSONResponse(
            status_code=401,
            content={
                "ok": False,
                "mensaje": (
                    "API key inválida "
                    "o ausente"
                )
            }
        )

    # --------------------------------------------------------
    # VALIDAR NODO
    # --------------------------------------------------------

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "ok": False,
            "mensaje": "Nodo inválido"
        }

    # --------------------------------------------------------
    # VALIDAR TIPO
    # --------------------------------------------------------

    if datos.get("tipo") != "lectura":

        return {
            "ok": False,
            "mensaje": (
                "El tipo debe ser 'lectura'"
            )
        }

    # --------------------------------------------------------
    # VALIDAR nodo_id
    # --------------------------------------------------------

    try:

        nodo_json = convertir_nodo_id(
            datos.get("nodo_id")
        )

    except ValueError as error:

        return {
            "ok": False,
            "mensaje": str(error)
        }

    if nodo_json != id_nodo:

        return {
            "ok": False,
            "mensaje": (
                "El nodo de la URL "
                "no coincide con nodo_id"
            )
        }

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    timestamp = datos.get(
        "timestamp"
    )

    if not timestamp:

        return {
            "ok": False,
            "mensaje": "Falta timestamp"
        }

    try:

        datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError
    ):

        return {
            "ok": False,
            "mensaje": (
                "El timestamp debe tener "
                "el formato "
                "YYYY-MM-DD HH:MM:SS"
            )
        }

    # --------------------------------------------------------
    # DHT
    # --------------------------------------------------------

    dht = datos.get(
        "dht"
    )

    if not isinstance(
        dht,
        dict
    ):

        return {
            "ok": False,
            "mensaje": "Falta objeto dht"
        }

    temperatura_dht = dht.get("t")

    humedad_dht = dht.get("h")

    # --------------------------------------------------------
    # SUELO
    # --------------------------------------------------------

    suelo = datos.get(
        "suelo"
    )

    if not isinstance(
        suelo,
        dict
    ):

        return {
            "ok": False,
            "mensaje": "Falta objeto suelo"
        }

    nitrogeno = suelo.get("N")

    fosforo = suelo.get("P")

    potasio = suelo.get("K")

    humedad_suelo = suelo.get("hum")

    temperatura_suelo = suelo.get("temp")

    ec = suelo.get("ec")

    ph = suelo.get("ph")

    # --------------------------------------------------------
    # BATERÍA
    # --------------------------------------------------------

    bateria = datos.get(
        "bateria"
    )

    if not isinstance(
        bateria,
        dict
    ):

        return {
            "ok": False,
            "mensaje": (
                "Falta objeto bateria"
            )
        }

    porcentaje_bateria = (
        bateria.get(
            "porcentaje"
        )
    )

    # --------------------------------------------------------
    # PIRANÓMETRO (opcional): radiación solar
    # --------------------------------------------------------

    piramometro = datos.get(
        "piramometro"
    )

    radiacion = None

    if isinstance(
        piramometro,
        dict
    ):

        valor_rad = piramometro.get(
            "rad"
        )

        if (
            isinstance(valor_rad, (int, float))
            and not isinstance(valor_rad, bool)
            and math.isfinite(valor_rad)
        ):

            radiacion = float(valor_rad)

    # --------------------------------------------------------
    # GUARDAR MEDICIÓN
    # --------------------------------------------------------

    conexion = conectar()
    cursor = conexion.cursor()

    # --------------------------------------------------------
    # EVITAR DUPLICADOS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT id
        FROM mediciones
        WHERE nodo = ?
        AND timestamp = ?
        LIMIT 1
    """, (
        id_nodo,
        timestamp
    ))

    medicion_existente = (
        cursor.fetchone()
    )

    if medicion_existente is not None:

        id_medicion = (
            medicion_existente["id"]
        )

        cursor.execute("""
            UPDATE nodos
            SET estado = ?,
                ultima_conexion = ?
            WHERE id = ?
        """, (
            "activo",
            timestamp,
            id_nodo
        ))

        conexion.commit()
        conexion.close()

        return {

            "ok": True,

            "mensaje": (
                "La lectura ya estaba "
                "almacenada; "
                "confirmación repetida."
            ),

            "id_medicion": id_medicion,

            "nodo": id_nodo,

            "nodo_id": nombre_nodo(
                id_nodo
            ),

            "timestamp": timestamp,

            "duplicado": True

        }

    # --------------------------------------------------------
    # INSERTAR MEDICIÓN
    # --------------------------------------------------------

    cursor.execute("""
        INSERT INTO mediciones (

            nodo,
            tipo,
            timestamp,

            temperatura_dht,
            humedad_dht,

            nitrogeno,
            fosforo,
            potasio,

            humedad_suelo,
            temperatura_suelo,

            ec,
            ph,

            bateria,

            radiacion

        )
        VALUES (
            ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?
        )
    """, (

        id_nodo,

        "lectura",

        timestamp,

        temperatura_dht,

        humedad_dht,

        nitrogeno,

        fosforo,

        potasio,

        humedad_suelo,

        temperatura_suelo,

        ec,

        ph,

        porcentaje_bateria,

        radiacion

    ))

    id_medicion = (
        cursor.lastrowid
    )

    # --------------------------------------------------------
    # ACTUALIZAR ESTADO DEL NODO
    # --------------------------------------------------------

    cursor.execute("""
        UPDATE nodos
        SET estado = ?,
            ultima_conexion = ?
        WHERE id = ?
    """, (
        "activo",
        timestamp,
        id_nodo
    ))

    conexion.commit()
    conexion.close()

    return {

        "ok": True,

        "mensaje": (
            "Lectura recibida y "
            "almacenada correctamente"
        ),

        "id_medicion": id_medicion,

        "nodo": id_nodo,

        "nodo_id": nombre_nodo(
            id_nodo
        ),

        "timestamp": timestamp

    }


# ============================================================
# RECIBIR FOTOGRAFÍA DESDE RASPBERRY
# ============================================================

@app.post(
    "/api/nodos/{id_nodo}/foto",
    tags=[TAG_RASPBERRY],
    summary="2 · Enviar la foto del nodo",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "image/jpeg": {"schema": {"type": "string", "format": "binary"}},
                "image/png": {"schema": {"type": "string", "format": "binary"}}
            }
        }
    }
)
async def recibir_foto(
    request: Request,
    id_nodo: int,
    timestamp: str = Query(
        default=None,
        description=(
            "Fecha de la foto: AAAA-MM-DD HH:MM:SS. "
            "También se acepta en el encabezado X-Foto-Timestamp."
        ),
        examples=["2026-10-15 18:30:00"]
    ),
    x_foto_timestamp: str = Header(
        default=None,
        alias="X-Foto-Timestamp",
        description="Alternativa al parámetro timestamp."
    )
):

    # --------------------------------------------------------
    # AUTENTICAR RASPBERRY
    # --------------------------------------------------------

    api_key = request.headers.get(
        "X-API-Key",
        ""
    )

    if not hmac.compare_digest(
        api_key,
        API_KEY_NODOS
    ):

        return JSONResponse(
            status_code=401,
            content={
                "ok": False,
                "mensaje": (
                    "API key inválida "
                    "o ausente"
                )
            }
        )

    # --------------------------------------------------------
    # VALIDAR NODO
    # --------------------------------------------------------

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "ok": False,
            "mensaje": "Nodo inválido"
        }

    # --------------------------------------------------------
    # OBTENER TIMESTAMP
    # --------------------------------------------------------

    timestamp = (
        request.query_params.get(
            "timestamp"
        )
        or
        request.headers.get(
            "X-Foto-Timestamp"
        )
    )

    if not timestamp:

        return {
            "ok": False,
            "mensaje": (
                "Falta timestamp "
                "de fotografía"
            )
        }

    # --------------------------------------------------------
    # VALIDAR TIMESTAMP
    # --------------------------------------------------------

    try:

        datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError
    ):

        return {
            "ok": False,
            "mensaje": (
                "Timestamp de foto inválido"
            )
        }

    # --------------------------------------------------------
    # LEER IMAGEN
    # --------------------------------------------------------

    imagen = await request.body()

    if not imagen:

        return {
            "ok": False,
            "mensaje": (
                "Fotografía vacía"
            )
        }

    # --------------------------------------------------------
    # VALIDAR TIPO DE IMAGEN
    # --------------------------------------------------------

    content_type = (
        request.headers.get(
            "Content-Type",
            ""
        ).lower()
    )

    tipos_permitidos = [
        "image/jpeg",
        "image/jpg",
        "image/png"
    ]

    if (
        content_type
        and content_type not in tipos_permitidos
    ):

        return JSONResponse(
            status_code=415,
            content={
                "ok": False,
                "mensaje": (
                    "Tipo de imagen no "
                    "compatible. Use JPEG o PNG."
                )
            }
        )

    # --------------------------------------------------------
    # PROTECCIÓN CONTRA ARCHIVOS EXCESIVAMENTE GRANDES
    # --------------------------------------------------------

    TAM_MAXIMO = 10 * 1024 * 1024

    if len(imagen) > TAM_MAXIMO:

        return JSONResponse(
            status_code=413,
            content={
                "ok": False,
                "mensaje": (
                    "La fotografía supera "
                    "el límite de 10 MB"
                )
            }
        )

    # --------------------------------------------------------
    # GUARDAR FOTOGRAFÍA
    # --------------------------------------------------------

    conexion = conectar()
    cursor = conexion.cursor()

    # --------------------------------------------------------
    # COMPROBAR DUPLICADO
    # --------------------------------------------------------

    cursor.execute("""
        SELECT timestamp
        FROM fotos
        WHERE nodo = ?
    """, (
        id_nodo,
    ))

    foto_existente = (
        cursor.fetchone()
    )

    if (
        foto_existente is not None
        and
        foto_existente["timestamp"]
        == timestamp
    ):

        conexion.close()

        return {

            "ok": True,

            "mensaje": (
                "La fotografía ya "
                "estaba almacenada"
            ),

            "nodo": id_nodo,

            "nodo_id": nombre_nodo(
                id_nodo
            ),

            "timestamp": timestamp,

            "duplicado": True

        }

    # --------------------------------------------------------
    # INSERTAR / REEMPLAZAR
    # --------------------------------------------------------

    cursor.execute("""
        INSERT INTO fotos (
            nodo,
            timestamp,
            imagen,
            tam_bytes
        )
        VALUES (
            ?, ?, ?, ?
        )

        ON CONFLICT(nodo)
        DO UPDATE SET
            timestamp = excluded.timestamp,
            imagen = excluded.imagen,
            tam_bytes = excluded.tam_bytes
    """, (

        id_nodo,

        timestamp,

        imagen,

        len(imagen)

    ))

    conexion.commit()
    conexion.close()

    return {

        "ok": True,

        "mensaje": (
            "Fotografía recibida y "
            "almacenada correctamente"
        ),

        "nodo": id_nodo,

        "nodo_id": nombre_nodo(
            id_nodo
        ),

        "timestamp": timestamp,

        "tam_bytes": len(imagen)

    }


# ============================================================
# OBTENER ÚLTIMA FOTOGRAFÍA
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/foto",
    tags=[TAG_FOTOS],
    summary="Descargar la última foto de un nodo"
)
def obtener_foto(
    request: Request,
    id_nodo: int
):

    # --------------------------------------------------------
    # REQUIERE LOGIN (O MODO INVITADO)
    # --------------------------------------------------------

    if not acceso_lectura(request):

        return no_autorizado()

    # --------------------------------------------------------
    # VALIDAR NODO
    # --------------------------------------------------------

    if id_nodo not in [1, 2, 3, 4]:

        return JSONResponse(
            status_code=404,
            content={
                "ok": False,
                "mensaje": (
                    "Nodo inválido"
                )
            }
        )

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            imagen,
            tam_bytes
        FROM fotos
        WHERE nodo = ?
    """, (
        id_nodo,
    ))

    foto = cursor.fetchone()

    conexion.close()

    if foto is None:

        return JSONResponse(
            status_code=404,
            content={
                "ok": False,
                "mensaje": (
                    "No existe fotografía "
                    "para este nodo"
                )
            }
        )

    # --------------------------------------------------------
    # RESPUESTA DE IMAGEN
    # --------------------------------------------------------

    respuesta = Response(
        content=foto["imagen"],
        media_type="image/jpeg"
    )

    respuesta.headers[
        "Cache-Control"
    ] = (
        "no-store, "
        "no-cache, "
        "must-revalidate, "
        "max-age=0"
    )

    respuesta.headers[
        "Pragma"
    ] = "no-cache"

    respuesta.headers[
        "X-Foto-Timestamp"
    ] = str(
        foto["timestamp"]
    )

    respuesta.headers[
        "X-Foto-Tam-Bytes"
    ] = str(
        foto["tam_bytes"]
    )

    return respuesta


# ============================================================
# INFORMACIÓN DE LA ÚLTIMA FOTOGRAFÍA
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/foto/info",
    tags=[TAG_FOTOS],
    summary="Fecha y tamaño de la última foto"
)
def informacion_foto(
    request: Request,
    id_nodo: int
):

    if not acceso_lectura(request):

        return no_autorizado()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "ok": False,
            "mensaje": "Nodo inválido"
        }

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            tam_bytes
        FROM fotos
        WHERE nodo = ?
    """, (
        id_nodo,
    ))

    foto = cursor.fetchone()

    conexion.close()

    if foto is None:

        return {
            "ok": False,
            "existe": False,
            "mensaje": (
                "No existe fotografía"
            )
        }

    return {

        "ok": True,

        "existe": True,

        "nodo": id_nodo,

        "nodo_id": nombre_nodo(
            id_nodo
        ),

        "timestamp": (
            foto["timestamp"]
        ),

        "tam_bytes": (
            foto["tam_bytes"]
        ),

        "url": (
            f"/api/nodos/"
            f"{id_nodo}/foto"
        )

    }


# ============================================================
# FOTOS FIJAS DE SEGUIMIENTO (3 por nodo)
# ============================================================

POSICIONES_FOTO_FIJA = (1, 2, 3)

TAM_MAXIMO_FOTO_FIJA = 5 * 1024 * 1024


def detectar_tipo_imagen(datos):
    """Devuelve 'image/jpeg', 'image/png' o None según el contenido real."""

    if datos[:3] == b"\xff\xd8\xff":
        return "image/jpeg"

    if datos[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"

    return None


def error_foto_fija(mensaje, codigo=400):

    return JSONResponse(
        status_code=codigo,
        content={"ok": False, "mensaje": mensaje}
    )


def validar_nodo_y_posicion(id_nodo, posicion):

    if id_nodo not in [1, 2, 3, 4]:
        return error_foto_fija("Nodo inválido", 404)

    if posicion is not None and posicion not in POSICIONES_FOTO_FIJA:
        return error_foto_fija("La posición debe ser 1, 2 o 3", 404)

    return None


@app.get(
    "/api/nodos/{id_nodo}/fotos_fijas",
    tags=[TAG_FOTOS],
    summary="Listar las 3 fotos fijas de seguimiento de un nodo"
)
def listar_fotos_fijas(request: Request, id_nodo: int):

    if not acceso_lectura(request):
        return no_autorizado()

    error = validar_nodo_y_posicion(id_nodo, None)

    if error:
        return error

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT posicion, etiqueta, tam_bytes, subido_en, subido_por
        FROM fotos_fijas
        WHERE nodo = ?
    """, (id_nodo,))

    existentes = {f["posicion"]: f for f in cursor.fetchall()}

    conexion.close()

    fotos = []

    for posicion in POSICIONES_FOTO_FIJA:

        f = existentes.get(posicion)

        fotos.append({
            "posicion": posicion,
            "existe": f is not None,
            "etiqueta": f["etiqueta"] if f else None,
            "tam_bytes": f["tam_bytes"] if f else None,
            "subido_en": f["subido_en"] if f else None,
            "subido_por": f["subido_por"] if f else None
        })

    return {
        "ok": True,
        "nodo": id_nodo,
        "fotos": fotos
    }


@app.get(
    "/api/nodos/{id_nodo}/fotos_fijas/{posicion}",
    tags=[TAG_FOTOS],
    summary="Descargar una foto fija de seguimiento"
)
def obtener_foto_fija(request: Request, id_nodo: int, posicion: int):

    if not acceso_lectura(request):
        return no_autorizado()

    error = validar_nodo_y_posicion(id_nodo, posicion)

    if error:
        return error

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT imagen, tipo, subido_en
        FROM fotos_fijas
        WHERE nodo = ? AND posicion = ?
    """, (id_nodo, posicion))

    foto = cursor.fetchone()
    conexion.close()

    if foto is None:
        return error_foto_fija("No existe esa foto fija", 404)

    return Response(
        content=foto["imagen"],
        media_type=foto["tipo"],
        headers={
            # La página agrega ?v=<fecha de subida>, por eso puede
            # guardarse en caché sin mostrar una versión vieja.
            "Cache-Control": "private, max-age=86400"
        }
    )


@app.put(
    "/api/nodos/{id_nodo}/fotos_fijas/{posicion}",
    tags=[TAG_FOTOS],
    summary="Subir o reemplazar una foto fija de seguimiento · administrador"
)
async def subir_foto_fija(
    request: Request,
    id_nodo: int,
    posicion: int,
    etiqueta: str = ""
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_administrador(request):
        return prohibido()

    error = validar_nodo_y_posicion(id_nodo, posicion)

    if error:
        return error

    imagen = await request.body()

    if not imagen:
        return error_foto_fija("La imagen está vacía")

    if len(imagen) > TAM_MAXIMO_FOTO_FIJA:
        return error_foto_fija(
            "La imagen supera el límite de 5 MB",
            413
        )

    tipo = detectar_tipo_imagen(imagen)

    if tipo is None:
        return error_foto_fija(
            "Formato no compatible. Use JPEG o PNG.",
            415
        )

    etiqueta = (etiqueta or "").strip()[:60] or None

    subido_en = (
        datetime.utcnow() + ZONA_HORARIA
    ).strftime("%Y-%m-%d %H:%M:%S")

    subido_por = str(request.session.get("usuario", ""))

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        INSERT INTO fotos_fijas (
            nodo, posicion, etiqueta, imagen, tipo,
            tam_bytes, subido_en, subido_por
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(nodo, posicion)
        DO UPDATE SET
            etiqueta = excluded.etiqueta,
            imagen = excluded.imagen,
            tipo = excluded.tipo,
            tam_bytes = excluded.tam_bytes,
            subido_en = excluded.subido_en,
            subido_por = excluded.subido_por
    """, (
        id_nodo, posicion, etiqueta, imagen, tipo,
        len(imagen), subido_en, subido_por
    ))

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "SUBIR_FOTO_FIJA",
        f"Nodo {id_nodo}, foto {posicion}, {len(imagen)} bytes"
    )

    return {
        "ok": True,
        "mensaje": "Foto guardada correctamente",
        "nodo": id_nodo,
        "posicion": posicion,
        "tam_bytes": len(imagen),
        "subido_en": subido_en
    }


@app.put(
    "/api/nodos/{id_nodo}/fotos_fijas/{posicion}/etiqueta",
    tags=[TAG_FOTOS],
    summary="Cambiar solo el nombre de una foto fija · administrador"
)
def renombrar_foto_fija(
    request: Request,
    id_nodo: int,
    posicion: int,
    datos: dict = Body(...)
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_administrador(request):
        return prohibido()

    error = validar_nodo_y_posicion(id_nodo, posicion)

    if error:
        return error

    etiqueta = datos.get("etiqueta")

    if etiqueta is not None and not isinstance(etiqueta, str):
        return error_foto_fija("Nombre inválido")

    etiqueta = (etiqueta or "").strip()[:60] or None

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE fotos_fijas
        SET etiqueta = ?
        WHERE nodo = ? AND posicion = ?
    """, (etiqueta, id_nodo, posicion))

    cambiadas = cursor.rowcount

    conexion.commit()
    conexion.close()

    if cambiadas == 0:
        return error_foto_fija("No existe esa foto fija", 404)

    registrar_actividad(
        request,
        "RENOMBRAR_FOTO_FIJA",
        f"Nodo {id_nodo}, foto {posicion}"
    )

    return {"ok": True, "mensaje": "Nombre actualizado"}


@app.delete(
    "/api/nodos/{id_nodo}/fotos_fijas/{posicion}",
    tags=[TAG_FOTOS],
    summary="Eliminar una foto fija de seguimiento · administrador"
)
def eliminar_foto_fija(request: Request, id_nodo: int, posicion: int):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_administrador(request):
        return prohibido()

    error = validar_nodo_y_posicion(id_nodo, posicion)

    if error:
        return error

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        DELETE FROM fotos_fijas
        WHERE nodo = ? AND posicion = ?
    """, (id_nodo, posicion))

    borradas = cursor.rowcount

    conexion.commit()
    conexion.close()

    if borradas == 0:
        return error_foto_fija("No existe esa foto fija", 404)

    registrar_actividad(
        request,
        "ELIMINAR_FOTO_FIJA",
        f"Nodo {id_nodo}, foto {posicion}"
    )

    return {"ok": True, "mensaje": "Foto eliminada"}


# ============================================================
# ALERTAS DEL ANÁLISIS DE DATOS (Raspberry -> nube)
# ============================================================

def respuesta_error_alerta(mensaje):
    """
    La Raspberry da una alerta por enviada cuando la nube responde con
    un código HTTP 2xx. Por eso los errores de validación de este
    endpoint devuelven 400 (y no 200): así la alerta no se pierde y
    la Raspberry la reintenta.
    """

    return JSONResponse(
        status_code=400,
        content={
            "ok": False,
            "mensaje": mensaje
        }
    )


def alerta_a_json(fila):

    return {
        "id": fila["id"],
        "nodo": fila["nodo"],
        "nodo_id": nombre_nodo(fila["nodo"]),
        "timestamp": fila["timestamp"],
        "tipo": fila["tipo"],
        "puntuacion": fila["puntuacion"],
        "severidad": fila["severidad"],
        "descripcion": fila["descripcion"],
        "estado": fila["estado"],
        "actualizado_por": fila["actualizado_por"],
        "actualizado_en": fila["actualizado_en"]
    }


@app.post(
    "/api/nodos/{id_nodo}/alertas",
    tags=[TAG_RASPBERRY],
    summary="5 · Enviar una alerta del análisis de datos",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY
)
def recibir_alerta(
    request: Request,
    id_nodo: int,
    datos: dict = Body(..., examples=[EJEMPLO_ALERTA])
):

    # --------------------------------------------------------
    # AUTENTICAR RASPBERRY
    # --------------------------------------------------------

    if not verificar_api_key(request):

        return api_key_invalida()

    # --------------------------------------------------------
    # VALIDAR NODO
    # --------------------------------------------------------

    if id_nodo not in [1, 2, 3, 4]:

        return respuesta_error_alerta("Nodo inválido")

    # nodo_id es opcional, pero si viene debe coincidir con la URL
    if "nodo_id" in datos:

        try:

            nodo_json = convertir_nodo_id(
                datos.get("nodo_id")
            )

        except ValueError as error:

            return respuesta_error_alerta(str(error))

        if nodo_json != id_nodo:

            return respuesta_error_alerta(
                "El nodo de la URL no coincide con nodo_id"
            )

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    timestamp = datos.get("timestamp")

    if not timestamp:

        return respuesta_error_alerta("Falta timestamp")

    try:

        datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (ValueError, TypeError):

        return respuesta_error_alerta(
            "El timestamp debe tener el formato "
            "YYYY-MM-DD HH:MM:SS"
        )

    # --------------------------------------------------------
    # TIPO Y SEVERIDAD
    # --------------------------------------------------------

    tipo = datos.get("tipo")

    if not isinstance(tipo, str) or not tipo.strip():

        return respuesta_error_alerta("Falta el tipo de alerta")

    severidad = datos.get("severidad")

    if (
        not isinstance(severidad, str)
        or not severidad.strip()
    ):

        return respuesta_error_alerta("Falta la severidad")

    tipo = tipo.strip()[:100]

    severidad = severidad.strip()[:30]

    # --------------------------------------------------------
    # PUNTUACIÓN (opcional, numérica)
    # --------------------------------------------------------

    puntuacion = datos.get("puntuacion")

    if puntuacion is not None:

        if (
            not isinstance(puntuacion, (int, float))
            or isinstance(puntuacion, bool)
            or not math.isfinite(puntuacion)
        ):

            return respuesta_error_alerta(
                "La puntuación debe ser un número"
            )

        puntuacion = float(puntuacion)

    # --------------------------------------------------------
    # DESCRIPCIÓN Y ESTADO (opcionales)
    # --------------------------------------------------------

    descripcion = datos.get("descripcion")

    if descripcion is not None:

        descripcion = str(descripcion)[:1000]

    estado = datos.get("estado")

    if isinstance(estado, str) and estado.strip():

        estado = estado.strip()[:30]

    else:

        estado = "Activa"

    # --------------------------------------------------------
    # GUARDAR (sin duplicados)
    # --------------------------------------------------------

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT id
        FROM alertas
        WHERE nodo = ?
        AND timestamp = ?
        AND tipo = ?
        LIMIT 1
    """, (
        id_nodo,
        timestamp,
        tipo
    ))

    existente = cursor.fetchone()

    if existente is not None:

        conexion.close()

        return {
            "ok": True,
            "mensaje": (
                "La alerta ya estaba almacenada; "
                "confirmación repetida."
            ),
            "id_alerta": existente["id"],
            "nodo": id_nodo,
            "nodo_id": nombre_nodo(id_nodo),
            "timestamp": timestamp,
            "duplicado": True
        }

    cursor.execute("""
        INSERT INTO alertas (
            nodo,
            timestamp,
            tipo,
            puntuacion,
            severidad,
            descripcion,
            estado
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        id_nodo,
        timestamp,
        tipo,
        puntuacion,
        severidad,
        descripcion,
        estado
    ))

    id_alerta = cursor.lastrowid

    conexion.commit()
    conexion.close()

    return {
        "ok": True,
        "mensaje": "Alerta recibida y almacenada correctamente",
        "id_alerta": id_alerta,
        "nodo": id_nodo,
        "nodo_id": nombre_nodo(id_nodo),
        "timestamp": timestamp
    }


# ============================================================
# CONSULTAR ALERTAS (DASHBOARD)
# ============================================================

@app.get(
    "/api/alertas",
    tags=[TAG_ALERTAS],
    summary="Listar alertas (paginado, filtrable y ordenable)"
)
def listar_alertas(
    request: Request,
    nodo: int = None,
    severidad: str = None,
    estado: str = None,
    pagina: int = 1,
    por_pagina: int = 20,
    orden: str = "fecha",
    direccion: str = "desc"
):

    if not acceso_lectura(request):

        return no_autorizado()

    return consultar_alertas(
        nodo, severidad, estado, pagina, por_pagina, orden, direccion
    )


def consultar_alertas(
    nodo,
    severidad,
    estado,
    pagina,
    por_pagina,
    orden,
    direccion
):

    # Columnas permitidas para ordenar (lista blanca)
    columnas_orden = {
        "fecha": "timestamp",
        "nodo": "nodo",
        "tipo": "tipo",
        "severidad": "severidad",
        "puntuacion": "puntuacion",
        "estado": "estado"
    }

    columna = columnas_orden.get(orden, "timestamp")

    sentido = "ASC" if direccion == "asc" else "DESC"

    condiciones = []
    parametros = []

    if nodo is not None:

        condiciones.append("nodo = ?")
        parametros.append(nodo)

    if severidad:

        condiciones.append("severidad = ? COLLATE NOCASE")
        parametros.append(severidad)

    if estado:

        condiciones.append("estado = ? COLLATE NOCASE")
        parametros.append(estado)

    where = (
        "WHERE " + " AND ".join(condiciones)
        if condiciones
        else ""
    )

    por_pagina = max(5, min(por_pagina, 100))

    pagina = max(1, pagina)

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        f"SELECT COUNT(*) AS total FROM alertas {where}",
        parametros
    )

    total = cursor.fetchone()["total"]

    paginas = max(1, (total + por_pagina - 1) // por_pagina)

    pagina = min(pagina, paginas)

    desplazamiento = (pagina - 1) * por_pagina

    # Los valores vacíos (NULL) siempre quedan al final
    cursor.execute(f"""
        SELECT *
        FROM alertas
        {where}
        ORDER BY ({columna} IS NULL), {columna} {sentido}, id {sentido}
        LIMIT ? OFFSET ?
    """, parametros + [por_pagina, desplazamiento])

    filas = cursor.fetchall()

    conexion.close()

    return {
        "total": total,
        "pagina": pagina,
        "por_pagina": por_pagina,
        "paginas": paginas,
        "orden": orden if orden in columnas_orden else "fecha",
        "direccion": sentido.lower(),
        "datos": [alerta_a_json(fila) for fila in filas]
    }


@app.get(
    "/api/alertas/resumen",
    tags=[TAG_ALERTAS],
    summary="Resumen de alertas activas por severidad y por nodo"
)
def resumen_alertas(
    request: Request
):

    if not acceso_lectura(request):

        return no_autorizado()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM alertas")

    total = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT severidad, COUNT(*) AS cantidad
        FROM alertas
        WHERE estado = 'Activa' COLLATE NOCASE
        GROUP BY severidad
    """)

    por_severidad = {
        fila["severidad"]: fila["cantidad"]
        for fila in cursor.fetchall()
    }

    por_nodo = []

    for id_nodo in [1, 2, 3, 4]:

        cursor.execute("""
            SELECT
                COUNT(*) AS activas,
                COALESCE(SUM(
                    severidad = 'Crítica' COLLATE NOCASE
                ), 0) AS criticas,
                MAX(timestamp) AS ultima
            FROM alertas
            WHERE nodo = ?
            AND estado = 'Activa' COLLATE NOCASE
        """, (
            id_nodo,
        ))

        fila = cursor.fetchone()

        por_nodo.append({
            "id": id_nodo,
            "nodo_id": nombre_nodo(id_nodo),
            "activas": fila["activas"],
            "criticas": fila["criticas"],
            "ultima": fila["ultima"]
        })

    cursor.execute("""
        SELECT *
        FROM alertas
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
    """)

    ultima = cursor.fetchone()

    conexion.close()

    return {
        "total": total,
        "activas": sum(por_severidad.values()),
        "criticas_activas": sum(
            cantidad
            for nombre, cantidad in por_severidad.items()
            if nombre.lower() == "crítica"
        ),
        "por_severidad": por_severidad,
        "por_nodo": por_nodo,
        "ultima": alerta_a_json(ultima) if ultima else None
    }


@app.get(
    "/api/nodos/{id_nodo}/alertas",
    tags=[TAG_RASPBERRY],
    summary="6 · Consultar las alertas de un nodo y su estado",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY
)
def alertas_de_un_nodo(
    request: Request,
    id_nodo: int,
    severidad: str = None,
    estado: str = None,
    pagina: int = 1,
    por_pagina: int = 20,
    orden: str = "fecha",
    direccion: str = "desc"
):

    # La Raspberry se autentica con X-API-Key; también se acepta una
    # sesión iniciada en el dashboard.
    if not verificar_api_key(request) and not acceso_lectura(request):

        return no_autorizado()

    if id_nodo not in [1, 2, 3, 4]:

        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "mensaje": "Nodo inválido"
            }
        )

    return consultar_alertas(
        id_nodo,
        severidad,
        estado,
        pagina,
        por_pagina,
        orden,
        direccion
    )


ESTADOS_ALERTA = ("Activa", "Reconocida", "Resuelta")


@app.put(
    "/api/alertas/{id_alerta}",
    tags=[TAG_ALERTAS],
    summary="Cambiar el estado de una alerta · administrador"
)
def cambiar_estado_alerta(
    request: Request,
    id_alerta: int,
    datos: dict = Body(..., examples=[EJEMPLO_ESTADO_ALERTA])
):

    if not verificar_sesion(request):

        return no_autorizado()

    if not verificar_admin(request):

        return prohibido()

    solicitado = datos.get("estado")

    equivalencias = {
        e.lower(): e
        for e in ESTADOS_ALERTA
    }

    if (
        not isinstance(solicitado, str)
        or solicitado.strip().lower() not in equivalencias
    ):

        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "mensaje": (
                    "El estado debe ser: "
                    + ", ".join(ESTADOS_ALERTA)
                )
            }
        )

    nuevo_estado = equivalencias[solicitado.strip().lower()]

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT * FROM alertas WHERE id = ?",
        (id_alerta,)
    )

    anterior = cursor.fetchone()

    if anterior is None:

        conexion.close()

        return JSONResponse(
            status_code=404,
            content={
                "ok": False,
                "mensaje": "Alerta no encontrada"
            }
        )

    cursor.execute("""
        UPDATE alertas
        SET estado = ?,
            actualizado_por = ?,
            actualizado_en = ?
        WHERE id = ?
    """, (
        nuevo_estado,
        request.session.get("usuario"),
        (
            datetime.utcnow()
            + ZONA_HORARIA
        ).strftime("%Y-%m-%d %H:%M:%S"),
        id_alerta
    ))

    conexion.commit()

    cursor.execute(
        "SELECT * FROM alertas WHERE id = ?",
        (id_alerta,)
    )

    actualizada = cursor.fetchone()

    conexion.close()

    registrar_actividad(
        request,
        "CAMBIAR_ESTADO_ALERTA",
        (
            f"Alerta {id_alerta} (nodo {anterior['nodo']}): "
            f"{anterior['estado']} -> {nuevo_estado}"
        )
    )

    return {
        "ok": True,
        "alerta": alerta_a_json(actualizada)
    }


# ============================================================
# ALERTAS POR DÍA (gráfica del dashboard)
# ============================================================

@app.get(
    "/api/alertas/por_dia",
    tags=[TAG_ALERTAS],
    summary="Cantidad de alertas por día y severidad"
)
def alertas_por_dia(
    request: Request,
    dias: int = 30
):

    if not acceso_lectura(request):

        return no_autorizado()

    dias = max(1, min(dias, 365))

    hoy = datetime.utcnow() + ZONA_HORARIA

    primer_dia = (hoy - timedelta(days=dias - 1)).strftime("%Y-%m-%d")

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT substr(timestamp, 1, 10) AS fecha,
               severidad,
               COUNT(*) AS cantidad
        FROM alertas
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY fecha, severidad
    """, (
        primer_dia,
    ))

    por_fecha = {}

    for fila in cursor.fetchall():

        por_fecha.setdefault(fila["fecha"], {})[fila["severidad"]] = (
            fila["cantidad"]
        )

    conexion.close()

    resultado = []

    # Todos los días del rango, también los que no tienen alertas
    for indice in range(dias):

        fecha = (
            hoy - timedelta(days=dias - 1 - indice)
        ).strftime("%Y-%m-%d")

        severidades = por_fecha.get(fecha, {})

        resultado.append({
            "fecha": fecha,
            "total": sum(severidades.values()),
            "por_severidad": severidades
        })

    return {
        "dias": resultado
    }


# ============================================================
# ÚLTIMA LECTURA DE UN NODO
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/datos",
    tags=[TAG_NODOS],
    summary="Última lectura de un nodo"
)
def obtener_datos(
    request: Request,
    id_nodo: int
):

    if not acceso_lectura(request):

        return no_autorizado()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "error": "Nodo inválido"
        }

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM mediciones
        WHERE nodo = ?
        ORDER BY id DESC
        LIMIT 1
    """, (
        id_nodo,
    ))

    medicion = cursor.fetchone()

    conexion.close()

    if medicion is None:

        return {
            "mensaje": (
                "No existen mediciones "
                "para este nodo"
            )
        }

    return construir_json_lectura(
        medicion
    )


# ============================================================
# FILTRO POR FECHAS Y EXPORTACIÓN DEL HISTÓRICO
# ============================================================

def construir_filtro_fechas(desde, hasta):
    """
    Devuelve (fragmento_sql, parametros, error).

    desde / hasta llegan como AAAA-MM-DD y se incluyen completos:
    desde 00:00:00 del primer día hasta 23:59:59 del último.
    Los timestamps se guardan como texto AAAA-MM-DD HH:MM:SS, por lo
    que la comparación de texto equivale a la comparación de fechas.
    """

    condiciones = []
    parametros = []

    fechas = {}

    for nombre, valor in (("desde", desde), ("hasta", hasta)):

        if valor is None or str(valor).strip() == "":

            continue

        try:

            datetime.strptime(valor, "%Y-%m-%d")

        except (ValueError, TypeError):

            return "", [], (
                f"La fecha '{nombre}' debe tener el formato AAAA-MM-DD"
            )

        fechas[nombre] = valor

    if (
        "desde" in fechas
        and "hasta" in fechas
        and fechas["desde"] > fechas["hasta"]
    ):

        return "", [], (
            "La fecha 'desde' no puede ser posterior a la fecha 'hasta'"
        )

    if "desde" in fechas:

        condiciones.append("AND timestamp >= ?")
        parametros.append(fechas["desde"] + " 00:00:00")

    if "hasta" in fechas:

        condiciones.append("AND timestamp <= ?")
        parametros.append(fechas["hasta"] + " 23:59:59")

    return " ".join(condiciones), parametros, None


# ------------------------------------------------------------
# Filtro por valor de una variable (histórico y exportación)
#
#   variable : nombre de la variable (lista blanca de abajo)
#   minimo   : valor mínimo incluido (opcional)
#   maximo   : valor máximo incluido (opcional)
#
#   Solo mínimo  -> mayor o igual que
#   Solo máximo  -> menor o igual que
#   Ambos        -> entre los dos (iguales = valor exacto)
# ------------------------------------------------------------

VARIABLES_FILTRO = {
    "temperatura_dht": "temperatura_dht",
    "humedad_dht": "humedad_dht",
    "nitrogeno": "nitrogeno",
    "fosforo": "fosforo",
    "potasio": "potasio",
    "humedad_suelo": "humedad_suelo",
    "temperatura_suelo": "temperatura_suelo",
    "ec": "ec",
    "ph": "ph",
    "bateria": "bateria",
    "radiacion": "radiacion"
}


def construir_filtro_variable(variable, minimo, maximo):
    """
    Devuelve (fragmento_sql, parametros, error).

    El nombre de la columna sale siempre de VARIABLES_FILTRO (nunca
    del texto recibido) y los valores viajan como parámetros.
    """

    if variable is None or str(variable).strip() == "":
        return "", [], None

    variable = str(variable).strip().lower()

    if variable not in VARIABLES_FILTRO:
        return "", [], "La variable del filtro no es válida"

    columna = VARIABLES_FILTRO[variable]

    limites = {}

    for nombre, valor in (("minimo", minimo), ("maximo", maximo)):

        if valor is None or str(valor).strip() == "":
            continue

        try:
            numero = float(str(valor).strip().replace(",", "."))
        except ValueError:
            numero = None

        if numero is None or not math.isfinite(numero):
            return "", [], (
                f"El valor '{nombre}' del filtro debe ser un número"
            )

        limites[nombre] = numero

    if not limites:
        return "", [], "Indique un valor para filtrar la variable"

    if (
        "minimo" in limites
        and "maximo" in limites
        and limites["minimo"] > limites["maximo"]
    ):
        return "", [], (
            "El valor mínimo del filtro no puede ser mayor que el máximo"
        )

    condiciones = [f"AND {columna} IS NOT NULL"]
    parametros = []

    if "minimo" in limites:
        condiciones.append(f"AND {columna} >= ?")
        parametros.append(limites["minimo"])

    if "maximo" in limites:
        condiciones.append(f"AND {columna} <= ?")
        parametros.append(limites["maximo"])

    return " ".join(condiciones), parametros, None


# Columnas del archivo descargado: (título, función que lee la fila)
COLUMNAS_EXPORTACION = [
    ("Nodo", lambda f: f"NODO_{f['nodo']:02d}"),
    ("Fecha y hora", lambda f: f["timestamp"]),
    ("Temperatura aire (°C)", lambda f: f["temperatura_dht"]),
    ("Humedad aire (%)", lambda f: f["humedad_dht"]),
    ("Nitrógeno (N)", lambda f: f["nitrogeno"]),
    ("Fósforo (P)", lambda f: f["fosforo"]),
    ("Potasio (K)", lambda f: f["potasio"]),
    ("Humedad suelo (%)", lambda f: f["humedad_suelo"]),
    ("Temperatura suelo (°C)", lambda f: f["temperatura_suelo"]),
    ("EC (µS/cm)", lambda f: f["ec"]),
    ("pH", lambda f: f["ph"]),
    ("Batería (%)", lambda f: f["bateria"]),
    ("Radiación (W/m²)", lambda f: f["radiacion"])
]

LIMITE_FILAS_EXPORTACION = 200_000


def letra_columna(indice):
    """0 -> A, 1 -> B ... 25 -> Z, 26 -> AA"""

    letras = ""
    indice += 1

    while indice > 0:

        indice, resto = divmod(indice - 1, 26)
        letras = chr(65 + resto) + letras

    return letras


def generar_xlsx(columnas, filas):
    """
    Genera un archivo Excel (.xlsx) sin dependencias externas.
    La columna "Fecha y hora" se guarda como fecha real de Excel y los
    números como números (no como texto), así se pueden filtrar y graficar.
    """

    def celda_texto(referencia, texto, estilo=0):

        return (
            f'<c r="{referencia}" t="inlineStr" s="{estilo}">'
            f"<is><t>{escapar_xml(str(texto))}</t></is></c>"
        )

    def celda_numero(referencia, numero, estilo=0):

        return f'<c r="{referencia}" s="{estilo}"><v>{numero!r}</v></c>'

    origen = datetime(1899, 12, 30)

    filas_xml = []

    # Encabezado (negrita)
    encabezado = "".join(
        celda_texto(f"{letra_columna(i)}1", titulo, 1)
        for i, (titulo, _) in enumerate(columnas)
    )

    filas_xml.append(f'<row r="1">{encabezado}</row>')

    for numero_fila, fila in enumerate(filas, start=2):

        celdas = []

        for i, (titulo, leer) in enumerate(columnas):

            valor = leer(fila)

            referencia = f"{letra_columna(i)}{numero_fila}"

            if valor is None:

                continue

            if titulo == "Fecha y hora":

                try:

                    momento = datetime.strptime(
                        valor, "%Y-%m-%d %H:%M:%S"
                    )

                    serie = (momento - origen).total_seconds() / 86400

                    celdas.append(celda_numero(referencia, serie, 2))

                except ValueError:

                    celdas.append(celda_texto(referencia, valor))

            elif isinstance(valor, (int, float)) and not isinstance(valor, bool):

                celdas.append(celda_numero(referencia, valor))

            else:

                celdas.append(celda_texto(referencia, valor))

        filas_xml.append(f'<row r="{numero_fila}">{"".join(celdas)}</row>')

    ultima_columna = letra_columna(len(columnas) - 1)

    ultima_fila = max(1, len(filas) + 1)

    anchos = "".join(
        f'<col min="{i + 1}" max="{i + 1}" width="'
        f'{22 if titulo == "Fecha y hora" else max(12, len(titulo) + 2)}" '
        f'customWidth="1"/>'
        for i, (titulo, _) in enumerate(columnas)
    )

    hoja = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        "</sheetView></sheetViews>"
        f"<cols>{anchos}</cols>"
        f'<sheetData>{"".join(filas_xml)}</sheetData>'
        f'<autoFilter ref="A1:{ultima_columna}{ultima_fila}"/>'
        "</worksheet>"
    )

    estilos = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="3"><fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFDCFCE7"/>'
        '<bgColor indexed="64"/></patternFill></fill></fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" '
        'applyFont="1" applyFill="1"/>'
        '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" '
        'applyNumberFormat="1"/>'
        "</cellXfs>"
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        "</styleSheet>"
    )

    contenido_tipos = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )

    relaciones = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )

    libro = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Mediciones" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )

    relaciones_libro = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )

    salida = io.BytesIO()

    with zipfile.ZipFile(salida, "w", zipfile.ZIP_DEFLATED) as paquete:

        paquete.writestr("[Content_Types].xml", contenido_tipos)
        paquete.writestr("_rels/.rels", relaciones)
        paquete.writestr("xl/workbook.xml", libro)
        paquete.writestr("xl/_rels/workbook.xml.rels", relaciones_libro)
        paquete.writestr("xl/styles.xml", estilos)
        paquete.writestr("xl/worksheets/sheet1.xml", hoja)

    return salida.getvalue()


def generar_csv(columnas, filas):
    """CSV en UTF-8 con BOM para que Excel respete tildes y símbolos."""

    salida = io.StringIO()

    escritor = csv.writer(salida)

    escritor.writerow([titulo for titulo, _ in columnas])

    for fila in filas:

        escritor.writerow([
            "" if leer(fila) is None else leer(fila)
            for _, leer in columnas
        ])

    return ("\ufeff" + salida.getvalue()).encode("utf-8")


@app.get(
    "/api/historial/exportar",
    tags=[TAG_NODOS],
    summary="Descargar el histórico (un nodo o todos) en Excel o CSV"
)
def exportar_historial(
    request: Request,
    nodo: str = "todos",
    formato: str = "xlsx",
    desde: str = None,
    hasta: str = None,
    variable: str = None,
    minimo: str = None,
    maximo: str = None
):

    if not verificar_sesion(request):

        return no_autorizado()

    def error(mensaje, codigo=400):

        return JSONResponse(
            status_code=codigo,
            content={
                "ok": False,
                "mensaje": mensaje
            }
        )

    nodo = str(nodo).strip().lower()

    if nodo == "todos":

        id_nodo = None

    elif nodo in ("1", "2", "3", "4"):

        id_nodo = int(nodo)

    else:

        return error("El nodo debe ser 1, 2, 3, 4 o 'todos'")

    formato = str(formato).strip().lower()

    if formato not in ("xlsx", "csv"):

        return error("El formato debe ser 'xlsx' o 'csv'")

    filtro_fechas, parametros_fechas, error_fechas = (
        construir_filtro_fechas(desde, hasta)
    )

    if error_fechas:

        return error(error_fechas)

    # Filtro opcional por valor de una variable: se suma al de fechas
    filtro_variable, parametros_variable, error_variable = (
        construir_filtro_variable(variable, minimo, maximo)
    )

    if error_variable:
        return error(error_variable)

    filtro_fechas = f"{filtro_fechas} {filtro_variable}"
    parametros_fechas = [*parametros_fechas, *parametros_variable]

    condicion_nodo = "AND nodo = ?" if id_nodo is not None else ""

    parametros = (
        ([id_nodo] if id_nodo is not None else [])
        + parametros_fechas
    )

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(f"""
        SELECT COUNT(*) AS total
        FROM mediciones
        WHERE 1 = 1
        {condicion_nodo}
        {filtro_fechas}
    """, parametros)

    total = cursor.fetchone()["total"]

    if total == 0:

        conexion.close()

        return error(
            "No hay mediciones para descargar con ese nodo y esos "
            "filtros",
            404
        )

    if total > LIMITE_FILAS_EXPORTACION:

        conexion.close()

        return error(
            f"Son {total} mediciones y el máximo por descarga es "
            f"{LIMITE_FILAS_EXPORTACION}. Acote el rango de fechas."
        )

    cursor.execute(f"""
        SELECT *
        FROM mediciones
        WHERE 1 = 1
        {condicion_nodo}
        {filtro_fechas}
        ORDER BY timestamp ASC, nodo ASC, id ASC
    """, parametros)

    filas = cursor.fetchall()

    conexion.close()

    if formato == "xlsx":

        contenido = generar_xlsx(COLUMNAS_EXPORTACION, filas)

        tipo = (
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )

    else:

        contenido = generar_csv(COLUMNAS_EXPORTACION, filas)

        tipo = "text/csv; charset=utf-8"

    partes = [
        "agrotech_historico",
        "todos" if id_nodo is None else f"nodo{id_nodo}"
    ]

    if desde or hasta:

        partes.append(f"{desde or 'inicio'}_a_{hasta or 'hoy'}")

    else:

        partes.append("completo")

    nombre_archivo = "_".join(partes) + f".{formato}"

    registrar_actividad(
        request,
        "EXPORTAR_DATOS",
        (
            f"{'todos los nodos' if id_nodo is None else f'Nodo {id_nodo}'}, "
            f"{desde or 'inicio'} a {hasta or 'hoy'}, "
            f"{formato}, {total} mediciones"
        )
    )

    return Response(
        content=contenido,
        media_type=tipo,
        headers={
            "Content-Disposition": f'attachment; filename="{nombre_archivo}"',
            "Cache-Control": "no-store"
        }
    )


# ============================================================
# HISTORIAL DE MEDICIONES
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/historial",
    tags=[TAG_NODOS],
    summary="Historial de mediciones de un nodo"
)
def obtener_historial(
    request: Request,
    id_nodo: int,
    pagina: int = None,
    por_pagina: int = 20,
    orden: str = "fecha",
    direccion: str = "desc",
    solo_radiacion: int = 0,
    desde: str = None,
    hasta: str = None,
    limite: int = 100,
    variable: str = None,
    minimo: str = None,
    maximo: str = None
):

    if not acceso_lectura(request):

        return no_autorizado()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "error": "Nodo inválido"
        }

    # Cantidad de mediciones que devuelve la versión sin paginar
    limite = max(1, min(limite, 2000))

    # Rango de fechas opcional (AAAA-MM-DD, ambas fechas incluidas)
    filtro_fechas, parametros_fechas, error_fechas = (
        construir_filtro_fechas(desde, hasta)
    )

    if error_fechas:

        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "mensaje": error_fechas
            }
        )

    # Filtro opcional por valor de una variable (por ejemplo
    # variable=nitrogeno&minimo=20&maximo=20). Se suma al de fechas,
    # así aplica al conteo, a la página y a la versión sin paginar.
    filtro_variable, parametros_variable, error_variable = (
        construir_filtro_variable(variable, minimo, maximo)
    )

    if error_variable:

        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "mensaje": error_variable
            }
        )

    filtro_fechas = f"{filtro_fechas} {filtro_variable}"
    parametros_fechas = [*parametros_fechas, *parametros_variable]

    # Con solo_radiacion=1 únicamente se consideran las mediciones
    # que traen radiación (piranómetro).
    filtro_radiacion = (
        "AND radiacion IS NOT NULL"
        if solo_radiacion
        else ""
    )

    # Columnas permitidas para ordenar (lista blanca)
    columnas_orden = {
        "fecha": "timestamp",
        "temperatura_dht": "temperatura_dht",
        "humedad_dht": "humedad_dht",
        "nitrogeno": "nitrogeno",
        "fosforo": "fosforo",
        "potasio": "potasio",
        "humedad_suelo": "humedad_suelo",
        "temperatura_suelo": "temperatura_suelo",
        "ec": "ec",
        "ph": "ph",
        "bateria": "bateria",
        "radiacion": "radiacion"
    }

    columna = columnas_orden.get(orden, "timestamp")

    sentido = "ASC" if direccion == "asc" else "DESC"

    conexion = conectar()
    cursor = conexion.cursor()

    # ------------------------------------------------------------
    # SIN "pagina": lo usan las gráficas.
    #   - orden=fecha (por defecto): las últimas "limite" mediciones,
    #     de la más reciente a la más antigua.
    #   - orden=<variable>: las "limite" mediciones con el mayor
    #     (direccion=desc) o menor (direccion=asc) valor de esa
    #     variable entre TODAS las registradas, sin contar vacíos.
    # ------------------------------------------------------------

    if pagina is None:

        if orden != "fecha" and orden in columnas_orden:

            cursor.execute(f"""
                SELECT *
                FROM mediciones
                WHERE nodo = ?
                AND {columna} IS NOT NULL
                {filtro_radiacion}
                {filtro_fechas}
                ORDER BY {columna} {sentido}, id DESC
                LIMIT ?
            """, (
                id_nodo,
                *parametros_fechas,
                limite
            ))

        else:

            cursor.execute(f"""
                SELECT *
                FROM mediciones
                WHERE nodo = ?
                {filtro_radiacion}
                {filtro_fechas}
                ORDER BY id DESC
                LIMIT ?
            """, (
                id_nodo,
                *parametros_fechas,
                limite
            ))

        filas = cursor.fetchall()
        conexion.close()

        resultado = []

        for medicion in filas:

            lectura = construir_json_lectura(medicion)
            lectura["id"] = medicion["id"]
            resultado.append(lectura)

        return resultado

    # ------------------------------------------------------------
    # CON "pagina": histórico paginado y ordenable
    # ------------------------------------------------------------

    por_pagina = max(5, min(por_pagina, 100))
    pagina = max(1, pagina)

    cursor.execute(f"""
        SELECT COUNT(*) AS total
        FROM mediciones
        WHERE nodo = ?
        {filtro_radiacion}
        {filtro_fechas}
    """, (
        id_nodo,
        *parametros_fechas
    ))

    total = cursor.fetchone()["total"]

    paginas = max(1, (total + por_pagina - 1) // por_pagina)

    pagina = min(pagina, paginas)

    desplazamiento = (pagina - 1) * por_pagina

    # Los valores vacíos (NULL) siempre quedan al final
    cursor.execute(f"""
        SELECT *
        FROM mediciones
        WHERE nodo = ?
        {filtro_radiacion}
        {filtro_fechas}
        ORDER BY ({columna} IS NULL), {columna} {sentido}, id {sentido}
        LIMIT ? OFFSET ?
    """, (
        id_nodo,
        *parametros_fechas,
        por_pagina,
        desplazamiento
    ))

    filas = cursor.fetchall()
    conexion.close()

    datos = []

    for medicion in filas:

        lectura = construir_json_lectura(medicion)
        lectura["id"] = medicion["id"]
        datos.append(lectura)

    return {
        "total": total,
        "pagina": pagina,
        "por_pagina": por_pagina,
        "paginas": paginas,
        "orden": orden if orden in columnas_orden else "fecha",
        "direccion": sentido.lower(),
        "datos": datos
    }


# ============================================================
# CONFIGURACIÓN GENERAL
# ============================================================

@app.get(
    "/api/configuracion",
    tags=[TAG_HORARIOS],
    summary="Horarios de todos los nodos · administrador"
)
def obtener_configuracion(
    request: Request
):

    if not verificar_sesion(request):

        return no_autorizado()

    if not es_administrador(request):

        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM configuracion_mediciones
        ORDER BY nodo
    """)

    configuraciones = (
        cursor.fetchall()
    )

    conexion.close()

    resultado = []

    for config in configuraciones:

        resultado.append({

            "nodo": (
                config["nodo"]
            ),

            "nodo_id": nombre_nodo(
                config["nodo"]
            ),

            "cantidad_diaria": (
                config[
                    "cantidad_diaria"
                ]
            ),

            "horarios": (
                config["horarios"]
            )

        })

    return resultado


# ============================================================
# CONFIGURACIÓN DE UN NODO
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/configuracion",
    tags=[TAG_HORARIOS],
    summary="Horarios de un nodo · administrador"
)
def obtener_configuracion_nodo(
    request: Request,
    id_nodo: int
):

    if not verificar_sesion(request):

        return no_autorizado()

    if not es_administrador(request):

        return prohibido()

    if id_nodo not in [1, 2, 3, 4]:

        return {
            "error": "Nodo inválido"
        }

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM configuracion_mediciones
        WHERE nodo = ?
    """, (
        id_nodo,
    ))

    config = cursor.fetchone()

    conexion.close()

    if config is None:

        return {
            "error": (
                "Configuración "
                "no encontrada"
            )
        }

    return {

        "nodo": (
            config["nodo"]
        ),

        "nodo_id": nombre_nodo(
            config["nodo"]
        ),

        "cantidad_diaria": (
            config[
                "cantidad_diaria"
            ]
        ),

        "horarios": (
            config["horarios"]
        )

    }




# ============================================================
# ADMINISTRACIÓN DE USUARIOS
# SOLO PERFIL PRINCIPAL
# ============================================================

def obtener_usuario_por_id(cursor, id_usuario):
    cursor.execute("""
        SELECT
            id,
            usuario,
            rol,
            activo
        FROM usuarios
        WHERE id = ?
    """, (id_usuario,))
    return cursor.fetchone()


@app.get(
    "/api/usuarios",
    tags=[TAG_USUARIOS],
    summary="Listar usuarios con último ingreso y último cambio · principal"
)
def listar_usuarios(request: Request):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            u.id,
            u.usuario,
            u.rol,
            u.activo,
            (
                SELECT MAX(r.fecha_hora)
                FROM registros_actividad r
                WHERE r.usuario_id = u.id
                  AND r.accion = 'LOGIN'
            ) AS ultimo_acceso,
            (
                SELECT MAX(r.fecha_hora)
                FROM registros_actividad r
                WHERE r.usuario_id = u.id
                  AND r.accion NOT IN ('LOGIN', 'LOGOUT')
            ) AS ultimo_cambio
        FROM usuarios u
        ORDER BY
            CASE u.rol
                WHEN 'principal' THEN 1
                WHEN 'administrador' THEN 2
                ELSE 3
            END,
            u.usuario
    """)

    usuarios = cursor.fetchall()
    conexion.close()

    return [
        {
            "id": u["id"],
            "usuario": u["usuario"],
            "rol": u["rol"],
            "activo": bool(u["activo"]),
            "ultimo_acceso": u["ultimo_acceso"],
            "ultimo_cambio": u["ultimo_cambio"]
        }
        for u in usuarios
    ]


@app.post(
    "/api/usuarios",
    tags=[TAG_USUARIOS],
    summary="Crear usuario · principal"
)
def crear_usuario_api(
    request: Request,
    datos: dict = Body(..., examples=[EJEMPLO_CREAR_USUARIO])
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    usuario = datos.get("usuario")
    password = datos.get("password")
    rol = datos.get("rol", "usuario")

    if not isinstance(usuario, str) or not usuario.strip():
        return JSONResponse(
            status_code=400,
            content={"error": "El usuario es obligatorio"}
        )

    if not isinstance(password, str) or len(password) < 6:
        return JSONResponse(
            status_code=400,
            content={
                "error": "La contraseña debe tener mínimo 6 caracteres"
            }
        )

    usuario = usuario.strip()

    if usuario.upper() == "AGROTECH":
        return JSONResponse(
            status_code=400,
            content={
                "error": (
                    "AGROTECH está reservado para la cuenta principal"
                )
            }
        )

    if rol not in ("administrador", "usuario"):
        return JSONResponse(
            status_code=400,
            content={
                "error": (
                    "El rol debe ser administrador o usuario"
                )
            }
        )

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT id FROM usuarios WHERE usuario = ?",
        (usuario,)
    )

    if cursor.fetchone() is not None:
        conexion.close()
        return JSONResponse(
            status_code=409,
            content={
                "error": "Ya existe un usuario con ese nombre"
            }
        )

    cursor.execute("""
        INSERT INTO usuarios (
            usuario,
            password_hash,
            rol,
            activo
        )
        VALUES (?, ?, ?, 1)
    """, (
        usuario,
        hashear_password(password),
        rol
    ))

    id_usuario = cursor.lastrowid

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "CREAR_USUARIO",
        f"Usuario creado: {usuario} | Rol: {rol}"
    )

    return {
        "ok": True,
        "mensaje": "Usuario creado correctamente",
        "id": id_usuario,
        "usuario": usuario,
        "rol": rol,
        "activo": True
    }


@app.put(
    "/api/usuarios/{id_usuario}",
    tags=[TAG_USUARIOS],
    summary="Editar usuario: nombre, rol o contraseña · principal"
)
def actualizar_usuario_api(
    request: Request,
    id_usuario: int,
    datos: dict = Body(..., examples=[EJEMPLO_ACTUALIZAR_USUARIO])
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    usuario_db = obtener_usuario_por_id(
        cursor,
        id_usuario
    )

    if usuario_db is None:
        conexion.close()
        return JSONResponse(
            status_code=404,
            content={"error": "Usuario no encontrado"}
        )

    nombre = datos.get("usuario")
    nuevo_rol = datos.get("rol")
    nueva_password = datos.get("password")

    # La cuenta AGROTECH siempre conserva rol principal y nombre.
    if usuario_db["usuario"].upper() == "AGROTECH":

        if nombre is not None and nombre != "AGROTECH":
            conexion.close()
            return JSONResponse(
                status_code=400,
                content={
                    "error": "La cuenta AGROTECH no puede cambiar de nombre"
                }
            )

        if nuevo_rol is not None and nuevo_rol != "principal":
            conexion.close()
            return JSONResponse(
                status_code=400,
                content={
                    "error": "La cuenta AGROTECH debe conservar el rol principal"
                }
            )

    else:

        if nombre is not None:

            if (
                not isinstance(nombre, str)
                or not nombre.strip()
            ):
                conexion.close()
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Nombre de usuario inválido"
                    }
                )

            nombre = nombre.strip()

            if nombre.upper() == "AGROTECH":
                conexion.close()
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Ese nombre está reservado"
                    }
                )

            cursor.execute("""
                SELECT id
                FROM usuarios
                WHERE usuario = ?
                AND id <> ?
            """, (
                nombre,
                id_usuario
            ))

            if cursor.fetchone() is not None:
                conexion.close()
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": "Ese nombre de usuario ya existe"
                    }
                )

            cursor.execute("""
                UPDATE usuarios
                SET usuario = ?
                WHERE id = ?
            """, (
                nombre,
                id_usuario
            ))

        if nuevo_rol is not None:

            if nuevo_rol not in (
                "administrador",
                "usuario"
            ):
                conexion.close()
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": (
                            "Solo se permiten los roles "
                            "administrador y usuario"
                        )
                    }
                )

            cursor.execute("""
                UPDATE usuarios
                SET rol = ?
                WHERE id = ?
            """, (
                nuevo_rol,
                id_usuario
            ))

    if nueva_password is not None:

        if (
            not isinstance(nueva_password, str)
            or len(nueva_password) < 6
        ):
            conexion.close()
            return JSONResponse(
                status_code=400,
                content={
                    "error": (
                        "La contraseña debe tener mínimo "
                        "6 caracteres"
                    )
                }
            )

        cursor.execute("""
            UPDATE usuarios
            SET password_hash = ?
            WHERE id = ?
        """, (
            hashear_password(nueva_password),
            id_usuario
        ))

    conexion.commit()

    cursor.execute("""
        SELECT id, usuario, rol, activo
        FROM usuarios
        WHERE id = ?
    """, (id_usuario,))

    actualizado = cursor.fetchone()
    conexion.close()

    if nueva_password is not None:
        accion = "CAMBIAR_PASSWORD"
        detalle = (
            f"Contraseña cambiada para: "
            f"{actualizado['usuario']}"
        )
    else:
        accion = "ACTUALIZAR_USUARIO"
        detalle = (
            f"Usuario actualizado: "
            f"{actualizado['usuario']}"
        )

    registrar_actividad(
        request,
        accion,
        detalle
    )

    return {
        "ok": True,
        "mensaje": "Usuario actualizado correctamente",
        "usuario": {
            "id": actualizado["id"],
            "usuario": actualizado["usuario"],
            "rol": actualizado["rol"],
            "activo": bool(actualizado["activo"])
        }
    }


@app.post(
    "/api/cuenta/password",
    tags=[TAG_USUARIOS],
    summary="Cambiar la contraseña de la cuenta principal (pide la actual) · principal"
)
def cambiar_mi_password(
    request: Request,
    datos: dict = Body(...)
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    def error(mensaje, codigo=400):
        return JSONResponse(
            status_code=codigo,
            content={"ok": False, "error": mensaje}
        )

    actual = datos.get("password_actual")
    nueva = datos.get("password_nueva")

    if not isinstance(actual, str) or not actual:
        return error("Escriba la contraseña actual")

    if not isinstance(nueva, str) or len(nueva) < 6:
        return error("La contraseña nueva debe tener mínimo 6 caracteres")

    if len(nueva) > 200:
        return error("La contraseña nueva es demasiado larga")

    if nueva == actual:
        return error("La contraseña nueva debe ser diferente a la actual")

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT id, usuario, password_hash
        FROM usuarios
        WHERE id = ?
    """, (request.session.get("usuario_id"),))

    cuenta = cursor.fetchone()

    if cuenta is None:
        conexion.close()
        return error("No se encontró la cuenta", 404)

    actual_correcta, _ = verificar_password(
        actual,
        cuenta["password_hash"]
    )

    if not actual_correcta:

        conexion.close()

        registrar_actividad(
            request,
            "CAMBIAR_PASSWORD_FALLIDO",
            f"Contraseña actual incorrecta para: {cuenta['usuario']}"
        )

        return error("La contraseña actual es incorrecta", 403)

    cursor.execute("""
        UPDATE usuarios
        SET password_hash = ?
        WHERE id = ?
    """, (
        hashear_password(nueva),
        cuenta["id"]
    ))

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "CAMBIAR_PASSWORD",
        f"La cuenta {cuenta['usuario']} cambió su propia contraseña"
    )

    return {
        "ok": True,
        "mensaje": "Contraseña actualizada correctamente"
    }


@app.put(
    "/api/usuarios/{id_usuario}/activar",
    tags=[TAG_USUARIOS],
    summary="Activar usuario · principal"
)
def activar_usuario(
    request: Request,
    id_usuario: int
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    usuario_db = obtener_usuario_por_id(
        cursor,
        id_usuario
    )

    if usuario_db is None:
        conexion.close()
        return JSONResponse(
            status_code=404,
            content={"error": "Usuario no encontrado"}
        )

    cursor.execute("""
        UPDATE usuarios
        SET activo = 1
        WHERE id = ?
    """, (id_usuario,))

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "ACTIVAR_USUARIO",
        f"Usuario activado: {usuario_db['usuario']}"
    )

    return {
        "ok": True,
        "mensaje": "Usuario activado correctamente"
    }


@app.put(
    "/api/usuarios/{id_usuario}/desactivar",
    tags=[TAG_USUARIOS],
    summary="Desactivar usuario · principal"
)
def desactivar_usuario(
    request: Request,
    id_usuario: int
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    usuario_db = obtener_usuario_por_id(
        cursor,
        id_usuario
    )

    if usuario_db is None:
        conexion.close()
        return JSONResponse(
            status_code=404,
            content={"error": "Usuario no encontrado"}
        )

    if usuario_db["usuario"].upper() == "AGROTECH":
        conexion.close()
        return JSONResponse(
            status_code=400,
            content={
                "error": "La cuenta AGROTECH no puede desactivarse"
            }
        )

    if (
        usuario_db["id"]
        == request.session.get("usuario_id")
    ):
        conexion.close()
        return JSONResponse(
            status_code=400,
            content={
                "error": "No puede desactivar su propia cuenta"
            }
        )

    cursor.execute("""
        UPDATE usuarios
        SET activo = 0
        WHERE id = ?
    """, (id_usuario,))

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "DESACTIVAR_USUARIO",
        f"Usuario desactivado: {usuario_db['usuario']}"
    )

    return {
        "ok": True,
        "mensaje": "Usuario desactivado correctamente"
    }


@app.delete(
    "/api/usuarios/{id_usuario}",
    tags=[TAG_USUARIOS],
    summary="Eliminar usuario · principal"
)
def eliminar_usuario(
    request: Request,
    id_usuario: int
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    conexion = conectar()
    cursor = conexion.cursor()

    usuario_db = obtener_usuario_por_id(
        cursor,
        id_usuario
    )

    if usuario_db is None:
        conexion.close()
        return JSONResponse(
            status_code=404,
            content={"error": "Usuario no encontrado"}
        )

    if usuario_db["usuario"].upper() == "AGROTECH":
        conexion.close()
        return JSONResponse(
            status_code=400,
            content={
                "error": "La cuenta AGROTECH no puede eliminarse"
            }
        )

    if (
        usuario_db["id"]
        == request.session.get("usuario_id")
    ):
        conexion.close()
        return JSONResponse(
            status_code=400,
            content={
                "error": "No puede eliminar su propia cuenta"
            }
        )

    cursor.execute(
        "DELETE FROM usuarios WHERE id = ?",
        (id_usuario,)
    )

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "ELIMINAR_USUARIO",
        f"Usuario eliminado: {usuario_db['usuario']}"
    )

    return {
        "ok": True,
        "mensaje": "Usuario eliminado correctamente"
    }


@app.get(
    "/api/actividad",
    tags=[TAG_USUARIOS],
    summary="Registro de actividad, con filtro opcional por usuario · principal"
)
def listar_actividad(
    request: Request,
    limite: int = 200,
    usuario: str = None
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_principal(request):
        return prohibido()

    limite = max(
        1,
        min(int(limite), 500)
    )

    conexion = conectar()
    cursor = conexion.cursor()

    if usuario:
        cursor.execute("""
            SELECT
                id,
                usuario_id,
                usuario,
                accion,
                detalle,
                fecha_hora,
                ip
            FROM registros_actividad
            WHERE usuario = ?
            ORDER BY id DESC
            LIMIT ?
        """, (usuario, limite))
    else:
        cursor.execute("""
            SELECT
                id,
                usuario_id,
                usuario,
                accion,
                detalle,
                fecha_hora,
                ip
            FROM registros_actividad
            ORDER BY id DESC
            LIMIT ?
        """, (limite,))

    registros = cursor.fetchall()
    conexion.close()

    return [
        {
            "id": r["id"],
            "usuario_id": r["usuario_id"],
            "usuario": r["usuario"],
            "accion": r["accion"],
            "detalle": r["detalle"],
            "fecha_hora": r["fecha_hora"],
            "ip": r["ip"]
        }
        for r in registros
    ]


# ============================================================
# CONFIGURACIÓN REMOTA DE HORARIOS
# Dashboard -> Nube (este main.py) -> Raspberry -> ESP32

# Como la nube no puede conectarse a la Raspberry (está detrás del router),
# la Raspberry consulta cada ~30 s si hay una configuración pendiente
# (ver raspberry_parche_horarios.py).
# ============================================================

import json
import re

MAX_HORARIOS = 48   # límite razonable de despertares por día

_PATRON_HHMM = re.compile(r"^(\d{1,2}):(\d{1,2})$")


# ------------------------------------------------------------
# Tabla de control de sincronización (no toca configuracion_mediciones)
#   version            : sube +1 cada vez que el dashboard guarda
#   version_publicada  : última versión que la Raspberry publicó por MQTT
#   version_aplicada   : última versión que el ESP32 confirmó (configok)
# ------------------------------------------------------------

def crear_tabla_config_sync():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config_sync (
            nodo              INTEGER PRIMARY KEY,
            version           INTEGER NOT NULL DEFAULT 0,
            version_publicada INTEGER NOT NULL DEFAULT 0,
            version_aplicada  INTEGER NOT NULL DEFAULT 0,
            horarios          TEXT    NOT NULL DEFAULT '',
            detalle           TEXT,
            actualizado       TEXT
        )
    """)

    conexion.commit()
    conexion.close()


crear_tabla_config_sync()


# ------------------------------------------------------------
# Utilidades
# ------------------------------------------------------------

def verificar_api_key(request: Request):
    """Autentica a la Raspberry con la misma X-API-Key de los datos."""

    api_key = request.headers.get("X-API-Key", "")

    return hmac.compare_digest(
        api_key.encode("utf-8"),
        API_KEY_NODOS.encode("utf-8")
    )


def api_key_invalida():

    return JSONResponse(
        status_code=401,
        content={
            "ok": False,
            "mensaje": "API key inválida o ausente"
        }
    )


def normalizar_horarios_entrada(valor):
    """
    Acepta:
        ["06:00", "12:30"]          (lista)
        "06:00,12:30"               (texto separado por comas)
        '["06:00","12:30"]'         (JSON en texto)
    Devuelve una lista ordenada, sin duplicados, en formato HH:MM.
    Lanza ValueError con un mensaje claro si algo es inválido.
    """

    if isinstance(valor, str):

        texto = valor.strip()

        if texto.startswith("["):
            try:
                valor = json.loads(texto)
            except ValueError:
                raise ValueError("horarios no es un JSON válido")
        else:
            valor = [p for p in re.split(r"[,;\s]+", texto) if p]

    if not isinstance(valor, list):
        raise ValueError(
            "horarios debe ser una lista o texto separado por comas"
        )

    resultado = set()

    for item in valor:

        texto = str(item).strip()

        # Compatibilidad con horarios antiguos: 10 -> 10:00
        if texto.isdigit():
            texto = f"{texto}:00"

        coincidencia = _PATRON_HHMM.match(texto)

        if not coincidencia:
            raise ValueError(f"Horario inválido: {item!r} (use HH:MM)")

        hora = int(coincidencia.group(1))
        minuto = int(coincidencia.group(2))

        if hora > 23 or minuto > 59:
            raise ValueError(f"Horario fuera de rango: {item!r}")

        resultado.add(f"{hora:02d}:{minuto:02d}")

    if not resultado:
        raise ValueError("Debe existir al menos un horario")

    if len(resultado) > MAX_HORARIOS:
        raise ValueError(f"No se permiten más de {MAX_HORARIOS} horarios")

    # HH:MM con ceros a la izquierda ordena bien como texto
    return sorted(resultado)


def ahora_local():

    return (
        datetime.utcnow() + ZONA_HORARIA
    ).strftime("%Y-%m-%d %H:%M:%S")


# ============================================================
# MODIFICAR CONFIGURACIÓN (principal y administrador)
# ============================================================

@app.put(
    "/api/nodos/{id_nodo}/configuracion",
    tags=[TAG_HORARIOS],
    summary="Guardar nuevos horarios de un nodo · administrador"
)
def modificar_configuracion(
    request: Request,
    id_nodo: int,
    datos: dict = Body(..., examples=[EJEMPLO_HORARIOS])
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not verificar_admin(request):
        return prohibido()

    if id_nodo not in [1, 2, 3, 4]:
        return JSONResponse(
            status_code=400,
            content={"error": "Nodo inválido"}
        )

    if datos.get("horarios") is None:
        return JSONResponse(
            status_code=400,
            content={"error": "Faltan horarios"}
        )

    try:
        horarios = normalizar_horarios_entrada(datos.get("horarios"))
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"error": str(e)}
        )

    # La cantidad siempre se deriva de la lista: así nunca se desincronizan
    cantidad_diaria = len(horarios)
    horarios_texto = ",".join(horarios)

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE configuracion_mediciones
        SET cantidad_diaria = ?,
            horarios = ?
        WHERE nodo = ?
    """, (
        cantidad_diaria,
        horarios_texto,
        id_nodo
    ))

    if cursor.rowcount == 0:
        conexion.rollback()
        conexion.close()
        return JSONResponse(
            status_code=404,
            content={"error": "Configuración no encontrada"}
        )

    # Marca la configuración como pendiente para la Raspberry
    cursor.execute("""
        INSERT INTO config_sync (nodo, version, horarios, actualizado)
        VALUES (?, 1, ?, ?)
        ON CONFLICT(nodo) DO UPDATE SET
            version     = version + 1,
            horarios    = excluded.horarios,
            detalle     = NULL,
            actualizado = excluded.actualizado
    """, (
        id_nodo,
        horarios_texto,
        ahora_local()
    ))

    cursor.execute(
        "SELECT version FROM config_sync WHERE nodo = ?",
        (id_nodo,)
    )

    version = cursor.fetchone()["version"]

    conexion.commit()
    conexion.close()

    registrar_actividad(
        request,
        "CAMBIAR_CONFIGURACION",
        (
            f"Nodo {id_nodo}: "
            f"horarios={horarios_texto}"
        )
    )

    return {
        "ok": True,
        "mensaje": (
            "Configuración guardada. Se enviará al nodo "
            "cuando la Raspberry la recoja."
        ),
        "nodo": id_nodo,
        "nodo_id": nombre_nodo(id_nodo),
        "cantidad_diaria": cantidad_diaria,
        "horarios": horarios,
        "version": version,
        "estado": "pendiente"
    }


# ============================================================
# ESTADO DE LA CONFIGURACIÓN  (para mostrarlo en el dashboard)
# ============================================================

@app.get(
    "/api/nodos/{id_nodo}/configuracion/estado",
    tags=[TAG_HORARIOS],
    summary="Estado del envío de horarios al nodo · administrador"
)
def estado_configuracion(
    request: Request,
    id_nodo: int
):

    if not verificar_sesion(request):
        return no_autorizado()

    if not es_administrador(request):

        return prohibido()

    if id_nodo not in [1, 2, 3, 4]:
        return JSONResponse(
            status_code=400,
            content={"error": "Nodo inválido"}
        )

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT * FROM config_sync WHERE nodo = ?",
        (id_nodo,)
    )

    fila = cursor.fetchone()
    conexion.close()

    if fila is None:
        return {
            "nodo": id_nodo,
            "estado": "sin_cambios",
            "mensaje": "Sin cambios remotos"
        }

    if fila["version"] > fila["version_publicada"]:
        estado = "pendiente"
        mensaje = "Esperando a que la Raspberry recoja la configuración"
    elif fila["version"] > fila["version_aplicada"]:
        estado = "publicada"
        mensaje = (
            "Enviada al nodo; se aplicará cuando despierte"
        )
    else:
        estado = "aplicada"
        mensaje = "El nodo confirmó la nueva configuración"

    return {
        "nodo": id_nodo,
        "nodo_id": nombre_nodo(id_nodo),
        "estado": estado,
        "mensaje": mensaje,
        "version": fila["version"],
        "horarios": fila["horarios"].split(",") if fila["horarios"] else [],
        "detalle": fila["detalle"],
        "actualizado": fila["actualizado"]
    }


# ============================================================
# RASPBERRY: CONSULTAR CONFIGURACIONES PENDIENTES  (X-API-Key)
# ============================================================

@app.get(
    "/api/configuracion/pendientes",
    tags=[TAG_RASPBERRY],
    summary="3 · Consultar horarios pendientes",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY
)
def configuraciones_pendientes(
    request: Request
):

    if not verificar_api_key(request):
        return api_key_invalida()

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT nodo, version, horarios
        FROM config_sync
        WHERE version > version_publicada
        ORDER BY nodo
    """)

    filas = cursor.fetchall()
    conexion.close()

    return {
        "ok": True,
        "pendientes": [
            {
                "nodo": f["nodo"],
                "nodo_id": nombre_nodo(f["nodo"]),
                "version": f["version"],
                "horarios": f["horarios"].split(","),
            }
            for f in filas
        ]
    }


# ============================================================
# RASPBERRY: CONFIRMAR PUBLICACIÓN / APLICACIÓN  (X-API-Key)
#   estado = "publicada"  -> la Raspberry ya la publicó por MQTT
#   estado = "aplicada"   -> el ESP32 respondió con configok
#   estado = "error"      -> falló; queda pendiente y se reintenta
# ============================================================

@app.post(
    "/api/nodos/{id_nodo}/configuracion/confirmar",
    tags=[TAG_RASPBERRY],
    summary="4 · Confirmar horarios publicados o aplicados",
    dependencies=[Security(esquema_api_key)],
    responses=RESPUESTA_401_RASPBERRY
)
def confirmar_configuracion(
    request: Request,
    id_nodo: int,
    datos: dict = Body(..., examples=[EJEMPLO_CONFIRMAR])
):

    if not verificar_api_key(request):
        return api_key_invalida()

    if id_nodo not in [1, 2, 3, 4]:
        return {"ok": False, "mensaje": "Nodo inválido"}

    version = datos.get("version")
    estado = datos.get("estado")
    detalle = str(datos.get("detalle", ""))[:300]

    if not isinstance(version, int) or isinstance(version, bool):
        return {"ok": False, "mensaje": "version debe ser un entero"}

    if estado not in ("publicada", "aplicada", "error"):
        return {
            "ok": False,
            "mensaje": "estado debe ser publicada, aplicada o error"
        }

    conexion = conectar()
    cursor = conexion.cursor()

    if estado == "publicada":
        cursor.execute("""
            UPDATE config_sync
            SET version_publicada = MAX(version_publicada, ?),
                detalle = NULL
            WHERE nodo = ? AND ? <= version
        """, (version, id_nodo, version))

    elif estado == "aplicada":
        cursor.execute("""
            UPDATE config_sync
            SET version_publicada = MAX(version_publicada, ?),
                version_aplicada  = MAX(version_aplicada, ?),
                detalle = NULL
            WHERE nodo = ? AND ? <= version
        """, (version, version, id_nodo, version))

    else:
        cursor.execute("""
            UPDATE config_sync
            SET detalle = ?
            WHERE nodo = ?
        """, (detalle, id_nodo))

    conexion.commit()
    conexion.close()

    return {"ok": True}