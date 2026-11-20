import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "datos.db"


def conectar():
    conexion = sqlite3.connect(DATABASE)
    conexion.row_factory = sqlite3.Row
    return conexion


# ============================================================
# TABLAS PRINCIPALES
# ============================================================

def crear_tabla_datos():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nodos (
            id INTEGER PRIMARY KEY,
            ubicacion TEXT,
            cultivo TEXT,
            estado TEXT,
            ultima_conexion TEXT
        )
    """)

    for nodo in range(1, 5):

        cursor.execute("""
            INSERT OR IGNORE INTO nodos (
                id,
                ubicacion,
                cultivo,
                estado,
                ultima_conexion
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            nodo,
            f"Nodo {nodo}",
            "",
            "inactivo",
            None
        ))

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mediciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nodo INTEGER NOT NULL,
            tipo TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            temperatura_dht REAL,
            humedad_dht REAL,
            nitrogeno REAL,
            fosforo REAL,
            potasio REAL,
            humedad_suelo REAL,
            temperatura_suelo REAL,
            ec REAL,
            ph REAL,
            bateria REAL,
            radiacion REAL
        )
    """)

    # Compatibilidad: bases de datos creadas antes de guardar la radiación
    # (piranómetro). Se agrega la columna sin borrar las mediciones.

    cursor.execute("""
        PRAGMA table_info(mediciones)
    """)

    columnas_mediciones = [
        fila["name"]
        for fila in cursor.fetchall()
    ]

    if "radiacion" not in columnas_mediciones:

        cursor.execute("""
            ALTER TABLE mediciones
            ADD COLUMN radiacion REAL
        """)

    conexion.commit()
    conexion.close()


# ============================================================
# TABLA DE FOTOGRAFÍAS
# ============================================================

def crear_tabla_fotos():

    """
    Guarda la última fotografía recibida de cada nodo.
    """

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fotos (
            nodo INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            imagen BLOB NOT NULL,
            tam_bytes INTEGER NOT NULL
        )
    """)

    conexion.commit()
    conexion.close()


# ============================================================
# FOTOS FIJAS DE SEGUIMIENTO (3 por nodo, cargadas desde el dashboard)
# ============================================================

def crear_tabla_fotos_fijas():

    """
    Hasta 3 fotografías fijas por nodo para llevar seguimiento del
    cultivo. Solo cambian cuando un administrador las reemplaza; la
    foto que envía la Raspberry sigue en la tabla "fotos" (una sola
    por nodo, que se sobrescribe), así la base no acumula imágenes.
    """

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fotos_fijas (
            nodo INTEGER NOT NULL,
            posicion INTEGER NOT NULL CHECK (posicion BETWEEN 1 AND 3),
            etiqueta TEXT,
            imagen BLOB NOT NULL,
            tipo TEXT NOT NULL,
            tam_bytes INTEGER NOT NULL,
            subido_en TEXT NOT NULL,
            subido_por TEXT,
            PRIMARY KEY (nodo, posicion)
        )
    """)

    conexion.commit()
    conexion.close()


# ============================================================
# CONFIGURACIÓN DE MEDICIONES
# ============================================================

def crear_tabla_configuracion():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS configuracion_mediciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nodo INTEGER UNIQUE NOT NULL,
            cantidad_diaria INTEGER NOT NULL,
            horarios TEXT NOT NULL
        )
    """)

    conexion.commit()
    conexion.close()


def crear_configuracion_inicial():

    conexion = conectar()
    cursor = conexion.cursor()

    configuraciones = [
        (1, 4, "06:00,10:00,14:00,18:00"),
        (2, 4, "06:00,10:00,14:00,18:00"),
        (3, 4, "06:00,10:00,14:00,18:00"),
        (4, 4, "06:00,10:00,14:00,18:00")
    ]

    for nodo, cantidad, horarios in configuraciones:

        cursor.execute("""
            INSERT OR IGNORE INTO configuracion_mediciones (
                nodo,
                cantidad_diaria,
                horarios
            )
            VALUES (?, ?, ?)
        """, (
            nodo,
            cantidad,
            horarios
        ))

    conexion.commit()
    conexion.close()


# ============================================================
# USUARIOS
# ============================================================

def crear_tabla_usuarios():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL,
            activo INTEGER NOT NULL DEFAULT 1
        )
    """)

    # --------------------------------------------------------
    # COMPATIBILIDAD CON LA BASE DE DATOS EXISTENTE
    # --------------------------------------------------------
    # Si la tabla usuarios ya existía sin la columna "activo",
    # se agrega sin borrar los usuarios existentes.

    cursor.execute("""
        PRAGMA table_info(usuarios)
    """)

    columnas = [
        fila["name"]
        for fila in cursor.fetchall()
    ]

    if "activo" not in columnas:

        cursor.execute("""
            ALTER TABLE usuarios
            ADD COLUMN activo INTEGER NOT NULL DEFAULT 1
        """)

    conexion.commit()
    conexion.close()


# ============================================================
# USUARIOS INICIALES
# ============================================================
#
# Las contraseñas iniciales NO están escritas en el código.
#
# Al crear cada cuenta por primera vez, la contraseña se toma de
# una variable de entorno:
#
#     AGROTECH_PASSWORD_PRINCIPAL   -> cuenta AGROTECH (principal)
#     AGROTECH_PASSWORD_ADMIN       -> cuenta admin (administrador)
#     AGROTECH_PASSWORD_USUARIO     -> cuenta usuario (consulta)
#
# Si la variable no existe, se genera una contraseña aleatoria y
# se anota en el archivo "credenciales_iniciales.txt" (junto a
# este módulo, con permisos 600 y fuera del repositorio). Conviene
# cambiarla desde el dashboard y borrar ese archivo.
#
# Las cuentas que ya existen en la base no se tocan.

ITERACIONES_INICIALES = 240_000

ARCHIVO_CREDENCIALES = BASE_DIR / "credenciales_iniciales.txt"


def hash_password_inicial(password):

    """
    Mismo formato PBKDF2 que usa main.py:

        pbkdf2$<iteraciones>$<sal>$<hash>
    """

    import hashlib
    import secrets

    sal = secrets.token_hex(16)

    hash_hex = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        sal.encode("utf-8"),
        ITERACIONES_INICIALES
    ).hex()

    return f"pbkdf2${ITERACIONES_INICIALES}${sal}${hash_hex}"


def crear_usuarios_iniciales():

    import os
    import secrets

    conexion = conectar()
    cursor = conexion.cursor()

    usuarios = [

        # Usuario principal del sistema
        (
            "AGROTECH",
            "AGROTECH_PASSWORD_PRINCIPAL",
            "principal"
        ),

        # Administrador
        (
            "admin",
            "AGROTECH_PASSWORD_ADMIN",
            "administrador"
        ),

        # Usuario de consulta
        (
            "usuario",
            "AGROTECH_PASSWORD_USUARIO",
            "usuario"
        )
    ]

    generadas = []

    for usuario, variable_entorno, rol in usuarios:

        cursor.execute("""
            SELECT id
            FROM usuarios
            WHERE usuario = ?
        """, (
            usuario,
        ))

        registro = cursor.fetchone()

        if registro is None:

            password = os.environ.get(variable_entorno)

            if not password:

                password = secrets.token_urlsafe(9)

                generadas.append((usuario, password))

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
                hash_password_inicial(password),
                rol
            ))

        else:

            # ------------------------------------------------
            # ACTUALIZAR EL ROL DEL USUARIO EXISTENTE
            # ------------------------------------------------
            #
            # Esto es importante para el usuario "admin",
            # porque anteriormente tenía el rol "admin".
            #
            # Ahora debe ser "administrador".
            #

            cursor.execute("""
                UPDATE usuarios
                SET rol = ?
                WHERE usuario = ?
            """, (
                rol,
                usuario
            ))

    conexion.commit()
    conexion.close()

    # --------------------------------------------------------
    # ANOTAR LAS CONTRASEÑAS GENERADAS
    # --------------------------------------------------------

    if generadas:

        with open(ARCHIVO_CREDENCIALES, "a", encoding="utf-8") as archivo:

            archivo.write(
                "# Contraseñas iniciales generadas por AGROTECH.\n"
                "# Cámbielas desde el dashboard y borre este archivo.\n"
            )

            for usuario, password in generadas:

                archivo.write(f"{usuario}: {password}\n")

        try:
            ARCHIVO_CREDENCIALES.chmod(0o600)
        except Exception:
            pass


# ============================================================
# REGISTRO DE ACTIVIDAD
# ============================================================

def crear_tabla_registros_actividad():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registros_actividad (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            usuario TEXT NOT NULL,
            accion TEXT NOT NULL,
            detalle TEXT,
            fecha_hora TEXT NOT NULL,
            ip TEXT,
            FOREIGN KEY (usuario_id)
                REFERENCES usuarios(id)
        )
    """)

    conexion.commit()
    conexion.close()


# ============================================================
# ALERTAS DEL ANÁLISIS DE DATOS (Raspberry)
# ============================================================

def crear_tabla_alertas():

    """
    Alertas generadas por el análisis de datos (Isolation Forest)
    de la Raspberry. Una alerta es única por nodo + timestamp + tipo,
    así un reenvío de la Raspberry no la duplica.
    """

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nodo INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            tipo TEXT NOT NULL,
            puntuacion REAL,
            severidad TEXT NOT NULL,
            descripcion TEXT,
            estado TEXT NOT NULL DEFAULT 'Activa',
            actualizado_por TEXT,
            actualizado_en TEXT,
            UNIQUE (nodo, timestamp, tipo)
        )
    """)

    # Compatibilidad: quién y cuándo cambió el estado de la alerta
    cursor.execute("PRAGMA table_info(alertas)")

    columnas_alertas = [
        fila["name"]
        for fila in cursor.fetchall()
    ]

    for columna in ("actualizado_por", "actualizado_en"):

        if columna not in columnas_alertas:

            cursor.execute(
                f"ALTER TABLE alertas ADD COLUMN {columna} TEXT"
            )

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alertas_nodo_fecha
        ON alertas (nodo, timestamp)
    """)

    conexion.commit()
    conexion.close()