# AGROTECH

Plataforma web para el monitoreo IoT de cultivos. Recibe las mediciones de cuatro nodos de campo, las almacena y las muestra en un dashboard con gráficas, histórico, fotos y alertas.

**Demo en vivo:** https://felipegmezm.pythonanywhere.com (abre en modo invitado, solo consulta)

<!-- Agrega aquí una captura del dashboard: ![Dashboard](docs/dashboard.png) -->

## Qué hace

- **API para el campo.** Una Raspberry Pi envía por HTTPS las lecturas de los nodos ESP32, una foto por nodo y las alertas de su análisis de datos (Isolation Forest), autenticada con una clave de API.
- **Dashboard de una sola página.** Estado de los nodos, gráficas por variable, fotos de seguimiento, histórico y alertas, con actualización automática cada 30 segundos.
- **Histórico con filtros.** Paginado y ordenable, con filtro por fechas y por valor de una variable (igual, mayor, menor o entre), y exportación a Excel o CSV.
- **Alertas con ciclo de vida.** Activa, Reconocida y Resuelta, con registro de quién cambió el estado y cuándo.
- **Horarios de medición remotos.** Un administrador cambia los horarios desde la web y el sistema confirma cuándo el nodo los aplicó.
- **Acceso por roles.** Invitado (solo consulta), usuario, administrador y principal, con auditoría de las acciones.

## Variables medidas

Temperatura y humedad del aire, nitrógeno, fósforo, potasio, humedad y temperatura del suelo, conductividad eléctrica, pH, batería del nodo y, de forma opcional, radiación solar.

## Arquitectura

```
Nodos ESP32 (1 a 4)  ──MQTT──  Raspberry Pi
                                   │  HTTPS + X-API-Key
                                   ▼
                    API FastAPI (main.py)  ──  SQLite (datos.db)
                                   ▲
                                   │  HTTPS + cookie de sesión
                          Navegador (dashboard)
```

Este repositorio contiene la API y el dashboard. El firmware de los ESP32 y los programas de la Raspberry Pi no hacen parte de él.

## Tecnologías

| Componente | Tecnología |
| --- | --- |
| API | Python, FastAPI, Uvicorn |
| Base de datos | SQLite |
| Dashboard | HTML, CSS y JavaScript sin framework, Chart.js |
| Plantillas y sesiones | Jinja2, cookies firmadas (Starlette) |
| Contraseñas | PBKDF2-HMAC-SHA256 con sal por usuario |
| Alojamiento | PythonAnywhere (sitio ASGI) |

## Estructura

```
agrotech/
├── main.py              API: endpoints, sesiones, roles, exportación
├── database.py          Conexión y creación de tablas
├── templates/
│   ├── dashboard.html   Dashboard (HTML + CSS + JS)
│   └── login.html       Página de ingreso de respaldo
└── requirements.txt
```

## Ejecución local

Requiere Python 3.10 o superior.

```bash
python -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Abra http://127.0.0.1:8000. El dashboard carga en modo invitado; para entrar con una cuenta use el botón **Iniciar sesión**, abajo a la izquierda.

En el primer arranque la aplicación crea por sí sola:

| Archivo | Contenido |
| --- | --- |
| `datos.db` | Base de datos |
| `secret_key.txt` | Clave que firma las sesiones |
| `api_key_nodos.txt` | Clave que la Raspberry envía en `X-API-Key` |
| `credenciales_iniciales.txt` | Contraseñas generadas para las cuentas `AGROTECH`, `admin` y `usuario` |

Ninguno de esos archivos se sube al repositorio (ver `.gitignore`).

## Configuración

Todo es opcional; si una variable no existe, la aplicación genera el valor.

| Variable de entorno | Uso |
| --- | --- |
| `SECRET_KEY` | Clave de las sesiones |
| `API_KEY_NODOS` | Clave de la Raspberry |
| `AGROTECH_PASSWORD_PRINCIPAL` | Contraseña inicial de la cuenta `AGROTECH` |
| `AGROTECH_PASSWORD_ADMIN` | Contraseña inicial de la cuenta `admin` |
| `AGROTECH_PASSWORD_USUARIO` | Contraseña inicial de la cuenta `usuario` |

El modo invitado se activa o desactiva con la constante `MODO_INVITADO` de `main.py`.

## API

La documentación interactiva está en `/docs`. Ejemplo de una lectura enviada por la Raspberry:

```bash
curl -X POST http://127.0.0.1:8000/api/nodos/1/datos \
  -H "X-API-Key: CLAVE" -H "Content-Type: application/json" \
  -d '{"tipo":"lectura","nodo_id":"nodo1","timestamp":"2026-11-19 10:00:00","dht":{"t":24.5,"h":61},"suelo":{"N":20,"P":15,"K":30,"hum":42,"temp":22,"ec":520,"ph":6.4},"bateria":{"porcentaje":80}}'
```

## Despliegue en PythonAnywhere

```bash
pa website create --domain USUARIO.pythonanywhere.com \
  --command '/home/USUARIO/venvs/fastapi-env/bin/uvicorn --app-dir /home/USUARIO/APInew --uds ${DOMAIN_SOCKET} main:app'
```

Después de subir una nueva versión: `pa website reload --domain USUARIO.pythonanywhere.com`.

## Autor

**Andrés Felipe Gómez M.**
Programa de Ingeniería Electrónica, Universidad del Quindío

Desarrollé la API y el dashboard como trabajo de seminario.


## Dirección académica

Proyecto dirigido por los profesores Jaime Alberto Buitrago y Luis Miguel Capacho Valbuena, Programa de Ingeniería Electrónica, Universidad del Quindío.
