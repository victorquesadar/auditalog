# Despliegue en Virtualmin · AuditaLog

Guía para publicar AuditaLog en un servidor con Virtualmin (Ubuntu/Debian).

## Requisitos previos
- Virtualmin instalado y con un dominio creado (ej. `auditalog.ejemplo.com`).
- Python 3.11+ disponible en el servidor (Virtualmin trae 3.10+ en Ubuntu 22.04).
- Redis local o acceso al Redis del curso (`grupo4:` prefijo).
- Acceso al cluster MongoDB Atlas (IP del servidor whitelisted).
- Puerto 8000 (o el que decidamos) libre internamente — nginx hará proxy.

## 1. Clonar el repo en el home del dominio

```bash
# Como usuario del dominio Virtualmin (no root)
cd ~
git clone https://github.com/victorquesadar/auditalog.git
cd auditalog
```

## 2. Crear virtualenv e instalar dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Configurar `.env`

```bash
cp .env.example .env
nano .env
```

Variables obligatorias en producción:

```ini
APP_ENV=prod
APP_HOST=127.0.0.1           # solo loopback, nginx hace el proxy
APP_PORT=8000
APP_SECRET=$(openssl rand -hex 32)

# Autenticación (OBLIGATORIA en producción)
AUTH_USER=admin
AUTH_PASS=contraseña-fuerte-aqui
AUTH_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Mongo Atlas
MONGO_URI=mongodb+srv://andrey:...@cluster.xxxxx.mongodb.net/?retryWrites=true&w=majority
MONGO_DB=grupo4_db

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
```

## 4. (Opcional) Descargar bases GeoIP para cobertura completa

```bash
source .venv/bin/activate
python scripts/download_geoip.py
# Descarga DB-IP Lite (gratis, sin registro) a data/geoip/
```

Sin este paso, el fallback embebido de ~210 redes cubre los principales
proveedores cloud y Costa Rica.

## 5. Crear servicio systemd

Como `root`:

```bash
sudo nano /etc/systemd/system/auditalog.service
```

Contenido:

```ini
[Unit]
Description=AuditaLog FastAPI service
After=network.target redis.service

[Service]
Type=simple
User=auditalog                                # usuario del dominio Virtualmin
WorkingDirectory=/home/auditalog/auditalog
EnvironmentFile=/home/auditalog/auditalog/.env
ExecStart=/home/auditalog/auditalog/.venv/bin/uvicorn src.api.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Activar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable auditalog
sudo systemctl start auditalog
sudo systemctl status auditalog         # verificar que corre
sudo journalctl -u auditalog -f         # ver logs en vivo
```

## 6. Configurar proxy nginx en Virtualmin

Virtualmin → **Services → Configure Website (SSL)** → **Edit Directives**.
Dentro del `server { ... }` del dominio, agregar:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 300s;
}

# Subidas grandes (.zip con varios logs)
client_max_body_size 100M;
```

Guardar y reiniciar:

```bash
sudo systemctl reload nginx
```

## 7. Habilitar HTTPS (Let's Encrypt)

Virtualmin → **Server Configuration → SSL Certificate** → **Let's Encrypt** →
**Request Certificate**.

Esto habilita HTTPS y Virtualmin renueva automáticamente cada 90 días.

## 8. Verificación final

```bash
# Health check
curl -I https://auditalog.ejemplo.com/api/health
# → 200 OK (ruta pública, no requiere login)

# Portada → debe redirigir a /login
curl -I https://auditalog.ejemplo.com/
# → 303 See Other, Location: /login
```

Abrir el navegador en `https://auditalog.ejemplo.com/`, entrar con las
credenciales de `AUTH_USER` / `AUTH_PASS`.

## 9. Actualizaciones futuras

```bash
# Como usuario del dominio
cd ~/auditalog
git pull
source .venv/bin/activate
pip install -r requirements.txt

# Como root
sudo systemctl restart auditalog
```

## Troubleshooting

| Síntoma | Causa | Solución |
|---|---|---|
| 502 Bad Gateway | uvicorn caído | `sudo systemctl status auditalog` + `journalctl -u auditalog -n 50` |
| Login rechaza credenciales correctas | AUTH_SECRET distinto entre reinicios | Fijar `AUTH_SECRET` en `.env`, no dejarlo vacío |
| Upload falla con 413 | Nginx limita tamaño | Subir `client_max_body_size` en el `server { }` |
| Mongo no conecta | IP del servidor no whitelisted | Agregar en Atlas Network Access |
| GeoIP solo muestra "Unknown" | MMDB no descargadas | Correr `python scripts/download_geoip.py` o verificar permisos de `data/geoip/` |
