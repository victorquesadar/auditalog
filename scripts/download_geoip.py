"""Descarga las bases de datos locales de GeoIP.

Prueba dos fuentes, en orden:

  1. **DB-IP Lite** (https://db-ip.com/db/lite.php) — GRATIS, SIN REGISTRO.
     Datos actualizados mensualmente. Es el default.

  2. **MaxMind GeoLite2** (fallback) — requiere registro gratuito y una
     license key en MAXMIND_LICENSE_KEY. Más precisa.

Uso:
    python scripts/download_geoip.py                 # intenta DB-IP Lite
    MAXMIND_LICENSE_KEY=xxxx python scripts/download_geoip.py   # usa MaxMind
    python scripts/download_geoip.py --force         # re-descarga aunque exista

Después de ejecutarlo, los archivos quedan en data/geoip/ y AuditaLog los usa
automáticamente — no hace falta reiniciar nada (lazy load).
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# En Windows la consola por defecto es cp1252 y no puede imprimir Unicode.
# Forzamos stdout/stderr a UTF-8 cuando corresponde.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "geoip"
OUT_DIR.mkdir(parents=True, exist_ok=True)

COUNTRY_MMDB = OUT_DIR / "GeoLite2-Country.mmdb"
ASN_MMDB = OUT_DIR / "GeoLite2-ASN.mmdb"


def _urlopen(url: str, timeout: int = 90):
    req = urllib.request.Request(url, headers={"User-Agent": "AuditaLog/0.4"})
    return urllib.request.urlopen(req, timeout=timeout)


def _atomic_write(path: Path, data: bytes) -> None:
    """Escribe bytes a `path` de forma atómica y segura en Windows.

    En Windows, maxminddb puede tener el archivo mapeado con mmap y
    `path.write_bytes` falla con Errno 22. Escribimos a un .tmp y
    después usamos os.replace que SÍ puede reemplazar archivos mapeados.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    # Si el destino existe y está bloqueado, intentamos borrarlo antes
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass
    os.replace(str(tmp), str(path))


# ----------------------------------------------------------------------------
# DB-IP Lite (gratis, sin registro)
# ----------------------------------------------------------------------------

def download_dbip_lite() -> bool:
    """Descarga las MMDB free de DB-IP Lite (country + ASN).

    URLs: https://download.db-ip.com/free/dbip-{country,asn}-lite-YYYY-MM.mmdb.gz
    """
    now = datetime.now(timezone.utc)
    # DB-IP publica la DB del mes a los pocos días del mes; probamos este mes y el anterior
    candidates = []
    for delta_months in (0, 1, 2):
        yr = now.year
        mo = now.month - delta_months
        while mo < 1:
            mo += 12
            yr -= 1
        candidates.append(f"{yr}-{mo:02d}")

    for tag in candidates:
        country_url = f"https://download.db-ip.com/free/dbip-country-lite-{tag}.mmdb.gz"
        asn_url = f"https://download.db-ip.com/free/dbip-asn-lite-{tag}.mmdb.gz"

        print(f"[dbip] intentando versión {tag}")
        try:
            # Country
            print(f"[dbip]   descargando {country_url}")
            with _urlopen(country_url) as r:
                gz = r.read()
            raw = gzip.decompress(gz)
            _atomic_write(COUNTRY_MMDB, raw)
            print(f"[dbip]   [OK] Country ({len(raw):,} bytes)")

            # ASN
            print(f"[dbip]   descargando {asn_url}")
            with _urlopen(asn_url) as r:
                gz = r.read()
            raw = gzip.decompress(gz)
            _atomic_write(ASN_MMDB, raw)
            print(f"[dbip]   [OK] ASN ({len(raw):,} bytes)")

            return True
        except Exception as e:
            print(f"[dbip]   versión {tag} no disponible: {e}")
            continue

    return False


# ----------------------------------------------------------------------------
# MaxMind GeoLite2 (requiere license key)
# ----------------------------------------------------------------------------

def download_maxmind(key: str) -> bool:
    editions = {"GeoLite2-Country": COUNTRY_MMDB, "GeoLite2-ASN": ASN_MMDB}
    ok = True
    for edition, out_path in editions.items():
        url = (
            "https://download.maxmind.com/app/geoip_download"
            f"?edition_id={edition}&license_key={key}&suffix=tar.gz"
        )
        print(f"[maxmind] descargando {edition}...")
        try:
            with _urlopen(url) as r:
                data = r.read()
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                written = False
                for m in tar.getmembers():
                    if m.name.endswith(".mmdb"):
                        f = tar.extractfile(m)
                        if f is None:
                            continue
                        _atomic_write(out_path, f.read())
                        print(f"[maxmind]   [OK] {out_path.name} ({out_path.stat().st_size:,} bytes)")
                        written = True
                        break
                if not written:
                    print(f"[maxmind]   [FAIL] no se encontró .mmdb en {edition}")
                    ok = False
        except Exception as e:
            print(f"[maxmind]   [FAIL] error: {e}")
            ok = False
    return ok


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Descarga las MMDB de GeoIP")
    ap.add_argument("--force", action="store_true",
                    help="Re-descarga aunque ya exista")
    ap.add_argument("--source", choices=("dbip", "maxmind", "auto"), default="auto",
                    help="Fuente a usar")
    args = ap.parse_args()

    if COUNTRY_MMDB.exists() and ASN_MMDB.exists() and not args.force:
        print("[geoip] ya hay MMDB descargadas en data/geoip/")
        print(f"        Country: {COUNTRY_MMDB} ({COUNTRY_MMDB.stat().st_size:,} bytes)")
        print(f"        ASN:     {ASN_MMDB} ({ASN_MMDB.stat().st_size:,} bytes)")
        print("        Usá --force para re-descargar.")
        return 0

    # DB-IP Lite primero (no requiere key)
    key = os.getenv("MAXMIND_LICENSE_KEY")
    if args.source == "maxmind" or (args.source == "auto" and key):
        if not key:
            print("[geoip] MAXMIND_LICENSE_KEY no definida — no puedo usar MaxMind.")
            return 1
        if download_maxmind(key):
            print("[geoip] [OK] MaxMind descargada en data/geoip/")
            return 0
        print("[geoip] MaxMind falló, intento DB-IP Lite...")

    if args.source in ("dbip", "auto"):
        if download_dbip_lite():
            print("[geoip] [OK] DB-IP Lite descargada en data/geoip/")
            print("[geoip] Las IPs se resolverán con cobertura completa en el próximo request.")
            return 0

    print("[geoip] [FAIL] No se pudo descargar ninguna base.", file=sys.stderr)
    print("        Comprobá tu conexión a internet y volvé a intentar.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
