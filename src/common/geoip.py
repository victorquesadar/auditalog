"""Lookup de GeoIP local (sin APIs HTTP).

Pensado para resolver `IP → país + ISP/ASN` sin pedirle al mundo exterior
(evita rate limits y mantiene el pipeline rápido).

Dos modos:
    1) **MaxMind GeoLite2** (recomendado): coloca los .mmdb en data/geoip/
       (GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb).
       Se bajan una sola vez desde https://www.maxmind.com/en/geolite2/signup
       o un mirror. Ver scripts/download_geoip.py.

    2) **Fallback embebido**: si no hay MMDB disponibles, usamos un diccionario
       de ~50 redes conocidas (cloud providers, scanners, bogons). Cubre los
       atacantes habituales y las IPs privadas para que la demo funcione sin
       descargas extras.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Optional

# ----------------------------------------------------------------------------
# MaxMind reader (opcional; el proyecto funciona sin él)
# ----------------------------------------------------------------------------

try:
    import maxminddb
    _HAS_MAXMIND = True
except ImportError:
    _HAS_MAXMIND = False


_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "geoip"
_COUNTRY_MMDB = _DATA_DIR / "GeoLite2-Country.mmdb"
_ASN_MMDB = _DATA_DIR / "GeoLite2-ASN.mmdb"

_country_reader = None
_asn_reader = None


def _load_mmdb():
    """Abre los MMDB si existen; se hace lazy y una sola vez."""
    global _country_reader, _asn_reader
    if not _HAS_MAXMIND:
        return
    if _country_reader is None and _COUNTRY_MMDB.exists():
        try:
            _country_reader = maxminddb.open_database(str(_COUNTRY_MMDB))
        except Exception:
            _country_reader = None
    if _asn_reader is None and _ASN_MMDB.exists():
        try:
            _asn_reader = maxminddb.open_database(str(_ASN_MMDB))
        except Exception:
            _asn_reader = None


# ----------------------------------------------------------------------------
# Fallback embebido: redes conocidas
# Mapea red CIDR → (country_iso, country_name, asn, organization)
# ----------------------------------------------------------------------------

# Nota: este dataset es MANUAL y acotado. Sirve para que la demo funcione sin
# descargar MMDB. Cubre: RFC1918 + RFC5737 + principales clouds + scanners.
_KNOWN_NETWORKS: list[tuple[str, tuple[str, str, Optional[int], str]]] = [
    # ========== Direcciones privadas / reservadas ==========
    ("10.0.0.0/8",         ("--", "LAN privada (RFC1918)", None, "Red privada")),
    ("172.16.0.0/12",      ("--", "LAN privada (RFC1918)", None, "Red privada")),
    ("192.168.0.0/16",     ("--", "LAN privada (RFC1918)", None, "Red privada")),
    ("127.0.0.0/8",        ("--", "Loopback",              None, "localhost")),
    ("169.254.0.0/16",     ("--", "Link-local",            None, "APIPA")),
    ("100.64.0.0/10",      ("--", "CGNAT (RFC6598)",       None, "Carrier-grade NAT")),

    # ========== RFC5737 — rangos de documentación ==========
    ("192.0.2.0/24",       ("--", "Documentación (RFC5737)", None, "TEST-NET-1")),
    ("198.51.100.0/24",    ("--", "Documentación (RFC5737)", None, "TEST-NET-2")),
    ("203.0.113.0/24",     ("--", "Documentación (RFC5737)", None, "TEST-NET-3")),

    # ========== Scanners académicos conocidos ==========
    ("205.210.31.0/24",    ("US", "Estados Unidos",    398722, "Censys, Inc.")),
    ("162.142.125.0/24",   ("US", "Estados Unidos",    398722, "Censys, Inc.")),
    ("167.248.133.0/24",   ("US", "Estados Unidos",    398324, "Driftnet Ltd")),
    ("92.118.39.0/24",     ("GB", "Reino Unido",       211680, "Internet Measurement")),
    ("199.45.154.0/24",    ("US", "Estados Unidos",    398722, "Censys, Inc.")),
    ("66.240.192.0/19",    ("US", "Estados Unidos",     20473, "Shodan.io")),

    # ========== DigitalOcean ==========
    ("152.42.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("165.22.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("165.227.0.0/16",     ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("167.71.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("167.99.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("104.248.0.0/16",     ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("45.55.0.0/16",       ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("64.227.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("68.183.0.0/16",      ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),
    ("128.199.0.0/16",     ("SG", "Singapur",           14061, "DigitalOcean, LLC")),
    ("139.59.0.0/16",      ("IN", "India",              14061, "DigitalOcean, LLC")),
    ("143.110.0.0/16",     ("US", "Estados Unidos",     14061, "DigitalOcean, LLC")),

    # ========== AWS ==========
    ("3.0.0.0/8",          ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("13.32.0.0/15",       ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("13.52.0.0/14",       ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("13.56.0.0/16",       ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("15.161.0.0/16",      ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("15.177.0.0/16",      ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("18.0.0.0/8",         ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("23.20.0.0/14",       ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("34.192.0.0/10",      ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("52.0.0.0/8",         ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("54.0.0.0/8",         ("US", "Estados Unidos",     16509, "Amazon AWS")),
    ("184.72.0.0/15",      ("US", "Estados Unidos",     16509, "Amazon AWS")),

    # ========== Microsoft Azure ==========
    ("13.64.0.0/11",       ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("13.96.0.0/13",       ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("20.0.0.0/8",         ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("40.64.0.0/10",       ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("40.112.0.0/13",      ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("40.124.0.0/16",      ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("40.126.0.0/18",      ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("65.52.0.0/14",       ("US", "Estados Unidos",      8075, "Microsoft Azure")),
    ("104.40.0.0/13",      ("US", "Estados Unidos",      8075, "Microsoft Azure")),

    # ========== Google Cloud ==========
    ("34.64.0.0/10",       ("US", "Estados Unidos",     15169, "Google LLC")),
    ("35.0.0.0/8",         ("US", "Estados Unidos",     15169, "Google LLC")),
    ("107.178.192.0/18",   ("US", "Estados Unidos",     15169, "Google LLC")),
    ("146.148.0.0/17",     ("US", "Estados Unidos",     15169, "Google LLC")),
    ("162.216.148.0/22",   ("US", "Estados Unidos",     15169, "Google LLC")),

    # ========== Cloudflare ==========
    ("104.16.0.0/12",      ("US", "Estados Unidos",     13335, "Cloudflare, Inc.")),
    ("172.64.0.0/13",      ("US", "Estados Unidos",     13335, "Cloudflare, Inc.")),
    ("162.158.0.0/15",     ("US", "Estados Unidos",     13335, "Cloudflare, Inc.")),
    ("1.1.1.0/24",         ("US", "Estados Unidos",     13335, "Cloudflare DNS")),

    # ========== Oracle Cloud ==========
    ("132.145.0.0/16",     ("US", "Estados Unidos",     31898, "Oracle Cloud")),
    ("129.146.0.0/15",     ("US", "Estados Unidos",     31898, "Oracle Cloud")),
    ("130.35.0.0/16",      ("US", "Estados Unidos",     31898, "Oracle Cloud")),
    ("130.61.0.0/16",      ("US", "Estados Unidos",     31898, "Oracle Cloud")),
    ("132.226.0.0/16",     ("US", "Estados Unidos",     31898, "Oracle Cloud")),

    # ========== OVH (Francia) ==========
    ("5.39.0.0/16",        ("FR", "Francia",            16276, "OVH SAS")),
    ("37.59.0.0/16",       ("FR", "Francia",            16276, "OVH SAS")),
    ("51.68.0.0/14",       ("FR", "Francia",            16276, "OVH SAS")),
    ("51.75.0.0/16",       ("FR", "Francia",            16276, "OVH SAS")),
    ("51.83.0.0/16",       ("FR", "Francia",            16276, "OVH SAS")),
    ("51.89.0.0/16",       ("FR", "Francia",            16276, "OVH SAS")),
    ("51.158.0.0/16",      ("FR", "Francia",            16276, "OVH SAS")),
    ("51.195.0.0/16",      ("FR", "Francia",            16276, "OVH SAS")),
    ("51.210.0.0/15",      ("FR", "Francia",            16276, "OVH SAS")),
    ("51.254.0.0/16",      ("FR", "Francia",            16276, "OVH SAS")),
    ("137.74.0.0/16",      ("FR", "Francia",            16276, "OVH SAS")),
    ("151.80.0.0/16",      ("FR", "Francia",            16276, "OVH SAS")),
    ("178.32.0.0/15",      ("FR", "Francia",            16276, "OVH SAS")),

    # ========== Hetzner (Alemania) ==========
    ("5.9.0.0/16",         ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("46.4.0.0/16",        ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("78.46.0.0/15",       ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("88.99.0.0/16",       ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("116.202.0.0/15",     ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("136.243.0.0/16",     ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("144.76.0.0/16",      ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("148.251.0.0/16",     ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("176.9.0.0/16",       ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("188.40.0.0/16",      ("DE", "Alemania",           24940, "Hetzner Online GmbH")),
    ("195.201.0.0/16",     ("DE", "Alemania",           24940, "Hetzner Online GmbH")),

    # ========== Vultr ==========
    ("45.32.0.0/16",       ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),
    ("45.76.0.0/16",       ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),
    ("45.77.0.0/16",       ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),
    ("104.207.128.0/17",   ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),
    ("108.61.0.0/16",      ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),
    ("149.28.0.0/16",      ("US", "Estados Unidos",     20473, "Vultr Holdings LLC")),

    # ========== Linode / Akamai ==========
    ("45.33.0.0/16",       ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("45.56.64.0/18",      ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("45.79.0.0/16",       ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("66.175.208.0/20",    ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("96.126.96.0/19",     ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("172.104.0.0/15",     ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("173.230.128.0/18",   ("US", "Estados Unidos",     63949, "Linode LLC")),
    ("173.255.192.0/18",   ("US", "Estados Unidos",     63949, "Linode LLC")),

    # ========== China ==========
    ("1.80.0.0/13",        ("CN", "China",               4134, "China Telecom")),
    ("14.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("36.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("39.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("42.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("49.0.0.0/8",         ("CN", "China",               4837, "China Unicom")),
    ("58.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("59.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("60.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("61.0.0.0/8",         ("CN", "China",               4134, "China Telecom")),
    ("101.0.0.0/8",        ("CN", "China",               4837, "China Unicom")),
    ("106.0.0.0/8",        ("CN", "China",               4837, "China Unicom")),
    ("111.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("112.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("113.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("114.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("115.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("116.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("117.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("117.72.0.0/14",      ("CN", "China",             136907, "Huawei Cloud")),
    ("118.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("119.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("120.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("121.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("122.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("123.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("124.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("125.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("175.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("180.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("182.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("183.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("202.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("210.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("211.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("218.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("219.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("220.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("221.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("222.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),
    ("223.0.0.0/8",        ("CN", "China",               4134, "China Telecom")),

    # ========== Rusia ==========
    ("2.56.0.0/14",        ("RU", "Rusia",              60380, "Hosting provider RU")),
    ("5.44.0.0/15",        ("RU", "Rusia",              41727, "YARNET LLC")),
    ("45.146.0.0/16",      ("RU", "Rusia",              60380, "Mir Telematiki Ltd.")),
    ("77.90.0.0/16",       ("RU", "Rusia",             202685, "Hosting Service RUS")),
    ("89.221.0.0/16",      ("RU", "Rusia",              51408, "Rostelecom")),
    ("91.106.0.0/15",      ("RU", "Rusia",              44391, "Hostings")),
    ("185.172.0.0/15",     ("RU", "Rusia",              60380, "Russian hosting")),
    ("188.166.0.0/16",     ("RU", "Rusia",              51408, "Rostelecom")),
    ("195.133.0.0/16",     ("RU", "Rusia",             202685, "RU-VDS")),

    # ========== Vietnam ==========
    ("27.0.0.0/8",         ("VN", "Vietnam",            45899, "VNPT Corp")),
    ("103.0.0.0/8",        ("VN", "Vietnam",             7552, "Viettel Group")),
    ("113.160.0.0/11",     ("VN", "Vietnam",            45899, "VNPT Corp")),
    ("115.72.0.0/13",      ("VN", "Vietnam",            45899, "VNPT Corp")),
    ("118.70.0.0/15",      ("VN", "Vietnam",             7552, "Viettel Group")),
    ("123.16.0.0/13",      ("VN", "Vietnam",            45899, "VNPT Corp")),
    ("210.245.0.0/16",     ("VN", "Vietnam",             7552, "Viettel Group")),

    # ========== India ==========
    ("106.200.0.0/13",     ("IN", "India",              45820, "Tata Communications")),
    ("115.240.0.0/13",     ("IN", "India",              45820, "Tata Communications")),
    ("123.252.0.0/14",     ("IN", "India",              45820, "Tata Communications")),

    # ========== Brasil ==========
    ("177.0.0.0/8",        ("BR", "Brasil",             26615, "TIM Brasil")),
    ("179.0.0.0/8",        ("BR", "Brasil",             28573, "Claro Brasil")),
    ("186.192.0.0/11",     ("BR", "Brasil",             28573, "Claro Brasil")),
    ("189.0.0.0/8",        ("BR", "Brasil",             26615, "TIM Brasil")),
    ("191.0.0.0/8",        ("BR", "Brasil",             28573, "Claro Brasil")),
    ("200.144.0.0/12",     ("BR", "Brasil",            263076, "Brasil Telecom")),

    # ========== Argentina ==========
    ("181.0.0.0/8",        ("AR", "Argentina",           7303, "Telecom Argentina")),
    ("190.0.0.0/8",        ("AR", "Argentina",          10318, "Cablevisión S.A.")),

    # ========== México ==========
    ("187.0.0.0/8",        ("MX", "México",              8151, "Uninet S.A. (Telmex)")),
    ("201.0.0.0/8",        ("MX", "México",              8151, "Uninet S.A. (Telmex)")),

    # ========== Costa Rica (red local del grupo del curso) ==========
    ("152.231.0.0/16",     ("CR", "Costa Rica",         11830, "ICE Telecom")),
    ("190.80.0.0/13",      ("CR", "Costa Rica",         11830, "ICE Telecom")),
    ("196.40.0.0/17",      ("CR", "Costa Rica",         52468, "Cabletica S.A.")),
    ("200.74.128.0/18",    ("CR", "Costa Rica",         52468, "Cabletica S.A.")),
    ("200.91.0.0/16",      ("CR", "Costa Rica",         11830, "ICE Telecom")),
    ("201.192.0.0/12",     ("CR", "Costa Rica",         11830, "ICE Telecom")),

    # ========== Alemania (DT, 1&1) ==========
    ("79.192.0.0/10",      ("DE", "Alemania",            3320, "Deutsche Telekom")),
    ("82.144.0.0/14",      ("DE", "Alemania",            8560, "IONOS (1&1)")),
    ("87.128.0.0/10",      ("DE", "Alemania",            3320, "Deutsche Telekom")),
    ("91.65.0.0/16",       ("DE", "Alemania",            3209, "Vodafone DE")),

    # ========== Reino Unido ==========
    ("86.0.0.0/8",         ("GB", "Reino Unido",         2856, "BT Group")),
    ("90.192.0.0/11",      ("GB", "Reino Unido",         5089, "Virgin Media")),

    # ========== Francia (fuera de OVH) ==========
    ("80.12.0.0/15",       ("FR", "Francia",             3215, "Orange S.A.")),
    ("81.56.0.0/14",       ("FR", "Francia",            12322, "Free SAS")),
    ("82.64.0.0/14",       ("FR", "Francia",            12322, "Free SAS")),

    # ========== Países Bajos (cloud / hosting común) ==========
    ("5.188.0.0/16",       ("NL", "Países Bajos",       49505, "Selectel Hosting")),
    ("37.153.0.0/16",      ("NL", "Países Bajos",       49505, "Selectel Hosting")),
    ("45.129.0.0/16",      ("NL", "Países Bajos",       49505, "DediPath Hosting")),
    ("80.209.0.0/16",      ("NL", "Países Bajos",       62240, "Clouvider Ltd")),

    # ========== Turquía ==========
    ("78.160.0.0/11",      ("TR", "Turquía",             9121, "Türk Telekom")),
    ("88.224.0.0/11",      ("TR", "Turquía",             9121, "Türk Telekom")),
    ("95.0.0.0/11",        ("TR", "Turquía",             9121, "Türk Telekom")),

    # ========== Corea del Sur ==========
    ("112.168.0.0/13",     ("KR", "Corea del Sur",       4766, "Korea Telecom")),
    ("121.128.0.0/10",     ("KR", "Corea del Sur",       4766, "Korea Telecom")),

    # ========== Japón ==========
    ("126.0.0.0/8",        ("JP", "Japón",               9605, "SoftBank Corp.")),
    ("153.128.0.0/9",      ("JP", "Japón",               2516, "KDDI Corporation")),

    # ========== Taiwán ==========
    ("118.160.0.0/11",     ("TW", "Taiwán",              3462, "Chunghwa Telecom")),
    ("220.128.0.0/10",     ("TW", "Taiwán",              3462, "Chunghwa Telecom")),

    # ========== Estados Unidos (ISPs residenciales grandes) ==========
    ("24.0.0.0/8",         ("US", "Estados Unidos",      7922, "Comcast Cable")),
    ("67.160.0.0/11",      ("US", "Estados Unidos",      7922, "Comcast Cable")),
    ("71.192.0.0/12",      ("US", "Estados Unidos",      7922, "Comcast Cable")),
    ("76.100.0.0/14",      ("US", "Estados Unidos",      7922, "Comcast Cable")),
    ("68.0.0.0/10",        ("US", "Estados Unidos",      7018, "AT&T Internet")),
    ("72.0.0.0/8",         ("US", "Estados Unidos",      7018, "AT&T Internet")),
    ("98.192.0.0/10",      ("US", "Estados Unidos",      7018, "AT&T Internet")),
    ("166.148.0.0/14",     ("US", "Estados Unidos",      7018, "AT&T Internet")),
    ("184.0.0.0/8",        ("US", "Estados Unidos",      7922, "Comcast Cable")),

    # ========== Canadá ==========
    ("142.128.0.0/10",     ("CA", "Canadá",              577, "Bell Canada")),
    ("184.145.0.0/16",     ("CA", "Canadá",              812, "Rogers Communications")),
]

_PARSED_NETWORKS = [
    (ipaddress.ip_network(cidr), data)
    for cidr, data in _KNOWN_NETWORKS
]


# ----------------------------------------------------------------------------
# API pública
# ----------------------------------------------------------------------------

@lru_cache(maxsize=10_000)
def lookup_ip(ip: str) -> dict:
    """Devuelve geo info para una IP.

    Returns:
        dict con las claves:
          - country_iso: "US", "CN", "--" (desconocido/privado)
          - country:     "Estados Unidos", "China", "Desconocido"
          - asn:         número de ASN (int) o None
          - organization: "Cloudflare, Inc.", "Hetzner Online GmbH", etc.
          - source:      "mmdb" | "builtin" | "unknown"
    """
    if not ip:
        return {"country_iso": "--", "country": "Desconocido",
                "asn": None, "organization": "Desconocido", "source": "unknown"}

    # Intento 1: MaxMind MMDB si está disponible
    _load_mmdb()
    if _country_reader is not None or _asn_reader is not None:
        info = {"country_iso": "--", "country": "Desconocido",
                "asn": None, "organization": "Desconocido", "source": "mmdb"}
        try:
            if _country_reader is not None:
                c = _country_reader.get(ip)
                if c:
                    country = c.get("country", {}) or {}
                    info["country_iso"] = country.get("iso_code") or "--"
                    names = country.get("names", {}) or {}
                    info["country"] = names.get("es") or names.get("en") or "Desconocido"
            if _asn_reader is not None:
                a = _asn_reader.get(ip)
                if a:
                    info["asn"] = a.get("autonomous_system_number")
                    info["organization"] = a.get("autonomous_system_organization") or "Desconocido"
            if info["country_iso"] != "--" or info["asn"] is not None:
                return info
        except (ValueError, KeyError):
            pass

    # Intento 2: tabla embebida
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"country_iso": "--", "country": "IP inválida",
                "asn": None, "organization": "Desconocido", "source": "unknown"}

    for net, (iso, country, asn, org) in _PARSED_NETWORKS:
        if ip_obj in net:
            return {
                "country_iso": iso,
                "country": country,
                "asn": asn,
                "organization": org,
                "source": "builtin",
            }

    return {
        "country_iso": "--",
        "country": "Desconocido",
        "asn": None,
        "organization": "Desconocido",
        "source": "unknown",
    }


def has_maxmind() -> bool:
    """Devuelve True si al menos uno de los MMDB está cargado."""
    _load_mmdb()
    return _country_reader is not None or _asn_reader is not None


def close_readers() -> None:
    """Cierra los readers MMDB abiertos. En Windows es necesario antes de
    re-descargar las bases, porque maxminddb mapea el archivo con mmap
    y bloquea escritura mientras esté abierto.
    """
    global _country_reader, _asn_reader
    for reader in (_country_reader, _asn_reader):
        if reader is None:
            continue
        try:
            reader.close()
        except Exception:
            pass
    _country_reader = None
    _asn_reader = None
    try:
        lookup_ip.cache_clear()
    except Exception:
        pass


def status() -> dict:
    """Estado del subsistema GeoIP, útil para /api/health."""
    _load_mmdb()
    return {
        "maxmind_lib": _HAS_MAXMIND,
        "country_mmdb": _country_reader is not None,
        "asn_mmdb": _asn_reader is not None,
        "country_mmdb_path": str(_COUNTRY_MMDB),
        "asn_mmdb_path": str(_ASN_MMDB),
        "builtin_networks": len(_PARSED_NETWORKS),
    }
