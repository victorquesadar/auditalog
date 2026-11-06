"""Tests del módulo GeoIP (lookup local sin APIs)."""
from __future__ import annotations

import pytest

from src.common.geoip import lookup_ip, status


def test_digitalocean_us_detectada():
    info = lookup_ip("152.42.130.61")
    assert info["country_iso"] == "US"
    assert "Estados Unidos" in info["country"]
    assert info["asn"] == 14061
    assert "DigitalOcean" in info["organization"]


def test_huawei_cloud_china():
    info = lookup_ip("117.72.108.255")
    assert info["country_iso"] == "CN"
    assert info["country"] == "China"
    assert info["organization"].startswith("Huawei") or info["organization"] == "China Telecom"


def test_microsoft_azure():
    info = lookup_ip("20.12.241.170")
    assert info["country_iso"] == "US"
    assert "Microsoft" in info["organization"] or "Azure" in info["organization"]


def test_censys_scanner_identificado():
    info = lookup_ip("205.210.31.58")
    assert info["organization"].startswith("Censys")


def test_ice_costa_rica():
    info = lookup_ip("152.231.189.202")
    assert info["country_iso"] == "CR"
    assert info["asn"] == 11830


def test_rfc1918_privada():
    info = lookup_ip("10.0.0.1")
    assert info["country_iso"] == "--"
    assert "privada" in info["country"].lower()


def test_rfc5737_documentacion():
    info = lookup_ip("198.51.100.5")
    assert "Documentación" in info["country"] or "RFC5737" in info["country"]


def test_ip_invalida_no_explota():
    info = lookup_ip("no-es-ip")
    assert info["country_iso"] == "--"
    assert info["organization"] == "Desconocido"


def test_ip_vacia_no_explota():
    info = lookup_ip("")
    assert info["country_iso"] == "--"


def test_ip_sin_match_devuelve_unknown():
    """Una IP que no está en la tabla embebida ni en MMDB."""
    info = lookup_ip("8.8.8.8")  # Google DNS (no está en el built-in)
    # Si no hay MMDB, debe retornar "unknown" (no explotar)
    assert info["country_iso"] in ("--", "US")  # con MMDB diría US


def test_status_devuelve_info():
    s = status()
    assert "builtin_networks" in s
    assert s["builtin_networks"] > 0
    assert isinstance(s["maxmind_lib"], bool)
