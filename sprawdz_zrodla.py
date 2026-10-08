"""Sprawdza, czy strony, z ktorych pochodza przepisy, wciaz dzialaja, i zapisuje ich podglad
(tytul, opis, obrazek, czy strone mozna pokazac w ramce) do data/zrodla_podglad.json.

Strona Kwiatownika czyta ten plik (/api/zrodla_podglad.json) i po kliknieciu w zrodlo przepisu
pokazuje dymek z podgladem strony albo informacje, ze strona juz nie dziala (+ kopia w Web Archive).
Patrz: static/js/zrodla_dymki.js.

Uzycie (w folderze Kwiatownik2):
    python sprawdz_zrodla.py                 # sprawdza nowe adresy i te sprawdzone dawniej niz 7 dni temu
    python sprawdz_zrodla.py --wszystkie     # sprawdza wszystko od nowa
    python sprawdz_zrodla.py --dni 3 --watki 16

Tylko biblioteka standardowa - dziala tez w kontenerze Siedziby Kwiatownika (agent publikacji).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import gzip
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
import zlib
from datetime import date, datetime, timedelta
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
PRZEPISY = ROOT / "data" / "przepisy"
WYNIK = ROOT / "data" / "zrodla_podglad.json"
NASZE_DOMENY = ("kwiatownik.onrender.com",)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36 (Kwiatownik - sprawdzanie zrodel)")
MAX_BAJTOW = 600_000

# stan strony:
#   dziala   - strona odpowiada (2xx)
#   brak     - strony juz nie ma (404/410) albo przekierowuje na strone glowna serwisu
#   blokada  - serwer nie wpuszcza automatow (401/403/429, Cloudflare) - strona pewnie dziala
#   blad     - serwer nie odpowiada, blad 5xx, zly certyfikat, brak domeny


def klucz(url: str) -> str:
    """Adres bez #kotwicy - ten sam klucz liczy static/js/zrodla_dymki.js."""
    p = urlsplit(url.strip())
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


# ------------------------------------------------------------------ zbieranie adresow
def _adresy(obj, out: set[str]) -> None:
    if isinstance(obj, dict):
        for k in ("zrodla", "zrodlo", "źródło", "źródła"):
            v = obj.get(k)
            for z in (v if isinstance(v, list) else [v]):
                u = z.get("url") if isinstance(z, dict) else z
                if isinstance(u, str) and re.match(r"^https?://", u.strip(), re.I):
                    out.add(u.strip())
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _adresy(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _adresy(v, out)


def zbierz_adresy() -> list[str]:
    out: set[str] = set()
    for f in sorted(PRZEPISY.glob("*.json")):
        if f.name == "wzorzec_przepisu.json":
            continue
        try:
            _adresy(json.loads(f.read_text(encoding="utf-8")), out)
        except Exception as exc:  # uszkodzony plik nie zatrzymuje sprawdzania
            print(f"  ! pomijam {f.name}: {exc}", file=sys.stderr)
    return sorted({klucz(u) for u in out})


# ------------------------------------------------------------------ czytanie strony
class _Head(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self.lang = ""
        self._in_title = False
        self.icon = ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and a.get("lang"):
            self.lang = a["lang"].split("-")[0].lower()[:5]
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (a.get("property") or a.get("name") or "").lower()
            if name and a.get("content") and name not in self.meta:
                self.meta[name] = a["content"]
        elif tag == "link" and not self.icon and "icon" in a.get("rel", "").lower() and a.get("href"):
            self.icon = a["href"]

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


def _tekst(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", unescape(s or "")).strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def _dekoduj(raw: bytes, enc: str, ctype: str) -> str:
    if enc == "gzip":
        raw = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    elif enc == "deflate":
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I) or re.search(rb'<meta[^>]+charset=["\']?([\w-]+)', raw[:4000], re.I)
    cs = m.group(1) if m else "utf-8"
    cs = cs.decode() if isinstance(cs, bytes) else cs
    try:
        return raw.decode(cs, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _osadzalna(headers, final_url: str) -> bool:
    """Czy strona pozwala pokazac sie w ramce (iframe) na kwiatownik.onrender.com."""
    if not final_url.lower().startswith("https://"):
        return False   # ramka http na stronie https zostalaby zablokowana
    if (headers.get("X-Frame-Options") or "").strip():
        return False
    csp = headers.get("Content-Security-Policy") or ""
    m = re.search(r"frame-ancestors([^;]*)", csp, re.I)
    if m:
        val = m.group(1)
        return "*" in val.split() or any(d in val for d in NASZE_DOMENY)
    return True


def _na_glowna(url: str, final_url: str) -> bool:
    a, b = urlsplit(url), urlsplit(final_url)
    glebokie = len(a.path.strip("/")) > 1
    return glebokie and b.path.strip("/") in ("", "index.html", "index.php", "pl", "en") and not b.query


def sprawdz(url: str) -> dict:
    dzis = date.today().isoformat()
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pl,en;q=0.8,*;q=0.5", "Accept-Encoding": "gzip, deflate"})
    wynik: dict = {"sprawdzono": dzis}
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
            final = r.geturl()
            kod = r.status
            raw = r.read(MAX_BAJTOW)
            ctype = r.headers.get("Content-Type", "")
            wynik.update(kod=kod, osadzalna=_osadzalna(r.headers, final))
            if klucz(final) != klucz(url):
                wynik["adres_koncowy"] = final
            if _na_glowna(url, final):
                wynik.update(stan="brak", blad="strona przekierowuje na stronę główną serwisu – przepisu pewnie już tam nie ma",
                             osadzalna=False)
            else:
                wynik["stan"] = "dziala"
            if wynik["stan"] == "dziala" and ("html" in ctype.lower() or not ctype):
                p = _Head()
                try:
                    p.feed(_dekoduj(raw, (r.headers.get("Content-Encoding") or "").lower(), ctype))
                except Exception:
                    pass
                m = p.meta
                tytul = m.get("og:title") or m.get("twitter:title") or p.title
                opis = m.get("og:description") or m.get("description") or m.get("twitter:description")
                obraz = m.get("og:image") or m.get("og:image:url") or m.get("twitter:image")
                if tytul:
                    wynik["tytul"] = _tekst(tytul, 160)
                if opis:
                    wynik["opis"] = _tekst(opis, 320)
                if obraz:
                    obraz = urljoin(final, obraz.strip())
                    if obraz.startswith("https://"):
                        wynik["obraz"] = obraz
                if m.get("og:site_name"):
                    wynik["serwis"] = _tekst(m["og:site_name"], 60)
                if p.lang:
                    wynik["jezyk"] = p.lang
    except urllib.error.HTTPError as e:
        wynik["kod"] = e.code
        if e.code in (404, 410):
            wynik.update(stan="brak", blad=f"strona nie istnieje (błąd {e.code})")
        elif e.code in (401, 403, 429) or (e.code == 503 and "cloudflare" in str(e.headers.get("Server", "")).lower()):
            wynik.update(stan="blokada", blad=f"serwer nie wpuszcza automatów (kod {e.code}) – w przeglądarce strona zwykle działa")
        else:
            wynik.update(stan="blad", blad=f"serwer zwrócił błąd {e.code}")
    except urllib.error.URLError as e:
        powod = e.reason
        if isinstance(powod, socket.gaierror):
            opis = "domena już nie istnieje"
        elif isinstance(powod, ssl.SSLError):
            opis = "nieważny certyfikat bezpieczeństwa strony"
        elif isinstance(powod, (TimeoutError, socket.timeout)):
            opis = "serwer nie odpowiada (przekroczony czas)"
        else:
            opis = f"nie udało się połączyć ({_tekst(str(powod), 80)})"
        wynik.update(stan="blad", blad=opis)
    except (TimeoutError, socket.timeout):
        wynik.update(stan="blad", blad="serwer nie odpowiada (przekroczony czas)")
    except Exception as e:
        wynik.update(stan="blad", blad=f"nie udało się sprawdzić ({type(e).__name__})")
    return wynik


# ------------------------------------------------------------------ zapis
def wczytaj() -> dict:
    try:
        d = json.loads(WYNIK.read_text(encoding="utf-8"))
        return d.get("zrodla", {}) if isinstance(d, dict) else {}
    except Exception:
        return {}


def scal(stary: dict | None, nowy: dict) -> dict:
    """Gdy strona przestala dzialac, zostawiamy jej dawny tytul/opis/obrazek (dymek pokaze, czym byla)."""
    if not stary:
        return nowy
    if nowy.get("stan") == "dziala":
        nowy["ostatnio_dzialala"] = nowy["sprawdzono"]
        return nowy
    for k in ("tytul", "opis", "obraz", "serwis", "jezyk"):
        if k not in nowy and stary.get(k):
            nowy[k] = stary[k]
    if stary.get("ostatnio_dzialala"):
        nowy["ostatnio_dzialala"] = stary["ostatnio_dzialala"]
    if nowy.get("stan") == "blokada" and stary.get("stan") == "dziala":
        nowy["osadzalna"] = stary.get("osadzalna", False)
    return nowy


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--wszystkie", action="store_true", help="sprawdz wszystkie adresy od nowa")
    ap.add_argument("--dni", type=int, default=7, help="co ile dni ponownie sprawdzac dzialajace strony (domyslnie 7)")
    ap.add_argument("--watki", type=int, default=12, help="ile stron sprawdzac naraz")
    a = ap.parse_args(argv)

    adresy = zbierz_adresy()
    stare = wczytaj()
    granica = (date.today() - timedelta(days=a.dni)).isoformat()
    dzis = date.today().isoformat()

    def do_sprawdzenia(u: str) -> bool:
        s = stare.get(u)
        if a.wszystkie or not s:
            return True
        if s.get("stan") == "dziala":
            return s.get("sprawdzono", "") < granica
        return s.get("sprawdzono", "") < dzis      # niedzialajace - raz dziennie (moze wrocily)

    kolejka = [u for u in adresy if do_sprawdzenia(u)]
    print(f"Źródła przepisów: {len(adresy)} adresów, do sprawdzenia {len(kolejka)}.")
    nowe = {u: stare[u] for u in adresy if u in stare}
    with cf.ThreadPoolExecutor(max_workers=max(1, a.watki)) as ex:
        for u, w in zip(kolejka, ex.map(sprawdz, kolejka)):
            nowe[u] = scal(stare.get(u), w)
            znak = {"dziala": "✓", "blokada": "~", "brak": "✗", "blad": "✗"}.get(w.get("stan"), "?")
            print(f"  {znak} {u[:90]}" + (f"  – {w['blad']}" if w.get("blad") else ""))

    if nowe == stare and WYNIK.exists():
        print("Bez zmian.")
        return 0
    licz = {}
    for w in nowe.values():
        licz[w.get("stan")] = licz.get(w.get("stan"), 0) + 1
    WYNIK.parent.mkdir(parents=True, exist_ok=True)
    tmp = WYNIK.with_suffix(".tmp")
    tmp.write_text(json.dumps({"zaktualizowano": datetime.now().isoformat(timespec="seconds"),
                               "liczby": licz, "zrodla": dict(sorted(nowe.items()))},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(WYNIK)
    print(f"Zapisano {WYNIK.relative_to(ROOT)}: " + ", ".join(f"{k}: {v}" for k, v in sorted(licz.items(), key=lambda x: str(x[0]))))
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # polskie znaki w konsoli Windows
    except Exception:
        pass
    sys.exit(main())
