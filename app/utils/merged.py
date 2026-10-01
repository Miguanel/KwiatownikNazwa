# app/utils/merged.py
"""Wiedza z sieci wmontowana przez Siedzibe Kwiatownika w rozdzialy strony rosliny (blok "scalone").

Plik rosliny: reczne pola (np. zastosowanie.medyczne) zostaja bez zmian, a obok nich
"scalone": {"pola": {"zastosowanie.medyczne": {"typ": "tekst"|"lista", "oryginal": <reczny tekst>,
            "tresc": [{"tekst": "...", "zrodla": [1, 3]}]}}, "uzyte_fakty": [...]}
Numery zrodel wskazuja na wiedza.zrodla (nr -> nazwa, url).
Szablon pokazuje wersje scalona tylko, gdy "oryginal" == obecna wartosc pola (gdy ktos zmienil reczny
tekst po scaleniu, wygrywa tekst reczny)."""
import re

URL_RE = re.compile(r"^https?://", re.I)


def _get(data, path):
    cur = data
    for key in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _empty(v):
    if v is None:
        return True
    if isinstance(v, str):
        return not v.strip()
    if isinstance(v, (list, dict)):
        return not v
    return False


def _sources(plant):
    out = {}
    for z in ((plant.get("wiedza") or {}).get("zrodla") or []):
        if isinstance(z, dict) and isinstance(z.get("nr"), int) and URL_RE.match(str(z.get("url") or "")):
            out[z["nr"]] = z
    return out


def scalone(plant, path):
    """Podrozdzial scalony z wiedza z sieci albo None (brak scalenia / reczny tekst zmienil sie od scalenia).
    Wynik: {"typ", "tresc": [{"tekst", "refs": [{"nr", "url", "nazwa"}]}], "oryginal", "oryginal_txt"}."""
    if not isinstance(plant, dict):
        return None
    entry = ((plant.get("scalone") or {}).get("pola") or {}).get(path) if isinstance(plant.get("scalone"), dict) else None
    if not isinstance(entry, dict) or not entry.get("tresc"):
        return None
    current = _get(plant, path)
    orig = entry.get("oryginal")
    if not ((orig is None and _empty(current)) or orig == current):
        return None
    zr = _sources(plant)
    tresc = []
    for t in entry["tresc"]:
        if not isinstance(t, dict) or not t.get("tekst"):
            continue
        tresc.append({"tekst": str(t["tekst"]),
                      "refs": [zr[n] for n in (t.get("zrodla") or []) if n in zr]})
    if not tresc:
        return None
    if isinstance(orig, list):
        orig_txt = " / ".join(str(x) for x in orig)
    else:
        orig_txt = str(orig) if orig else ""
    return {"typ": entry.get("typ") or "tekst", "tresc": tresc, "oryginal": orig, "oryginal_txt": orig_txt}


def scalone_jest(plant, prefix):
    """Czy jakis podrozdzial o tej sciezce (albo pod nia) ma aktualne scalenie - np. 'zastosowanie'."""
    pola = ((plant.get("scalone") or {}).get("pola") or {}) if isinstance(plant, dict) and \
        isinstance(plant.get("scalone"), dict) else {}
    return any((p == prefix or p.startswith(prefix + ".")) and scalone(plant, p) for p in pola)


def poza_rozdzialami(plant, punkt):
    """Czy punkt wiedzy z sieci NIE zostal wmontowany w zaden rozdzial (wtedy pokazujemy go w zakladce
    'Wiedza z sieci'; wmontowane sa juz w swoich rozdzialach)."""
    sc = plant.get("scalone") if isinstance(plant, dict) else None
    pola = (sc.get("pola") or {}) if isinstance(sc, dict) else {}
    used = {f for p, e in pola.items() if scalone(plant, p)        # tylko aktualne scalenia
            for t in (e.get("tresc") or []) for f in (t.get("fakty") or [])}
    ids = punkt.get("fakty") or [] if isinstance(punkt, dict) else []
    return not ids or not set(ids) <= used


def register(app):
    app.add_template_global(wszystkie_czesci, "wszystkie_czesci")
    app.add_template_global(scalone, "scalone")
    app.add_template_global(scalone_jest, "scalone_jest")
    app.add_template_global(poza_rozdzialami, "poza_rozdzialami")


# ---------------------------------------------------------------- czesci rosliny z sieci
PART_FIELDS = ("opis_botaniczny", "wlasciwości", "skladniki_aktywne", "czas_zbioru", "ostrzezenia")
CORE_FIELDS = ("wlasciwości", "skladniki_aktywne")


def czesci_z_sieci(plant):
    """Czesci rosliny znane tylko z wiedzy z sieci (Siedziba: scalone["czesci_rosliny.<czesc>.<pole>"]),
    ktorych nie ma w recznym czesci_rosliny - z dzialaniem albo substancjami czynnymi."""
    if not isinstance(plant, dict) or not isinstance(plant.get("scalone"), dict):
        return {}
    own = plant.get("czesci_rosliny") if isinstance(plant.get("czesci_rosliny"), dict) else {}
    out = {}
    for path in (plant["scalone"].get("pola") or {}):
        bits = path.split(".")
        if len(bits) != 3 or bits[0] != "czesci_rosliny" or bits[1] in own or bits[1] in out:
            continue
        part = bits[1]
        if any(scalone(plant, f"czesci_rosliny.{part}.{f}") for f in CORE_FIELDS):
            out[part] = {"nazwa_surowca": part.capitalize(), "_z_sieci": True}
    return out


def wszystkie_czesci(plant):
    """Reczne czesci rosliny + czesci z sieci (do zakladki "Surowce i zbiory" i generatora)."""
    own = plant.get("czesci_rosliny") if isinstance(plant, dict) and isinstance(plant.get("czesci_rosliny"), dict) else {}
    out = dict(own)
    out.update(czesci_z_sieci(plant))
    return out


def _as_text(value):
    if isinstance(value, list):
        return ", ".join(str(x) for x in value if x)
    return str(value or "")


def tekst_pola(plant, path, value, sep=" "):
    """Tekst pola do uzycia poza szablonem (generator, wyszukiwarka): wersja scalona albo reczna."""
    m = scalone(plant, path)
    if m:
        return sep.join(t["tekst"] for t in m["tresc"])
    return _as_text(value)


def czesci_generatora(plant):
    """{czesc: {props, ingr, warn, web}} dla generatora mieszanek - reczne czesci (z wiedza z sieci
    wmontowana w ich podrozdzialy) + nowe czesci znane tylko z sieci."""
    general = plant.get("ostrzezenia")
    general = " ".join(general) if isinstance(general, list) else str(general or "")
    out = {}
    for name, dane in wszystkie_czesci(plant).items():
        if not isinstance(dane, dict):
            continue
        base = f"czesci_rosliny.{name}."
        wk = "wlasciwosci" if ("wlasciwosci" in dane and "wlasciwości" not in dane) else "wlasciwości"
        props = tekst_pola(plant, base + wk, dane.get(wk) or dane.get("wlasciwosci"))
        ingr = tekst_pola(plant, base + "skladniki_aktywne", dane.get("skladniki_aktywne"), sep=", ")
        # ostrzezenie TEJ czesci (reczne albo z sieci); ogolne ostrzezenia gatunku sa osobno (ostrzezenia_generatora)
        warn = tekst_pola(plant, base + "ostrzezenia", dane.get("ostrzezenia"))
        out[name] = {"props": props, "ingr": ingr, "warn": warn, "web": bool(dane.get("_z_sieci")),
                     "warn_web": bool(scalone(plant, base + "ostrzezenia"))}
    return out


def ostrzezenia_generatora(plant):
    """Ostrzezenia calej rosliny dla generatora: przeciwwskazania + interakcje z lekami - wersja z wiedza
    z sieci (Siedziba), gdy jest scalona, inaczej reczna. Tekst bez HTML (szablon go escapuje)."""
    parts = []
    for path, label in (("ostrzezenia", "Przeciwwskazania"), ("interakcje", "Interakcje z lekami")):
        text = tekst_pola(plant, path, plant.get(path)).strip()
        if text:
            parts.append(f"{label}: {text}" + (" (uzupełnione wiedzą z sieci)" if scalone(plant, path) else ""))
    return " | ".join(parts)
