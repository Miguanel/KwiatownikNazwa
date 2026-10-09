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


def _facts(plant):
    """id informacji -> wpis z wiedza.fakty (url zrodla, jezyk, cytat - fragment oryginalu)."""
    return {f.get("id"): f for f in ((plant.get("wiedza") or {}).get("fakty") or [])
            if isinstance(f, dict) and f.get("id")}


def _refs(plant, nrs, fakty, zr=None, fk=None):
    """Przypisy [n] informacji: nr, url, nazwa zrodla, jezyk i cytat z tego zrodla (dymek zrodla w
    static/js/zrodla_dymki.js: podglad strony, miniatura, link przewijajacy do cytatu)."""
    zr = _sources(plant) if zr is None else zr
    fk = _facts(plant) if fk is None else fk
    out = []
    for n in nrs or []:
        z = zr.get(n)
        if not z:
            continue
        cytat, jezyk = "", z.get("jezyk") or ""
        for fid in fakty or []:
            f = fk.get(fid) or {}
            if str((f.get("zrodlo") or {}).get("url") or "") == z["url"]:
                cytat = cytat or str(f.get("cytat") or "")
                jezyk = jezyk or str(f.get("jezyk") or "")
        out.append({"nr": n, "url": z["url"], "nazwa": z.get("nazwa") or z["url"], "jezyk": jezyk[:5],
                    "cytat": cytat[:300]})
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
    zr, fk = _sources(plant), _facts(plant)
    tresc = []
    for t in entry["tresc"]:
        if not isinstance(t, dict) or not t.get("tekst"):
            continue
        tresc.append({"tekst": str(t["tekst"]), "refs": _refs(plant, t.get("zrodla"), t.get("fakty"), zr, fk)})
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


def _used(plant):
    """Informacje wmontowane w tekst aktualnych scalen (blok "scalone")."""
    sc = plant.get("scalone") if isinstance(plant, dict) else None
    pola = (sc.get("pola") or {}) if isinstance(sc, dict) else {}
    return {f for p, e in pola.items() if scalone(plant, p)        # tylko aktualne scalenia
            for t in (e.get("tresc") or []) for f in (t.get("fakty") or [])}


def poza_rozdzialami(plant, punkt):
    """Czy punkt wiedzy z sieci NIE zostal wmontowany w zaden rozdzial ani rozmieszczony w podrozdziale."""
    ids = punkt.get("fakty") or [] if isinstance(punkt, dict) else []
    return not ids or not set(ids) <= (_used(plant) | _placed_ids(plant))


# ---------------------------------------------------------------- rozmieszczenie (Siedziba: placement.py)
"""Blok "rozmieszczenie" pliku rosliny: punkty wiedzy z sieci, ktorych scalanie nie wplotlo w tekst, ustawione
w konkretnych miejscach strony. "miejsce" = "<rozdzial>/<podrozdzial>":
  - podrozdzial z szablonu (KOTWICE ponizej) -> lista "z sieci" pod jego trescia,
  - inny (nowy, np. "tajemna/historia", "surowce/czesc:korzeń") albo podrozdzial z szablonu, ktorego ta roslina
    nie ma -> nowy podrozdzial na koncu rozdzialu,
  - rozdzial spoza szablonu (dodany w "Ukladzie strony" Siedziby) -> nowy rozdzial po rozdziale "rozdzial_po".
Wstawka niesie tytul i ikone, wiec nowe podrozdzialy i rozdzialy nie wymagaja zmian w szablonie."""
ROZDZIALY = ("natura", "rozpoznawanie", "surowce", "zastosowanie", "bezpieczenstwo", "cykl", "tajemna")
ZASTOSOWANIE = {"medycyna": "medyczne", "kuchnia": "kulinarne", "rzemioslo": "rzemieslnicze",
                "kosmetyka": "kosmetyczne", "ogrod": "ogrodowe"}


def _filled(v):
    return not _empty(v)


def kotwica_widoczna(plant, miejsce):
    """Czy podrozdzial z szablonu jest na stronie tej rosliny (te same warunki co w plant_detail.html)."""
    if not isinstance(plant, dict) or "/" not in str(miejsce):
        return False
    ch, sub = miejsce.split("/", 1)
    pe = plant.get("profil_energetyczny") if isinstance(plant.get("profil_energetyczny"), dict) else {}
    wy = plant.get("wymagania") if isinstance(plant.get("wymagania"), dict) else {}
    idf = plant.get("identyfikacja") if isinstance(plant.get("identyfikacja"), dict) else {}
    za = plant.get("zastosowanie") if isinstance(plant.get("zastosowanie"), dict) else {}
    if ch == "natura" and sub == "profil":
        return bool(pe) or scalone_jest(plant, "profil_energetyczny")
    if ch == "natura" and sub == "wymagania":
        return bool(wy) or scalone_jest(plant, "wymagania")
    if ch == "rozpoznawanie" and sub == "cechy":
        return True                                        # lista cech jest w tresci rozdzialu
    if ch == "rozpoznawanie" and sub == "pomylki":
        return bool(idf.get("mozliwe_pomyłki"))
    if ch == "surowce" and sub.startswith("czesc:"):
        return sub.split(":", 1)[1] in wszystkie_czesci(plant)
    if ch == "zastosowanie" and sub in ZASTOSOWANIE:
        f = ZASTOSOWANIE[sub]
        return _filled(za.get(f)) or bool(scalone(plant, f"zastosowanie.{f}"))
    if ch == "bezpieczenstwo" and sub == "interakcje":
        return _filled(plant.get("interakcje")) or bool(scalone(plant, "interakcje"))
    if ch == "bezpieczenstwo" and sub == "przeciwwskazania":
        return _filled(plant.get("ostrzezenia")) or bool(scalone(plant, "ostrzezenia"))
    if ch == "cykl" and sub == "kalendarz":
        return _filled(plant.get("kalendarz_ogrodnika"))
    if ch == "cykl" and sub == "permakultura":
        return _filled(plant.get("permakultura"))
    if ch == "tajemna" and sub == "ciekawostki":
        return True                                        # lista ciekawostek jest w tresci rozdzialu
    return False


def _placed_ids(plant):
    blk = plant.get("rozmieszczenie") if isinstance(plant, dict) and isinstance(plant.get("rozmieszczenie"), dict) else {}
    out = {f for w in blk.get("wstawki") or [] if isinstance(w, dict)
           for p in w.get("punkty") or [] if isinstance(p, dict) for f in p.get("fakty") or []}
    return out | set(blk.get("duplikaty") or [])


def _wstawki(plant):
    """Wstawki gotowe do szablonu: punkty juz wplecione w tekst scalen pomijane, przypisy z cytatami."""
    blk = plant.get("rozmieszczenie") if isinstance(plant, dict) and isinstance(plant.get("rozmieszczenie"), dict) else {}
    if not blk.get("wstawki"):
        return []
    used, zr, fk = _used(plant), _sources(plant), _facts(plant)
    out = []
    for w in blk["wstawki"]:
        if not isinstance(w, dict) or "/" not in str(w.get("miejsce") or ""):
            continue
        pts = []
        for p in w.get("punkty") or []:
            if not isinstance(p, dict) or not p.get("tekst"):
                continue
            ids = set(p.get("fakty") or [])
            if ids and ids <= used:                         # w miedzyczasie wplecione w tekst rozdzialu
                continue
            pts.append({"tekst": str(p["tekst"]), "czesc": p.get("czesc"),
                        "refs": _refs(plant, p.get("zrodla"), p.get("fakty"), zr, fk)})
        if pts:
            ch = w["miejsce"].split("/", 1)[0]
            out.append({"miejsce": w["miejsce"], "rozdzial_id": ch, "rozdzial": str(w.get("rozdzial") or ch),
                        "tytul": str(w.get("tytul") or w["miejsce"]), "ikona": str(w.get("ikona") or "ra-leaf"),
                        "rozdzial_ikona": str(w.get("rozdzial_ikona") or "ra-leaf"),
                        "rozdzial_po": str(w.get("rozdzial_po") or "tajemna"), "punkty": pts,
                        "kotwica": ch in ROZDZIALY and kotwica_widoczna(plant, w["miejsce"])})
    return out


def wstawka(plant, miejsce):
    """Wstawka do srodka podrozdzialu z szablonu (None, gdy brak)."""
    return next((w for w in _wstawki(plant) if w["miejsce"] == miejsce and w["kotwica"]), None)


def nowe_podrozdzialy(plant, rozdzial):
    """Wstawki rozdzialu z szablonu, ktore staja sie nowymi podrozdzialami (na koncu rozdzialu)."""
    return [w for w in _wstawki(plant) if w["rozdzial_id"] == rozdzial and not w["kotwica"]]


def rozdzial_z_sieci(plant, rozdzial):
    """Czy rozdzial ma cos z rozmieszczenia (wtedy pokazujemy go, nawet gdy reczne pola sa puste)."""
    return any(w["rozdzial_id"] == rozdzial for w in _wstawki(plant))


def wlasne_rozdzialy(plant, po):
    """Rozdzialy spoza szablonu (Uklad strony w Siedzibie) stojace po rozdziale `po`: [{id, tytul, ikona, wstawki}]."""
    out = {}
    for w in _wstawki(plant):
        if w["rozdzial_id"] in ROZDZIALY:
            continue
        after = w["rozdzial_po"] if w["rozdzial_po"] in ROZDZIALY else "tajemna"
        if after != po:
            continue
        ch = out.setdefault(w["rozdzial_id"], {"id": w["rozdzial_id"], "tytul": w["rozdzial"],
                                              "ikona": w["rozdzial_ikona"], "wstawki": []})
        ch["wstawki"].append(w)
    return list(out.values())


def pozostale_z_sieci(plant):
    """Punkty wiedzy z sieci ani niewplecione w tekst, ani nierozmieszczone (np. zanim Siedziba je rozmiesci)."""
    if not isinstance(plant, dict) or not isinstance(plant.get("wiedza"), dict):
        return []
    w = plant["wiedza"]
    taken = _used(plant) | _placed_ids(plant)
    zr, fk = _sources(plant), _facts(plant)
    out = []
    if w.get("sekcje"):
        for sec in w["sekcje"]:
            for p in (sec.get("punkty") or []) if isinstance(sec, dict) else []:
                ids = set(p.get("fakty") or []) if isinstance(p, dict) else set()
                if isinstance(p, dict) and p.get("tekst") and not (ids and ids <= taken):
                    out.append({"tekst": str(p["tekst"]), "czesc": p.get("czesc"),
                                "refs": _refs(plant, p.get("zrodla"), p.get("fakty"), zr, fk)})
    else:                                                     # stary format: same "fakty" bez ukladu
        by_url = {z.get("url"): z.get("nr") for z in w.get("zrodla") or [] if isinstance(z, dict)}
        for f in w.get("fakty") or []:
            if isinstance(f, dict) and f.get("tekst") and f.get("id") not in taken:
                nr = by_url.get((f.get("zrodlo") or {}).get("url"))
                out.append({"tekst": str(f["tekst"]), "czesc": f.get("czesc"),
                            "refs": _refs(plant, [nr] if nr else [], [f.get("id")], zr, fk)})
    return out


def zrodla_wiedzy(plant):
    """Lista zrodel wiedzy z sieci (na dole rozdzialu "Wiedza tajemna"), z jezykiem."""
    return [{"nr": n, "url": z["url"], "nazwa": z.get("nazwa") or z["url"], "jezyk": z.get("jezyk") or ""}
            for n, z in sorted(_sources(plant).items())]


def register(app):
    app.add_template_global(wszystkie_czesci, "wszystkie_czesci")
    app.add_template_global(scalone, "scalone")
    app.add_template_global(scalone_jest, "scalone_jest")
    app.add_template_global(poza_rozdzialami, "poza_rozdzialami")
    app.add_template_global(wstawka, "wstawka")
    app.add_template_global(nowe_podrozdzialy, "nowe_podrozdzialy")
    app.add_template_global(rozdzial_z_sieci, "rozdzial_z_sieci")
    app.add_template_global(wlasne_rozdzialy, "wlasne_rozdzialy")
    app.add_template_global(pozostale_z_sieci, "pozostale_z_sieci")
    app.add_template_global(zrodla_wiedzy, "zrodla_wiedzy")


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
