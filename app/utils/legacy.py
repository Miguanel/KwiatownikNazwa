# app/utils/legacy.py
"""Dane roslin z archiwum pierwszego Kwiatownika (data/plants/<kategoria>/<id>.json, stary format:
gatunek, Cechy, Ogrodnictwo, Przepisy...). Nowy Kwiatownik czyta pliki z data/plants/<id>.json - tu
udostepniamy archiwalne tresci (historia, legendy, barwniki, kosmetyka, bibliografia) oraz rosliny,
ktore istnieja tylko w archiwum."""
import json
import os
import re

LEGACY_DIRS = ("ziola", "drzewa", "krzewy", "bulwy", "cebule", "egzotyczne")
URL_RE = re.compile(r"^https?://", re.I)


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def find_legacy_file(plants_dir, pid):
    for cat in LEGACY_DIRS:
        path = os.path.join(plants_dir, cat, f"{pid}.json")
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return path, cat
    return None, None


def legacy_only_ids(plants_dir):
    """Rosliny, ktore sa tylko w archiwum (bez pliku w nowym formacie)."""
    roots = {f[:-5] for f in os.listdir(plants_dir) if f.endswith(".json")} if os.path.isdir(plants_dir) else set()
    out = []
    for cat in LEGACY_DIRS:
        folder = os.path.join(plants_dir, cat)
        if not os.path.isdir(folder):
            continue
        for f in sorted(os.listdir(folder)):
            pid = f[:-5]
            if f.endswith(".json") and pid not in roots and pid not in out and not pid[-1].isdigit():
                out.append(pid)
    return out


def _collect_urls(value, acc):
    if isinstance(value, str):
        if URL_RE.match(value.strip()) and value.strip() not in acc:
            acc.append(value.strip())
    elif isinstance(value, list):
        for v in value:
            _collect_urls(v, acc)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_urls(v, acc)


def get_legacy_plant(plants_dir, pid):
    """Archiwalne sekcje rosliny w uporzadkowanej postaci (albo None)."""
    path, cat = find_legacy_file(plants_dir, pid)
    if not path:
        return None
    d = _load(path)
    if not d:
        return None
    cechy = d.get("Cechy") if isinstance(d.get("Cechy"), dict) else {}
    ogrod = d.get("Ogrodnictwo") if isinstance(d.get("Ogrodnictwo"), dict) else {}
    get = lambda key: cechy.get(key) if cechy.get(key) is not None else d.get(key)  # noqa: E731
    inne = get("inne_zastosowania") if isinstance(get("inne_zastosowania"), dict) else {}
    barwniki = inne.get("barwniki")
    sections = [
        ("historia", "Historia i legendy", get("cechy_i_historia")),
        ("kultura", "Ciekawostki kulturowe", d.get("ciekawostki_kulturowe")),
        ("barwniki", "Barwienie (tkaniny, włosy)", barwniki),
        ("inne", "Inne zastosowania", {k: v for k, v in inne.items() if k != "barwniki"} or None),
        ("botanika", "Opis botaniczny", get("opis_botaniczny")),
        ("wystepowanie", "Występowanie", get("wystepowanie")),
        ("sklad", "Właściwości i składniki", get("wlasciwosci_i_skladniki")),
        ("uwagi", "Uwagi i ostrzeżenia", get("uwagi_i_ostrzezenia")),
        ("uprawa", "Uprawa", ogrod.get("uprawa")),
        ("kalendarz", "Kalendarz", ogrod.get("kalendarz") or d.get("kalendarz")),
        ("zamienniki_tytoniu", "Zamienniki tytoniu (historycznie)", d.get("zamienniki_tytoniu")),
    ]
    sections = [(k, t, v) for k, t, v in sections if v]
    urls = []
    _collect_urls(d.get("bibliografia"), urls)
    for _, _, v in sections:
        _collect_urls(v, urls)
    return {"kategoria": cat, "gatunek": d.get("gatunek"), "nazwa_lacinska": d.get("nazwa_lacinska"),
            "zdjecia": [z for z in (d.get("zdjecia") or []) if isinstance(z, str)],
            "sekcje": sections, "bibliografia": urls}


def _text(v):
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return v.get("opis") or v.get("uwaga") or ""
    return ""


def legacy_as_plant(plants_dir, pid):
    """Minimalny rekord w nowym formacie dla rosliny obecnej tylko w archiwum."""
    leg = get_legacy_plant(plants_dir, pid)
    if not leg:
        return None
    raw = _load(find_legacy_file(plants_dir, pid)[0]) or {}
    cechy = raw.get("Cechy") if isinstance(raw.get("Cechy"), dict) else {}
    hist = cechy.get("cechy_i_historia") if isinstance(cechy.get("cechy_i_historia"), dict) else {}
    uwagi = cechy.get("uwagi_i_ostrzezenia") or []
    ciek = [c for c in (hist.get("ciekawostki") or []) + (raw.get("ciekawostki_kulturowe") or []) if isinstance(c, str)]
    zbior = [z for z in (raw.get("nazwa_zbioru") or []) if isinstance(z, str)]
    return {
        "id": pid,
        "nazwa_pl": leg["gatunek"] or pid.replace("_", " ").capitalize(),
        "nazwa_lat": leg["nazwa_lacinska"] or "",
        "rodzina": next((z for z in zbior if z.lower().endswith(("owate", "aceae"))), ""),
        "opis": _text(hist) or "",
        "tagi": ["archiwum"],
        "ciekawostki": ciek[:12],
        "ostrzezenia": " ".join(t for t in (_text(u) for u in uwagi if u) if t),
        "url": {f"zdjęcie {i}": z for i, z in enumerate(leg["zdjecia"][:4], 1)} or None,
        "_archiwum": True,
    }
