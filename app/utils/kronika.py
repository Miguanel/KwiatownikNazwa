# app/utils/kronika.py
"""Kronika Siedziby (papirus na stronie glownej): historia aktualizacji Kwiatownika.

Wpisy pochodza z data/changelog.json - pisze go agent wdrozen Siedziby przy kazdej publikacji
(co nowego: informacje o roslinach, przepisy, zdjecia). Starsza historia (sprzed agenta) jest odtwarzana
z samych plikow roslin: daty w blokach "wiedza", "zdjecia_wiki" i "scalone".
Stan Siedziby na zywo (czy teraz pracuje) dokleja w przegladarce static/js/papirus.js z backendu.
"""
import json
import os
from collections import defaultdict
from datetime import datetime

from flask import current_app

MIESIACE = ["stycznia", "lutego", "marca", "kwietnia", "maja", "czerwca", "lipca", "sierpnia", "września",
            "października", "listopada", "grudnia"]
JEZYKI = {"zh": "chińskie", "ja": "japońskie", "uk": "ukraińskie", "ru": "rosyjskie", "de": "niemieckie",
          "fr": "francuskie", "en": "angielskie", "cs": "czeskie", "pl": "polskie", "it": "włoskie", "es": "hiszpańskie",
          "lt": "litewskie", "sk": "słowackie", "hu": "węgierskie", "ro": "rumuńskie", "bg": "bułgarskie"}


def odmiana(n, jeden, kilka, wiele):
    """Polska odmiana: 1 roslina, 2-4 rosliny, 5+ roslin (12-14 zawsze 'wiele')."""
    n = int(n)
    if n == 1:
        return jeden
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return kilka
    return wiele


def data_pl(iso):
    """'2026-10-08T20:30:00+02:00' -> '8 października 2026'."""
    try:
        d = datetime.fromisoformat(str(iso).replace('Z', '+00:00'))
    except ValueError:
        return str(iso)[:10]
    return f"{d.day} {MIESIACE[d.month - 1]} {d.year}"


def _read(path):
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _root():
    return os.path.abspath(os.path.join(current_app.root_path, '..'))


def wpisy_z_changelogu(root):
    data = _read(os.path.join(root, 'data', 'changelog.json'))
    rows = data.get('wpisy') if isinstance(data, dict) else data if isinstance(data, list) else []
    out = []
    for w in rows or []:
        if not isinstance(w, dict) or not w.get('data'):
            continue
        liczby = w.get('liczby') if isinstance(w.get('liczby'), dict) else {}
        out.append({
            'data': str(w['data']), 'kiedy': data_pl(w['data']), 'tytul': str(w.get('tytul') or 'Aktualizacja Kwiatownika'),
            'opis': str(w.get('opis') or ''), 'liczby': liczby,
            'rosliny': [r for r in (w.get('rosliny') or []) if isinstance(r, dict) and r.get('id')][:8],
            'przepisy': [p for p in (w.get('przepisy') or []) if isinstance(p, dict) and p.get('tytul')][:4],
            'zrodlo': 'siedziba',
        })
    return out


def wpisy_z_plikow(root):
    """Historia sprzed agenta wdrozen: kiedy Siedziba dopisala wiedze / zdjecia / scalenie do plikow roslin."""
    folder = os.path.join(root, 'data', 'plants')
    dni = defaultdict(lambda: {'wiedza': [], 'zdjecia': [], 'scalone': []})
    try:
        names = sorted(f for f in os.listdir(folder) if f.endswith('.json'))
    except OSError:
        return []
    for name in names:
        d = _read(os.path.join(folder, name))
        if not isinstance(d, dict):
            continue
        pid, nazwa = name[:-5], d.get('nazwa_pl') or name[:-5]
        w = d.get('wiedza') if isinstance(d.get('wiedza'), dict) else {}
        if w.get('zaktualizowano'):
            pkt = sum(len(s.get('punkty') or []) for s in w.get('sekcje') or [] if isinstance(s, dict)) \
                or len(w.get('fakty') or [])
            jez = sorted({str(z.get('jezyk') or '')[:2].lower() for z in w.get('zrodla') or [] if isinstance(z, dict)}
                         - {'', 'pl'})
            dni[str(w['zaktualizowano'])[:10]]['wiedza'].append({'id': pid, 'nazwa': nazwa, 'nowe': pkt, 'jezyki': jez})
        zw = d.get('zdjecia_wiki') if isinstance(d.get('zdjecia_wiki'), dict) else {}
        if zw.get('zaktualizowano') and zw.get('zdjecia'):
            dni[str(zw['zaktualizowano'])[:10]]['zdjecia'].append({'id': pid, 'nazwa': nazwa, 'n': len(zw['zdjecia'])})
        sc = d.get('scalone') if isinstance(d.get('scalone'), dict) else {}
        if sc.get('zaktualizowano'):
            dni[str(sc['zaktualizowano'])[:10]]['scalone'].append({'id': pid, 'nazwa': nazwa})
    out = []
    for day, x in dni.items():
        if not day[:4].isdigit():
            continue
        info = sum(r['nowe'] for r in x['wiedza'])
        parts = []
        nw, ns, nz = len(x['wiedza']), len(x['scalone']), len(x['zdjecia'])
        if nw:
            parts.append(f"wiedza z sieci o {nw} {odmiana(nw, 'roślinie', 'roślinach', 'roślinach')} "
                         f"({info} {odmiana(info, 'informacja', 'informacje', 'informacji')} ze źródłami)")
        if ns:
            parts.append(f"wiedza wpleciona w rozdziały {ns} {odmiana(ns, 'rośliny', 'roślin', 'roślin')}")
        if nz:
            parts.append(f"zdjęcia z Wikimedia Commons dla {nz} {odmiana(nz, 'rośliny', 'roślin', 'roślin')}")
        rosliny = sorted(x['wiedza'], key=lambda r: -r['nowe']) or [{'id': r['id'], 'nazwa': r['nazwa']} for r in x['zdjecia']]
        out.append({'data': day, 'kiedy': data_pl(day), 'tytul': 'Siedziba uzupełniła Kwiatownik',
                    'opis': ('; '.join(parts)[:1].upper() + '; '.join(parts)[1:] + '.') if parts else '', 'liczby': {'informacje': info, 'rosliny': len(x['wiedza'])},
                    'rosliny': rosliny[:8], 'przepisy': [], 'zrodlo': 'pliki'})
    return out


def kronika(limit=12):
    """Wpisy papirusu od najnowszych: z changelogu agenta + starsza historia z plikow roslin."""
    root = _root()
    nowe = wpisy_z_changelogu(root)
    najstarszy = min((w['data'][:10] for w in nowe), default='9999')
    stare = [w for w in wpisy_z_plikow(root) if w['data'][:10] < najstarszy]
    wpisy = sorted(nowe + stare, key=lambda w: w['data'], reverse=True)[:limit]
    for w in wpisy:
        l = w['liczby']
        w['liczby_txt'] = [t for t in (
            f"+{l['informacje']} {odmiana(l['informacje'], 'informacja', 'informacje', 'informacji')}" if l.get('informacje') else '',
            f"+{l['przepisy']} {odmiana(l['przepisy'], 'przepis', 'przepisy', 'przepisów')}" if l.get('przepisy') else '',
            f"+{l['nowe_rosliny']} {odmiana(l['nowe_rosliny'], 'nowa roślina', 'nowe rośliny', 'nowych roślin')}" if l.get('nowe_rosliny') else '',
            f"+{l['zdjecia']} {odmiana(l['zdjecia'], 'zdjęcie', 'zdjęcia', 'zdjęć')}" if l.get('zdjecia') else '') if t]
        for r in w['rosliny']:
            r['jezyki_txt'] = ', '.join(JEZYKI.get(j, j) for j in (r.get('jezyki') or [])[:4])
    return wpisy
