# app/utils/kronika.py
"""Kronika Siedziby (papirus na stronie glownej): historia aktualizacji Kwiatownika.

Wpisy pochodza z data/changelog.json - pisze go agent wdrozen Siedziby przy kazdej publikacji
(co nowego: informacje o roslinach, przepisy, zdjecia). Starsza historia (sprzed agenta) jest odtwarzana
z samych plikow roslin: daty w blokach "wiedza", "zdjecia_wiki" i "scalone".
Stan Siedziby (nad czym pracuje, ostatnie wpisy dziennika, statystyki strony) pochodzi z data/siedziba_stan.json -
zapisuje i commituje go agent wdrozen Siedziby, wiec strona nie pyta backendu (szybsze ladowanie na telefonie).
static/js/papirus.js tylko przelicza "X temu" w przegladarce.
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


LICZBY = ('informacje', 'przepisy', 'nowe_rosliny', 'zdjecia', 'rozmieszczone')


def _opis_dnia(liczby, rosliny):
    """Tytul i opis wpisu po polaczeniu kilku publikacji z jednego dnia (te same zwroty co agent wdrozen)."""
    n_pl, n_pt, n_rc, n_mv = len(rosliny), liczby.get('informacje', 0), liczby.get('przepisy', 0), \
        liczby.get('rozmieszczone', 0)
    bits = []
    if n_pl and n_pt:
        bits.append(f"nowa wiedza o {n_pl} {odmiana(n_pl, 'roślinie', 'roślinach', 'roślinach')}")
    if n_rc:
        bits.append(f"{n_rc} {odmiana(n_rc, 'nowy przepis', 'nowe przepisy', 'nowych przepisów')}")
    if n_mv and not bits:
        bits.append('wiedza z sieci rozłożona po rozdziałach')
    if liczby.get('zdjecia') and not bits:
        bits.append('nowe zdjęcia roślin')
    tytul = ' i '.join(bits) or 'Porządki w danych Kwiatownika'
    jez = sorted({j for r in rosliny for j in r.get('jezyki') or []})
    opis = []
    if n_pt:
        opis.append(f"Siedziba zebrała {n_pt} {odmiana(n_pt, 'sprawdzoną informację', 'sprawdzone informacje', 'sprawdzonych informacji')}"
                    + (f" (źródła: {', '.join(JEZYKI.get(j, j) for j in jez[:5])})" if jez else '') + '.')
    if liczby.get('nowe_rosliny'):
        opis.append(f"Nowe rośliny w zielniku: {liczby['nowe_rosliny']}.")
    if n_mv:
        opis.append(f"{n_mv} {odmiana(n_mv, 'informacja z sieci trafiła', 'informacje z sieci trafiły', 'informacji z sieci trafiło')}"
                    ' do właściwych rozdziałów i podrozdziałów stron roślin.')
    if liczby.get('zdjecia'):
        opis.append(f"Dodano {liczby['zdjecia']} {odmiana(liczby['zdjecia'], 'zdjęcie', 'zdjęcia', 'zdjęć')} z Wikimedia Commons.")
    return tytul[:1].upper() + tytul[1:], ' '.join(opis)


def polacz_dni(wpisy):
    """Kilka publikacji Siedziby tego samego dnia -> jeden wpis kroniki: liczby sie sumuja, ta sama roslina
    raz (informacje zsumowane, jezyki zrodel polaczone), przepisy bez powtorzen, godziny publikacji zapamietane.
    Agent wdrozen laczy juz przy zapisie; to zabezpiecza starsze wpisy w data/changelog.json."""
    dni = {}
    for w in wpisy:
        dni.setdefault(w['data'][:10], []).append(w)
    out = []
    for grupa in dni.values():
        if len(grupa) == 1:
            out.append(grupa[0])
            continue
        grupa = sorted(grupa, key=lambda w: w['data'], reverse=True)
        liczby = {k: 0 for k in LICZBY}
        rosliny, przepisy = {}, []
        for w in grupa:
            for k in LICZBY:
                try:
                    liczby[k] += int(w['liczby'].get(k) or 0)
                except (TypeError, ValueError):
                    pass
            for r in w['rosliny']:
                x = rosliny.setdefault(r['id'], {'id': r['id'], 'nazwa': r.get('nazwa') or r['id'], 'nowe': 0, 'jezyki': []})
                x['nowe'] += int(r.get('nowe') or 0)
                x['jezyki'] = sorted(set(x['jezyki']) | set(r.get('jezyki') or []))
            for p in w['przepisy']:
                if all(q.get('tytul') != p.get('tytul') for q in przepisy):
                    przepisy.append(p)
        rosliny = sorted(rosliny.values(), key=lambda r: -r['nowe'])
        liczby['rosliny'] = len(rosliny)
        tytul, opis = _opis_dnia(liczby, rosliny)
        godziny = sorted({g for w in grupa for g in (w.get('godziny') or [w['data'][11:16]]) if g})
        out.append(dict(grupa[0], tytul=tytul, opis=opis, liczby=liczby, rosliny=rosliny[:8], przepisy=przepisy[:4],
                        aktualizacje=sum(w.get('aktualizacje') or 1 for w in grupa), godziny=godziny))
    return out


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
            'aktualizacje': int(w.get('aktualizacje') or 1) if str(w.get('aktualizacje') or 1).isdigit() else 1,
            'godziny': [str(g)[:5] for g in (w.get('godziny') or []) if isinstance(g, str)][:12],
        })
    return polacz_dni(out)


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


def godzina_pl(iso):
    """'2026-10-08T20:30:00+02:00' -> '8 października 2026, 20:30'."""
    try:
        d = datetime.fromisoformat(str(iso).replace('Z', '+00:00'))
    except ValueError:
        return str(iso)[:16]
    return f"{d.day} {MIESIACE[d.month - 1]} {d.year}, {d.hour}:{d.minute:02d}"


def _safe_url(url):
    return url if isinstance(url, str) and (url.startswith('/') and not url.startswith('//')
                                            or url.startswith('https://')) else ''


def stan_siedziby():
    """Stan Siedziby z data/siedziba_stan.json (agent wdrozen) albo None, gdy pliku jeszcze nie ma.

    Format pliku: {zaktualizowano, siedziba: {status, zadania[{opis, od}], info}, wpisy[{ts, kind, text, url}],
    statystyki: {goscie_tydzien, odslony_tydzien, plantid_razem, plantid_tydzien, najczesciej_czytane[{id, nazwa, n}]}}
    """
    data = _read(os.path.join(_root(), 'data', 'siedziba_stan.json'))
    if not isinstance(data, dict) or not data.get('zaktualizowano'):
        return None
    s = data.get('siedziba') if isinstance(data.get('siedziba'), dict) else {}
    zadania = [{'opis': str(z.get('opis') or 'zadanie')[:120], 'od': str(z.get('od') or '')}
               for z in (s.get('zadania') or []) if isinstance(z, dict)][:3]
    wpisy = []
    for w in data.get('wpisy') or []:
        if isinstance(w, dict) and w.get('text') and w.get('ts'):
            wpisy.append({'ts': str(w['ts']), 'kiedy': godzina_pl(w['ts']), 'kind': str(w.get('kind') or 'info')[:20],
                          'text': str(w['text'])[:300], 'url': _safe_url(w.get('url'))})
    st = data.get('statystyki') if isinstance(data.get('statystyki'), dict) else {}

    def num(key):
        try:
            return max(0, int(st.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    liczby = []
    for key, forms, suffix in (('goscie_tydzien', ('wizyta', 'wizyty', 'wizyt'), 'w tygodniu'),
                               ('odslony_tydzien', ('odsłona', 'odsłony', 'odsłon'), 'roślin w tygodniu'),
                               ('plantid_razem', ('rozpoznanie', 'rozpoznania', 'rozpoznań'), 'rośliny ze zdjęcia')):
        n = num(key)
        if n:
            liczby.append({'n': f"{n:,}".replace(',', '\u00a0'), 'tekst': f"{odmiana(n, *forms)} {suffix}"})
    top = [{'id': str(t['id']), 'nazwa': str(t.get('nazwa') or t['id'])}
           for t in (st.get('najczesciej_czytane') or []) if isinstance(t, dict) and t.get('id')][:4]
    return {
        'zaktualizowano': str(data['zaktualizowano']), 'kiedy': godzina_pl(data['zaktualizowano']),
        'pracuje': s.get('status') == 'pracuje' and bool(zadania), 'zadania': zadania,
        'wpisy': wpisy[:6], 'liczby': liczby, 'najczesciej_czytane': top,
    }
