# app/utils/ochrona.py
"""Ochrona gatunkowa roslin w Polsce (data/ochrona_gatunkowa.json) - dla strony rosliny, Bestiariusza i Mojego zielnika.
Plik jest reczny: status kazdej rosliny sprawdzony w rozporzadzeniu Dz.U. 2014 poz. 1409 (zalaczniki 1-3)."""
import json
import os

from flask import current_app

_cache = {'mtime': None, 'data': None}


def _path():
    return os.path.join(current_app.root_path, '..', 'data', 'ochrona_gatunkowa.json')


def dane():
    """Caly plik ochrony (akt, statusy, rosliny, uwagi ogolne, zrodla); pusty slownik, gdy pliku brak."""
    path = _path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache['mtime'] != mtime:
        try:
            with open(path, encoding='utf-8') as f:
                _cache.update(mtime=mtime, data=json.load(f))
        except (OSError, ValueError):
            _cache.update(mtime=mtime, data={})
    return _cache['data'] or {}


def ochrona(plant_id):
    """Status rosliny: {'status', 'nazwa', 'ikona', 'zbior', 'pozyskiwanie', 'porada', 'akt'} albo None (nie chroniona)."""
    d = dane()
    wpis = (d.get('rosliny') or {}).get(plant_id)
    if not isinstance(wpis, dict):
        return None
    st = (d.get('statusy') or {}).get(wpis.get('status'), {})
    return {**wpis, 'nazwa': st.get('nazwa', wpis.get('status')), 'ikona': st.get('ikona', 'bi-shield'),
            'zbior': st.get('zbior', ''), 'akt': d.get('akt') or {}, 'ogolne': d.get('ogolne') or [],
            'zrodla': d.get('zrodla') or []}
