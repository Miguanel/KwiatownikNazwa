import os
import json

# Słownik do tłumaczenia cyfr na nazwy miesięcy
MIESIACE_MAP = {
    1: "styczeń", 2: "luty", 3: "marzec", 4: "kwiecień",
    5: "maj", 6: "czerwiec", 7: "lipiec", 8: "sierpień",
    9: "wrzesień", 10: "październik", 11: "listopad", 12: "grudzień"
}

# Przykład bazy danych ciekawostek (Knowledge Pool)
FESTIVAL_KNOWLEDGE = {
    "Szczodre Gody (Yule)": [
        {"roslina": "Jemioła", "tresc": "Wieszana pod sufitem miała chronić dom przed złymi mocami i piorunami."},
        {"roslina": "Świerk", "tresc": "W tradycji ludowej igliwie świerkowe palone w piecu miało oczyszczać atmosferę domostwa."},
        {"roslina": "Pszenica", "tresc": "Ziarno pszenicy pod obrusem symbolizowało nadzieję na obfite plony w nowym roku."}
    ],
    "Gromnica (Imbolc)": [
        {"roslina": "Len", "tresc": "W Imbolc tradycyjnie błogosławiono ziarna lnu, by zapewnić sobie dobre zbiory ubrań."},
        {"roslina": "Przebiśnieg", "tresc": "Pierwszy kwiat wiosny, symbol nadziei i czystości, poświęcony bogini Brygidzie."},
        {"roslina": "Wierzba", "tresc": "Bazie wierzbowe (kotki) uznawano za znak, że soki w ziemi zaczęły krążyć na nowo."}
    ],
    "Jare Gody (Ostara)": [
        {"roslina": "Brzoza", "tresc": "Wierzono, że uderzenie gałązką brzozy w Jare Gody przekazuje żywotność i zdrowie."},
        {"roslina": "Mniszek Lekarski", "tresc": "Młode listki mniszka zbierane teraz mają najwięcej sił witalnych i oczyszczają krew po zimie."},
        {"roslina": "Rzeżucha", "tresc": "Szybki wzrost rzeżuchy na oknie symbolizuje potęgę odradzającej się natury."}
    ],
    "Beltane / Zielone Świątki": [
        {"roslina": "Głóg", "tresc": "Uważany za drzewo wróżek; w Beltane nie wolno go ścinać, by nie ściągnąć na siebie pecha."},
        {"roslina": "Jarzębina", "tresc": "Gałązki jarzębiny zatknięte nad drzwiami w nocy majowej chroniły inwentarz przed urokami."},
        {"roslina": "Pokrzywa", "tresc": "W maju pokrzywa ma największą moc odżywczą – to idealny czas na majową zupę witaminową."}
    ],
    "Noc Kupały (Litha)": [
        {"roslina": "Dziurawiec", "tresc": "Ziele świętojańskie zebrane w południe Litha posiada najsilniejsze właściwości ochronne i lecznicze."},
        {"roslina": "Paproć", "tresc": "Legenda o kwiatku paproci to metafora poszukiwania mądrości i ukrytych skarbów ziemi."},
        {"roslina": "Bylica", "tresc": "Bylica przepasująca biodra podczas skoków przez ogniska miała zabierać wszelkie choroby."}
    ],
    # ... i tak dalej dla każdego festiwalu
    "GENERAL": [
        {"roslina": "Dąb", "tresc": "Dąb szypułkowy ściąga najwięcej piorunów ze wszystkich drzew w lesie."},
        {"roslina": "Sosna", "tresc": "Syrop z młodych pędów sosny to najstarszy słowiański sposób na kaszel."},
        {"roslina": "Bez Czarny", "tresc": "Wierzono, że w korzeniach bzu mieszkają opiekuńcze duchy ogrodu."}
    ]
}

def build_calendar_from_jsons(data_dir='data/plants'):
    okresy = {}  # Dla Miesięcy (np. "maj")
    czynnosci = {}  # Dla Zadań (np. "Zbiór liści na syrop")

    if os.path.exists(data_dir):
        for filename in os.listdir(data_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(data_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        plant_data = json.load(f)
                        nazwa_rosliny = plant_data.get('nazwa_pl', '')
                        if not nazwa_rosliny: continue

                        # Pobieramy nową strukturę kalendarza ogrodnika
                        kalendarz = plant_data.get('kalendarz_ogrodnika', {})
                        zadania = kalendarz.get('zadania', [])

                        for z in zadania:
                            tytul = z.get('czynnosc', '').strip()
                            desc = z.get('opis', '')
                            miesiace = z.get('miesiace', [])

                            # Pobieranie nowych, magicznych danych
                            faza = z.get('faza_ksiezyca', '')
                            pora = z.get('pora_dnia', '')
                            pogoda = z.get('pogoda', '')

                            # Domyślna ikona (zmienia się w zależności od słowa w tytule)
                            icon = "ra-scythe" if "Zbiór" in tytul else ("ra-sprout" if "Siew" in tytul else "ra-leaf")

                            # 1. GRUPOWANIE PO MIESIĄCACH
                            for m_num in miesiace:
                                miesiac_nazwa = MIESIACE_MAP.get(m_num, "nieznany")
                                if miesiac_nazwa not in okresy:
                                    okresy[miesiac_nazwa] = {"typ": "Miesiąc", "zadania": {}}

                                if tytul not in okresy[miesiac_nazwa]["zadania"]:
                                    okresy[miesiac_nazwa]["zadania"][tytul] = {
                                        "tytul": tytul, "desc": desc, "icon": icon,
                                        "faza": faza, "pora": pora, "pogoda": pogoda,
                                        "rosliny": []
                                    }
                                if nazwa_rosliny not in okresy[miesiac_nazwa]["zadania"][tytul]["rosliny"]:
                                    okresy[miesiac_nazwa]["zadania"][tytul]["rosliny"].append(nazwa_rosliny)

                            # 2. GRUPOWANIE PO CZYNNOŚCIACH (np. wyszukiwanie słowa "Zbiór liści")
                            if tytul:
                                tytul_low = tytul.lower()
                                if tytul_low not in czynnosci:
                                    czynnosci[tytul_low] = {
                                        "tytul": tytul, "desc": desc, "icon": icon,
                                        "faza": faza, "pora": pora, "pogoda": pogoda,
                                        "rosliny": []
                                    }
                                if nazwa_rosliny not in czynnosci[tytul_low]["rosliny"]:
                                    czynnosci[tytul_low]["rosliny"].append(nazwa_rosliny)

                except Exception as e:
                    print(f"Błąd pliku {filename}: {e}")

    # Formatowanie dla JavaScript
    final_okresy = {}
    for okr, data in okresy.items():
        final_okresy[okr] = {
            "typ": data["typ"],
            "zadania": list(data["zadania"].values())
        }

    return {"okresy": final_okresy, "czynnosci": czynnosci}


# Dodaj to do funkcji build_calendar_from_jsons w  data_builder.py
def get_random_knowledge_pool(data_dir='data/plants'):
    pool = []
    for filename in os.listdir(data_dir):
        if filename.endswith('.json'):
            with open(os.path.join(data_dir, filename), 'r', encoding='utf-8') as f:
                data = json.load(f)
                plant_name = data.get('nazwa_pl', 'Roślina')

                # Dodajemy ciekawostki
                for c in data.get('ciekawostki', []):
                    pool.append({"typ": "Ciekawostka", "tresc": c, "roslina": plant_name})

                # Dodajemy protipy
                for p in data.get('protipy', []):
                    pool.append({"typ": "Protip", "tresc": p, "roslina": plant_name})
    return pool

def get_festival_knowledge():
    return FESTIVAL_KNOWLEDGE