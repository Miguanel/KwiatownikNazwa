import ephem
import datetime
import requests


def get_moon_phase_name(date):
    moon = ephem.Moon(date)
    sun = ephem.Sun(date)
    elongation = ephem.separation(moon, sun)

    moon_yesterday = ephem.Moon(date - 1)
    is_waxing = moon.phase > moon_yesterday.phase

    if moon.phase < 2.0:
        return "Nów"
    elif moon.phase > 98.0:
        return "Pełnia"
    elif is_waxing:
        return "Księżyc Przybywający"
    else:
        return "Księżyc Ubywający"


def get_weather(lat='49.95', lon='18.38'):
    try:
        url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true&hourly=relativehumidity_2m"
        resp = requests.get(url, timeout=3).json()
        temp = resp['current_weather']['temperature']

        current_hour = datetime.datetime.utcnow().replace(minute=0, second=0, microsecond=0).isoformat() + "Z"
        humidity = 50
        if 'hourly' in resp and 'time' in resp['hourly']:
            try:
                idx = resp['hourly']['time'].index(resp['current_weather']['time'])
                humidity = resp['hourly']['relativehumidity_2m'][idx]
            except ValueError:
                humidity = resp['hourly']['relativehumidity_2m'][0]

        return {"temp": f"{temp}°C", "humidity": f"{humidity}%"}
    except Exception:
        return {"temp": "?°C", "humidity": "?%"}


def get_pagan_festival_info(date):
    m, d = date.month, date.day

    festivals = {
        "Yule": {
            "name": "Szczodre Gody (Yule)",
            "desc": "Zimowe Przesilenie. Zwycięstwo światła nad ciemnością i odrodzenie Słońca.",
            "symbol": "Snop zboża, jemioła",
            "action": "Czas świętowania w domu, wróżb i dzielenia się chlebem."
        },
        "Imbolc": {
            "name": "Gromnica (Imbolc)",
            "desc": "Pierwsze tchnienie wiosny. Czas oczyszczenia i budzenia się sił życiowych w ziemi.",
            "symbol": "Świeca (Gromnica), białe kwiaty",
            "action": "Oczyszczanie narzędzi ogrodniczych, błogosławienie ognia."
        },
        "Ostara": {
            "name": "Jare Gody (Ostara)",
            "desc": "Równonoc Wiosenna. Pełna równowaga dnia i nocy. Czas siania i płodności.",
            "symbol": "Pisanki, zające, bazie",
            "action": "Wysiewanie pierwszych ziół, topienie Marzanny (pożegnanie zimy)."
        },
        "Beltane": {
            "name": "Beltane / Zielone Świątki",
            "desc": "Święto ognia i miłości. Ziemia jest w pełnym rozkwicie i łączy się ze słońcem.",
            "symbol": "Majowe drzewko, ogniska",
            "action": "Zbieranie porannej rosy dla urody, dekorowanie domów gałązkami."
        },
        "Litha": {
            "name": "Noc Kupały (Litha)",
            "desc": "Letnie Przesilenie. Najdłuższy dzień roku. Czas ognia, wody i magicznych ziół.",
            "symbol": "Wianki, paproć, ogień",
            "action": "Zbiór ziół o największej mocy (np. dziurawiec), puszczanie wianków."
        },
        "Lughnasadh": {
            "name": "Święto Plonów (Lughnasadh)",
            "desc": "Pierwsze żniwa. Czas wdzięczności za dary ziemi i początek jesiennych zbiorów.",
            "symbol": "Chleb, kłosy zbóż",
            "action": "Pieczenie chleba z nowego ziarna, zbiór wczesnych owoców i jagód."
        },
        "Mabon": {
            "name": "Dożynki (Mabon)",
            "desc": "Równonoc Jesienna. Czas bilansu, dziękczynienia i przygotowania do zimy.",
            "symbol": "Jabłka, jarzębina, róg obfitości",
            "action": "Zbiór korzeni, robienie zapasów i win, dziękowanie za plony."
        },
        "Samhain": {
            "name": "Dziady (Samhain)",
            "desc": "Nowy Rok czarownic i zielarzy. Granica między światami jest najcieńsza.",
            "symbol": "Dynie, ogniska, korzenie",
            "action": "Wspominanie przodków, palenie świec w oknach, zbiór ostatnich korzeni."
        }
    }

    if (m == 12 and d >= 21) or (m == 1):
        return festivals["Yule"]
    elif m == 2 or (m == 3 and d < 20):
        return festivals["Imbolc"]
    elif m == 3 and d >= 20 or m == 4:
        return festivals["Ostara"]
    elif m == 5 or (m == 6 and d < 20):
        return festivals["Beltane"]
    elif m == 6 and d >= 20 or m == 7:
        return festivals["Litha"]
    elif m == 8 or (m == 9 and d < 22):
        return festivals["Lughnasadh"]
    elif m == 9 and d >= 22 or m == 10 and d < 31:
        return festivals["Mabon"]
    elif m == 10 and d >= 31 or m == 11:
        return festivals["Samhain"]

    return {"name": "Zwyczajny Czas", "desc": "Czas wzrostu i obserwacji natury.", "symbol": "Liść",
            "action": "Pielęgnacja ogrodu."}

def get_astrological_data(lat='49.95', lon='18.38'):
    now = datetime.datetime.utcnow()
    observer = ephem.Observer()
    observer.lat, observer.lon = lat, lon
    observer.date = now

    num_sum = sum(int(digit) for digit in f"{now.day}{now.month}{now.year}")
    vibration = num_sum % 9 or 9

    mars = ephem.Mars(observer)
    elements = ["Ziemia", "Powietrze", "Ogień", "Woda", "Eter"]
    current_element = elements[int(float(mars.ra) % 5)]

    eto = ["Szczur", "Bawoł", "Tygrys", "Zając", "Smok", "Wąż", "Koń", "Koza", "Małpa", "Kogut", "Pies", "Dzik"]
    japanese_year = eto[(now.year - 4) % 12]

    weather = get_weather(lat, lon)
    phase_name = get_moon_phase_name(observer.date)
    # pagan_fest = get_pagan_festival(now)

    pagan_info = get_pagan_festival_info(now)

    return {
        "location": "Lokalizacja",
        "temp": weather["temp"],
        "humidity": weather["humidity"],
        "phase_name": phase_name,
        "numerology": vibration,
        "japanese": japanese_year,
        "element": current_element,
        # Zmieniamy to:
        "festival": pagan_info["name"],
        "festival_desc": pagan_info["desc"],
        "festival_symbol": pagan_info["symbol"],
        "festival_action": pagan_info["action"]
    }