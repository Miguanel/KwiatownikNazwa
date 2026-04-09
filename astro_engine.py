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


def get_pagan_festival(date):
    """Zwraca dawne święta słowiańskie / celtyckie (Koło Roku)"""
    m, d = date.month, date.day
    if (m == 12 and d >= 21) or (m == 1 and d <= 31):
        return "Szczodre Gody (Yule)"
    elif m == 2 or (m == 3 and d < 20):
        return "Gromnica (Imbolc)"
    elif m == 3 and d >= 20 or m == 4:
        return "Jare Gody (Ostara)"
    elif m == 5 or (m == 6 and d < 20):
        return "Beltane / Zielone Świątki"
    elif m == 6 and d >= 20 or m == 7:
        return "Noc Kupały (Litha)"
    elif m == 8 or (m == 9 and d < 22):
        return "Święto Plonów (Lughnasadh)"
    elif m == 9 and d >= 22 or m == 10 and d < 31:
        return "Dożynki (Mabon)"
    elif m == 10 and d >= 31 or m == 11:
        return "Dziady (Samhain)"
    return "Zwyczajny Czas"


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
    pagan_fest = get_pagan_festival(now)

    return {
        "location": "Czyżowice",
        "temp": weather["temp"],
        "humidity": weather["humidity"],
        "phase_name": phase_name,
        "numerology": vibration,
        "japanese": japanese_year,
        "element": current_element,
        "festival": pagan_fest
    }