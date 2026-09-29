// ==========================================
// LOKALIZACJA I POGODA NA ŻYWO (wersja statyczna)
// Strona jest „zamrażana” (freeze), więc dane z Pythona pochodzą z chwili budowania.
// Ten skrypt odświeża je w przeglądarce odwiedzającego:
//  • lokalizacja – przybliżona z adresu IP (bez pytania o zgodę, bez GPS),
//  • pogoda – Open-Meteo (bez klucza API),
//  • faza księżyca, wibracja dnia, patron roku – liczone lokalnie z dzisiejszej daty.
// Dokładny GPS tylko po kliknięciu ikonki celownika (wtedy przeglądarka zapyta o zgodę).
// ==========================================
(function () {
    'use strict';

    const CACHE_KEY = 'kw_geo_weather_v1';
    const CACHE_TTL = 30 * 60 * 1000; // 30 minut

    function setField(name, value, title) {
        document.querySelectorAll(`[data-astro="${name}"]`).forEach(el => {
            el.textContent = value;
            if (title) el.title = title;
        });
    }

    function readCache() {
        try {
            const raw = localStorage.getItem(CACHE_KEY);
            if (!raw) return null;
            const data = JSON.parse(raw);
            return (Date.now() - data.time < CACHE_TTL) ? data : null;
        } catch (e) { return null; }
    }
    function writeCache(data) {
        try { localStorage.setItem(CACHE_KEY, JSON.stringify(Object.assign({ time: Date.now() }, data))); } catch (e) { /* brak pamięci */ }
    }

    async function fetchJson(url, ms) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), ms || 5000);
        try {
            const resp = await fetch(url, { signal: ctrl.signal });
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return await resp.json();
        } finally { clearTimeout(timer); }
    }

    // --- 1. Lokalizacja z adresu IP (kilka darmowych usług HTTPS jako zapas) ---
    async function locateByIp() {
        const providers = [
            async () => {
                const d = await fetchJson('https://get.geojs.io/v1/ip/geo.json');
                return { lat: +d.latitude, lon: +d.longitude, city: d.city || d.region || d.country };
            },
            async () => {
                const d = await fetchJson('https://ipwho.is/');
                if (d.success === false) throw new Error('ipwho.is');
                return { lat: +d.latitude, lon: +d.longitude, city: d.city || d.region || d.country };
            },
            async () => {
                const d = await fetchJson('https://ipapi.co/json/');
                return { lat: +d.latitude, lon: +d.longitude, city: d.city || d.region || d.country_name };
            }
        ];
        for (const p of providers) {
            try {
                const r = await p();
                if (isFinite(r.lat) && isFinite(r.lon)) return r;
            } catch (e) { /* następny dostawca */ }
        }
        return null;
    }

    // --- 2. Pogoda (Open-Meteo) ---
    const WEATHER_CODES = {
        0: ['☀️', 'bezchmurnie'], 1: ['🌤️', 'przeważnie pogodnie'], 2: ['⛅', 'częściowe zachmurzenie'], 3: ['☁️', 'pochmurno'],
        45: ['🌫️', 'mgła'], 48: ['🌫️', 'szadź'], 51: ['🌦️', 'lekka mżawka'], 53: ['🌦️', 'mżawka'], 55: ['🌧️', 'gęsta mżawka'],
        56: ['🌧️', 'marznąca mżawka'], 57: ['🌧️', 'marznąca mżawka'], 61: ['🌦️', 'słaby deszcz'], 63: ['🌧️', 'deszcz'], 65: ['🌧️', 'ulewa'],
        66: ['🌧️', 'marznący deszcz'], 67: ['🌧️', 'marznący deszcz'], 71: ['🌨️', 'słaby śnieg'], 73: ['🌨️', 'śnieg'], 75: ['❄️', 'śnieżyca'],
        77: ['🌨️', 'krupa śnieżna'], 80: ['🌦️', 'przelotny deszcz'], 81: ['🌧️', 'przelotne opady'], 82: ['⛈️', 'nawałnica'],
        85: ['🌨️', 'przelotny śnieg'], 86: ['❄️', 'przelotna śnieżyca'], 95: ['⛈️', 'burza'], 96: ['⛈️', 'burza z gradem'], 99: ['⛈️', 'burza z gradem']
    };

    async function getWeather(lat, lon) {
        const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat.toFixed(3)}&longitude=${lon.toFixed(3)}` +
            `&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&timezone=auto`;
        const d = await fetchJson(url, 6000);
        const c = d.current || {};
        const code = WEATHER_CODES[c.weather_code] || ['🌡️', ''];
        return {
            temp: `${Math.round(c.temperature_2m)}°C`,
            humidity: `${Math.round(c.relative_humidity_2m)}%`,
            sky: code[0],
            skyDesc: code[1],
            wind: isFinite(c.wind_speed_10m) ? `${Math.round(c.wind_speed_10m)} km/h` : ''
        };
    }

    // --- 3. Wartości liczone z daty (zgodne z astro_engine.py) ---
    function moonPhaseName(date) {
        const synodic = 29.530588853;
        const knownNewMoon = Date.UTC(2000, 0, 6, 18, 14);
        const age = (((date.getTime() - knownNewMoon) / 86400000) % synodic + synodic) % synodic;
        const illumination = (1 - Math.cos(2 * Math.PI * age / synodic)) / 2 * 100;
        if (illumination < 2) return 'Nów';
        if (illumination > 98) return 'Pełnia';
        return age < synodic / 2 ? 'Księżyc Przybywający' : 'Księżyc Ubywający';
    }
    function numerology(date) {
        const digits = `${date.getDate()}${date.getMonth() + 1}${date.getFullYear()}`;
        const sum = digits.split('').reduce((a, d) => a + parseInt(d, 10), 0);
        return sum % 9 || 9;
    }
    function japaneseYear(date) {
        const eto = ['Szczur', 'Bawoł', 'Tygrys', 'Zając', 'Smok', 'Wąż', 'Koń', 'Koza', 'Małpa', 'Kogut', 'Pies', 'Dzik'];
        return eto[(date.getFullYear() - 4) % 12];
    }

    function applyWeather(place, weather, source) {
        if (place && place.city) {
            setField('location', place.city, source === 'gps' ? 'Lokalizacja z GPS' : 'Przybliżona lokalizacja na podstawie adresu IP. Kliknij celownik, aby użyć GPS.');
        }
        if (weather) {
            setField('temp', weather.temp, weather.skyDesc ? `${weather.skyDesc}${weather.wind ? ', wiatr ' + weather.wind : ''}` : '');
            setField('humidity', weather.humidity);
            setField('sky', weather.sky, weather.skyDesc);
        }
    }

    async function refresh() {
        const today = new Date();
        setField('moon', moonPhaseName(today));
        setField('numerology', String(numerology(today)));
        setField('japanese', japaneseYear(today));

        const cached = readCache();
        if (cached) { applyWeather(cached.place, cached.weather, cached.source); return; }

        const place = await locateByIp();
        if (!place) return; // zostają wartości z chwili budowania strony
        let weather = null;
        try { weather = await getWeather(place.lat, place.lon); } catch (e) { /* brak pogody */ }
        applyWeather(place, weather, 'ip');
        writeCache({ place, weather, source: 'ip' });
    }

    // --- 4. Dokładny GPS – tylko na życzenie (kliknięcie celownika) ---
    window.forceGPS = function () {
        if (!('geolocation' in navigator)) { alert('Twoja przeglądarka nie obsługuje GPS.'); return; }
        setField('location', 'Szukam…');
        navigator.geolocation.getCurrentPosition(async pos => {
            const lat = pos.coords.latitude, lon = pos.coords.longitude;
            let city = 'Twoja okolica';
            try {
                const d = await fetchJson(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=10&accept-language=pl`, 6000);
                if (d.address) city = d.address.city || d.address.town || d.address.village || d.address.county || city;
            } catch (e) { /* zostaje "Twoja okolica" */ }
            let weather = null;
            try { weather = await getWeather(lat, lon); } catch (e) { /* brak pogody */ }
            const place = { lat, lon, city };
            applyWeather(place, weather, 'gps');
            writeCache({ place, weather, source: 'gps' });
        }, () => {
            setField('location', 'Brak zgody na GPS');
            try { localStorage.removeItem(CACHE_KEY); } catch (e) { /* ignore */ }
            setTimeout(refresh, 1500);
        }, { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 });
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refresh);
    else refresh();
})();
