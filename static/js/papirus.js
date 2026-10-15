// ==========================================
// PAPIRUS (strona glowna) – Kronika Siedziby
// Cala tresc jest w HTML: wpisy kroniki z data/changelog.json (i starsza historia z plikow roslin),
// kazdy z konkretna data i opisem tego, co Siedziba zebrala. Bez stanu "Siedziba pracuje", bez czasow
// "X temu" i bez zapytan do backendu.
// Ten skrypt tylko liczy klikniecia w rosliny z papirusu (statystyki, static/js – KwStats).
// ==========================================
function kwPapyrusInit() {
    const box = document.getElementById('kwPapyrus');
    if (!box) return;
    box.addEventListener('click', e => {
        const a = e.target.closest && e.target.closest('a[href^="/plant/"]');
        if (a && window.KwStats) KwStats.track('papyrus', decodeURIComponent(a.getAttribute('href').split('/')[2] || ''));
    });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', kwPapyrusInit);
else kwPapyrusInit();
