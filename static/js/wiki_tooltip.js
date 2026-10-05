// ==========================================
// DYMKI Z WIKIPEDII (KwWiki)
// Najechanie kursorem albo kliknięcie (dotknięcie na telefonie) w składnik lub pojęcie
// pokazuje dymek ze zwięzłym opisem z polskiej Wikipedii + link do artykułu.
//
// Jak oznaczać treść:
//   data-wiki-scan            – kontener: znane pojęcia (słownik niżej) w tekście stają się dymkami;
//                               treść dodawana później (np. modal przepisu) jest skanowana automatycznie
//   data-wiki-ingredient      – „chip” składnika, np. „Glikozydy irydoidowe (aukubina, katalpol) - działanie…”:
//                               główna nazwa i związki w nawiasie dostają osobne dymki
//   data-wiki-term="Hasło"    – pojedynczy element = jedno hasło (gdy brak wartości – tekst elementu)
//   data-wiki-skip            – fragment pomijany przy skanowaniu
// Działa w wersji statycznej (wszystko w przeglądarce, API Wikipedii z CORS, bez klucza).
// ==========================================
(function () {
    'use strict';

    const WIKI = 'https://pl.wikipedia.org';
    const WIKIDATA = 'https://www.wikidata.org/w/api.php';
    // Gdy polska Wikipedia nie ma artykułu – kolejne języki (czeski i ukraiński są blisko polskiego)
    const OTHER_LANGS = ['en', 'de', 'fr', 'cs', 'uk', 'ru', 'es', 'it', 'la'];
    const LANG_NAMES = { pl: 'polskiej', en: 'angielskiej', de: 'niemieckiej', fr: 'francuskiej', cs: 'czeskiej',
        uk: 'ukraińskiej', ru: 'rosyjskiej', es: 'hiszpańskiej', it: 'włoskiej', la: 'łacińskiej' };
    const wikiHost = lang => `https://${lang}.wikipedia.org`;

    // ------------------------------------------
    // SŁOWNIK POJĘĆ: [wzorzec (małe litery, bez końcówki), hasło w Wikipedii]
    // Wzorzec dopasowuje początek słowa; dowolna polska końcówka jest dozwolona.
    // Jeśli hasła nie ma, skrypt sam przeszuka Wikipedię.
    // ------------------------------------------
    const GLOSSARY = [
        // grupy związków
        ['flawonoid', 'Flawonoidy'], ['garbnik', 'Garbniki'], ['tanin', 'Taniny'],
        ['olej(?:ek|ki|ków|kiem|kami|kach|ku|kom)\\s+eteryczn', 'Olejki eteryczne'],
        ['olej(?:ek|ki|ków|kami)\\s+lotn', 'Olejki eteryczne'],
        ['kwas(?:y|ów|ami|om)?\\s+organiczn', 'Kwasy organiczne|Kwasy karboksylowe'],
        ['kwas(?:y|ów|ami|om)?\\s+fenolow', 'Kwasy fenolowe'],
        ['kwas(?:y|ów|ami|om)?\\s+polifenolow', 'Polifenole'],
        ['kwas(?:y|ów|ami|om)?\\s+tłuszczow', 'Kwasy tłuszczowe'],
        ['kwas(?:y|ów|ami|om)?\\s+żywiczn', 'Żywica'],
        ['polifenol', 'Polifenole'], ['fenolokwas', 'Kwasy fenolowe'],
        ['sol(?:e|i|ami)\\s+mineraln', 'Składniki mineralne|Sole mineralne|Makroelementy|Pierwiastki biogenne'], ['składnik(?:i|ów|ami)\\s+mineraln', 'Składniki mineralne|Sole mineralne|Makroelementy|Pierwiastki biogenne'], ['minerał(?:y|ów|ami)(?![a-ząćęłńóśźż])', 'Składniki mineralne|Sole mineralne|Makroelementy'],
        ['śluz(?:y|ów|ami|em|u)?(?![a-ząćęłńóśźż])', 'Śluzy roślinne|Śluz roślinny|Śluzy'], ['związk(?:i|ów)\\s+śluzow', 'Śluzy roślinne|Śluz roślinny|Śluzy'],
        ['pektyn', 'Pektyny'], ['saponin', 'Saponiny'], ['gorycz(?:e|y|ami|ach)(?![a-ząćęłńóśźż])', 'Substancje gorzkie|Goryczki|Gorycze'],
        ['związk(?:i|ów)\\s+gorzk', 'Substancje gorzkie|Goryczki|Gorycze'], ['fitosterol', 'Fitosterole'], ['steryn', 'Sterole'],
        ['antocyjan', 'Antocyjany'], ['antocyjanozyd', 'Antocyjany'], ['irydoid', 'Irydoidy'],
        ['kumaryna(?![a-ząćęłńóśźż])', 'Kumaryna'], ['furanokumaryn', 'Furanokumaryny'], ['kumaryn', 'Kumaryny'], ['żywic', 'Żywica'],
        ['skrobi', 'Skrobia'], ['inulin', 'Inulina'], ['karotenoid', 'Karotenoidy'], ['beta-karoten', 'Beta-karoten'], ['karoten', 'Beta-karoten'],
        ['krzemionk', 'Krzemionka'], ['kwas(?:u)?\\s+krzemow', 'Kwas krzemowy'],
        ['fitoncyd', 'Fitoncydy'], ['fitoestrogen', 'Fitoestrogeny'], ['fitohormon', 'Hormony roślinne'],
        ['glikozyd(?:y|ów|ami)?\\s+irydoidow', 'Irydoidy'], ['glikozyd(?:y|ów|ami)?\\s+flawonoidow', 'Flawonoidy'],
        ['glikozyd(?:y|ów|ami)?\\s+kumarynow', 'Kumaryny'], ['glikozyd(?:y|ów|ami)?\\s+antrachinonow', 'Antrachinony'], ['antrachinon', 'Antrachinony'],
        ['glikozyd(?:y|ów|ami)?\\s+cyjanogenn', 'Glikozydy cyjanogenne'], ['glikozyd(?:y|ów|ami)?\\s+nasercow', 'Glikozydy nasercowe'],
        ['glikozyd', 'Glikozydy'], ['aminokwas', 'Aminokwasy'], ['białk(?:a|o|ami|ach)(?![a-ząćęłńóśźż])', 'Białka'],
        ['enzym', 'Enzymy'], ['triterpen', 'Triterpeny'], ['trójterpen', 'Triterpeny'], ['terpen', 'Terpeny'],
        ['lignan', 'Lignany'], ['poliacetylen', 'Poliacetyleny'], ['alkaloid', 'Alkaloidy'], ['katechin', 'Katechiny'],
        ['procyjanidyn', 'Proantocyjanidyny'], ['proantocyjanidyn', 'Proantocyjanidyny'], ['naftochinon', 'Naftochinony'],
        ['salicylan', 'Salicylany'], ['ftalid', 'Ftalidy'], ['walepotriat', 'Walepotriaty'], ['waleropotriat', 'Walepotriaty'],
        ['azulen', 'Azulen'], ['chamazulen', 'Chamazulen'], ['chlorofil', 'Chlorofil'], ['błonnik', 'Błonnik pokarmowy'],
        ['węglowodan', 'Węglowodany'], ['tokoferol', 'Tokoferole'], ['luteina', 'Luteina'], ['luteiny', 'Luteina'],
        ['likopen', 'Likopen'], ['prebiotyk', 'Prebiotyk'], ['probiotyk', 'Probiotyk'],
        ['przeciwutleniacz', 'Przeciwutleniacze'], ['antyoksydant', 'Przeciwutleniacze'], ['wolnych rodników', 'Wolne rodniki'],
        ['adaptogen', 'Adaptogeny'],
        // pojedyncze związki
        ['kwercetyn', 'Kwercetyna'], ['rutyn', 'Rutyna'], ['rutozyd', 'Rutyna'], ['hiperozyd', 'Hiperozyd'],
        ['kemferol', 'Kemferol'], ['apigenin', 'Apigenina'], ['luteolin', 'Luteolina'], ['mirycetyn', 'Mirycetyna'],
        ['aukubin', 'Aukubina'], ['katalpol', 'Katalpol'], ['arbutyn', 'Arbutyna'], ['hydrochinon', 'Hydrochinon'],
        ['salicyn', 'Salicyna'], ['kwas(?:u|em)?\\s+salicylow', 'Kwas salicylowy'], ['kwas(?:u|em)?\\s+askorbinow', 'Witamina C'],
        ['kwas(?:u|em)?\\s+chlorogenow', 'Kwas chlorogenowy'], ['kwas(?:u|em)?\\s+kawow', 'Kwas kawowy'],
        ['kwas(?:u|em)?\\s+rozmarynow', 'Kwas rozmarynowy'], ['kwas(?:u|em)?\\s+galusow', 'Kwas galusowy'],
        ['kwas(?:u|em)?\\s+elagow', 'Kwas elagowy'], ['kwas(?:u|em)?\\s+jabłkow', 'Kwas jabłkowy'],
        ['kwas(?:u|em)?\\s+cytrynow', 'Kwas cytrynowy'], ['kwas(?:u|em)?\\s+winow', 'Kwas winowy'],
        ['kwas(?:u|em)?\\s+szczawiow', 'Kwas szczawiowy'], ['szczawian', 'Szczawiany'], ['kwas(?:u|em)?\\s+mrówkow', 'Kwas mrówkowy'],
        ['kwas(?:u|em)?\\s+walerianow', 'Kwas walerianowy'], ['kwas(?:u|em)?\\s+betulinow', 'Kwas betulinowy'],
        ['kwas(?:u|em)?\\s+abietynow', 'Kwas abietynowy'], ['kwas(?:u|em)?\\s+linolow', 'Kwas linolowy'],
        ['kwas(?:u|em)?\\s+linolenow', 'Kwas α-linolenowy'], ['kwas(?:u|em)?\\s+gamma-linolenow', 'Kwas γ-linolenowy'],
        ['kwas(?:u|em)?\\s+foliow', 'Kwas foliowy'], ['kwas(?:y|ów)?\\s+omega', 'Kwasy tłuszczowe omega-3'],
        ['betulin', 'Betulina'], ['lupeol', 'Lupeol'], ['limonen', 'Limonen'], ['pinen', 'Pinen'], ['alfa-pinen', 'Pinen'],
        ['borneol', 'Borneol'], ['kamfor', 'Kamfora'], ['cyneol', 'Eukaliptol'], ['eukaliptol', 'Eukaliptol'],
        ['tujon', 'Tujon'], ['mentol', 'Mentol'], ['tymol', 'Tymol'], ['karwakrol', 'Karwakrol'], ['linalol', 'Linalol'],
        ['geraniol', 'Geraniol'], ['eugenol', 'Eugenol'], ['anetol', 'Anetol'], ['mircen', 'Mircen'], ['humulen', 'Humulen'],
        ['kariofilen', 'Kariofilen'], ['bisabolol', 'Bisabolol'], ['farnezol', 'Farnezol'], ['farnesol', 'Farnezol'],
        ['amigdalin', 'Amygdalina'], ['amygdalin', 'Amygdalina'], ['allicyn', 'Allicyna'], ['alliin', 'Alliina'], ['ajoen', 'Ajoen'],
        ['adenozyn', 'Adenozyna'], ['hiperycyn', 'Hiperycyna'], ['hiperforyn', 'Hiperforyna'], ['chelidonin', 'Chelidonina'],
        ['sangwinaryn', 'Sangwinaryna'], ['chelerytryn', 'Chelerytryna'], ['berberyn', 'Berberyna'], ['escyn', 'Escyna'],
        ['eskulin', 'Eskulina'], ['umbeliferon', 'Umbeliferon'], ['skopolin', 'Skopoletyna'],
        ['sambunigryn', 'Sambunigryna'], ['solanin', 'Solanina'], ['kofein', 'Kofeina'], ['teobromin', 'Teobromina'],
        ['nikotyn', 'Nikotyna'], ['atropin', 'Atropina'], ['skopolamin', 'Skopolamina'], ['koniin', 'Koniina'],
        ['glicyryzyn', 'Glicyryzyna'], ['kapsaicyn', 'Kapsaicyna'], ['kurkumin', 'Kurkumina'], ['gingerol', 'Gingerol'],
        ['absyntyn', 'Absyntyna'], ['taraksacyn', 'Taraksacyna'], ['taraksasterol', 'Taraksasterol'], ['laktukaryum', 'Laktukarium'],
        ['sorbitol', 'Sorbitol'], ['mannitol', 'Mannitol'], ['fruktoz', 'Fruktoza'], ['glukoz', 'Glukoza'], ['sacharoz', 'Sacharoza'],
        ['lecytyn', 'Lecytyny'], ['celuloz', 'Celuloza'], ['lignin', 'Lignina'], ['wosk', 'Wosk'], ['kolagen', 'Kolagen'],
        ['histamin', 'Histamina'], ['acetylocholin', 'Acetylocholina'], ['serotonin', 'Serotonina'], ['melatonin', 'Melatonina'],
        // witaminy (litera dopisywana automatycznie)
        ['witamin(?:y|ami|om)?\\s+z\\s+grupy\\s+b(?![a-ząćęłńóśźż0-9])', 'Witaminy B'],
        ['witamin(?:a|y|ą|ie|ę|ami|om)?\\s+(?:z\\s+grupy\\s+)?([a-k])(\\d{0,2})(?![a-ząćęłńóśźż0-9])', 'Witamina $1$2'],
        ['prowitamin', 'Prowitamina'],
        // pierwiastki (pełne formy, żeby nie łapać np. „borówka”)
        ['(?:potas|potasu|potasem)(?![a-ząćęłńóśźż])', 'Potas'], ['(?:magnez|magnezu|magnezem)(?![a-ząćęłńóśźż])', 'Magnez'],
        ['(?:wapń|wapnia|wapniem)(?![a-ząćęłńóśźż])', 'Wapń'], ['(?:żelazo|żelaza|żelazem)(?![a-ząćęłńóśźż])', 'Żelazo'],
        ['(?:cynk|cynku|cynkiem)(?![a-ząćęłńóśźż])', 'Cynk'], ['(?:mangan|manganu|manganem)(?![a-ząćęłńóśźż])', 'Mangan'],
        ['(?:selen|selenu|selenem)(?![a-ząćęłńóśźż])', 'Selen'], ['(?:krzem|krzemu|krzemem)(?![a-ząćęłńóśźż])', 'Krzem'],
        ['(?:boru|borem)(?![a-ząćęłńóśźż])', 'Bor'], ['(?:jod|jodu|jodem)(?![a-ząćęłńóśźż])', 'Jod'],
        ['(?:fosfor|fosforu|fosforem)(?![a-ząćęłńóśźż])', 'Fosfor'], ['(?:sód|sodu|sodem)(?![a-ząćęłńóśźż])', 'Sód'],
        ['(?:miedź|miedzi)(?![a-ząćęłńóśźż])', 'Miedź'], ['(?:litu|litem)(?![a-ząćęłńóśźż])', 'Lit (pierwiastek)'],
        ['(?:siark[aię]|siarką)(?![a-ząćęłńóśźż])', 'Siarka'], ['związk(?:i|ów)\\s+siark', 'Związki siarkoorganiczne'],
        // działanie i fizjologia
        ['wykrztuśn', 'Leki wykrztuśne|Środki wykrztuśne|Wykrztuśne'], ['moczopędn', 'Leki moczopędne|Diuretyki'], ['diuretyk', 'Leki moczopędne|Diuretyki'],
        ['żółciopędn', 'Leki żółciopędne'], ['napotn', 'Środki napotne'], ['rozkurczow', 'Leki spazmolityczne'],
        ['spazmolityczn', 'Leki spazmolityczne'], ['ściągając', 'Środki ściągające'], ['wiatropędn', 'Środki wiatropędne'],
        ['przeczyszczając', 'Środki przeczyszczające'], ['przeciwskurcz', 'Leki spazmolityczne'], ['powlekając', 'Środki powlekające'],
        ['osłaniając', 'Środki powlekające'], ['immunostymul', 'Immunostymulacja'], ['antyseptyczn', 'Antyseptyka'],
        ['bakteriobójcz', 'Środki bakteriobójcze'], ['przeciwgrzybicz', 'Leki przeciwgrzybicze'], ['przeciwwirusow', 'Leki przeciwwirusowe'],
        ['fotouczula', 'Fotouczulenie'], ['fototoksyczn', 'Fototoksyczność'], ['hepatotoksyczn', 'Hepatotoksyczność'],
        ['przeciwzakrzepow', 'Leki przeciwzakrzepowe'], ['antykoagulant', 'Leki przeciwzakrzepowe'], ['estrogen', 'Estrogeny'],
        ['mikrobiot', 'Mikrobiota'], ['metabolizm', 'Metabolizm'], ['cytochrom', 'Cytochrom P450'],
        // przetwory i tradycje
        ['macerat', 'Maceracja'], ['maceracj', 'Maceracja'], ['nalew(?:ka|ki|kę|ką|ek|kach)(?![a-ząćęłńóśźż])', 'Nalewka'],
        ['odwar', 'Odwar'], ['napar', 'Napar'], ['intrakt', 'Intrakt'], ['tynktur', 'Tynktura'], ['kataplazm', 'Kataplazm'],
        ['okład', 'Okład'], ['inhalacj', 'Inhalacja'], ['destylacj', 'Destylacja'], ['hydrolat', 'Hydrolat'],
        ['oksymel', 'Oksymel'], ['spagiri', 'Spagiria'], ['spagiryk', 'Spagiria'], ['spageryczn', 'Spagiria'],
        ['ajurwed', 'Ajurweda'], ['doktryn(?:a|y|ie|ę|ą)\\s+sygnatur', 'Doktryna sygnatur'],
        ['humor(?:y|ów|ami|alna|alnej)(?![a-ząćęłńóśźż])', 'Humoryzm'], ['wu\\s+xing', 'Wu xing'], ['kampo', 'Kampō'],
        ['tradycyjn(?:a|ej|ą)\\s+medycyn(?:a|y|ie|ę|ą)\\s+chińsk', 'Tradycyjna medycyna chińska'], ['permakultur', 'Permakultura'],
        ['fitoterapi', 'Fitoterapia'], ['homeopat', 'Homeopatia']
    ];

    const LETTER = 'a-ząćęłńóśźż';
    const ENTRIES = GLOSSARY.map(([pat, title]) => {
        const explicitEnd = pat.includes('(?!');
        const src = `(?<![${LETTER}0-9-])(?:${pat})${explicitEnd ? '' : `[${LETTER}-]*`}`;
        return { re: new RegExp(src, 'giu'), title };
    });

    function findTerms(text) {
        const lower = text.toLowerCase();
        const found = [];
        ENTRIES.forEach(e => {
            e.re.lastIndex = 0;
            let m;
            while ((m = e.re.exec(lower))) {
                const title = e.title.replace(/\$(\d)/g, (_, i) => (m[+i] || '').toUpperCase());
                found.push({ start: m.index, end: m.index + m[0].length, title });
                if (m[0].length === 0) e.re.lastIndex++;
            }
        });
        // najpierw wcześniejsze, przy remisie dłuższe; bez nakładania się
        found.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
        const out = [];
        let lastEnd = -1;
        found.forEach(f => { if (f.start >= lastEnd) { out.push(f); lastEnd = f.end; } });
        return out;
    }

    // ------------------------------------------
    // OZNACZANIE TEKSTU
    // ------------------------------------------
    const SKIP = 'a,button,summary,script,style,textarea,input,select,option,code,pre,sup,h1,.kw-wiki,.kw-wiki-tip,[data-wiki-skip]';
    const BLOCK = 'li,p,td,th,dd,dt,blockquote,.chem-link,.ritual-text,.subtab-content,.tab-content,div';
    const usedInBlock = new WeakMap();

    function makeTerm(text, query) {
        const span = document.createElement('span');
        span.className = 'kw-wiki';
        span.tabIndex = 0;
        span.setAttribute('role', 'button');
        span.setAttribute('aria-haspopup', 'dialog');
        span.dataset.wiki = query;
        span.textContent = text;
        return span;
    }

    function wrapTextNode(node, onlyOncePerBlock) {
        const text = node.nodeValue;
        if (!text || text.trim().length < 3) return;
        let matches = findTerms(text);
        if (!matches.length) return;
        if (onlyOncePerBlock) {
            const block = node.parentElement.closest(BLOCK) || node.parentElement;
            let used = usedInBlock.get(block);
            if (!used) { used = new Set(); usedInBlock.set(block, used); }
            matches = matches.filter(m => { if (used.has(m.title)) return false; used.add(m.title); return true; });
            if (!matches.length) return;
        }
        const frag = document.createDocumentFragment();
        let pos = 0;
        matches.forEach(m => {
            if (m.start > pos) frag.appendChild(document.createTextNode(text.slice(pos, m.start)));
            frag.appendChild(makeTerm(text.slice(m.start, m.end), m.title));
            pos = m.end;
        });
        if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
        node.parentNode.replaceChild(frag, node);
    }

    function scanText(root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(n) {
                const p = n.parentElement;
                if (!p || p.closest(SKIP)) return NodeFilter.FILTER_REJECT;
                return /[a-ząćęłńóśźż]{3}/i.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
            }
        });
        const nodes = [];
        while (walker.nextNode()) nodes.push(walker.currentNode);
        nodes.forEach(n => wrapTextNode(n, true));
    }

    // --- chip składnika: „Główna nazwa (związek, związek) - opis” ---
    const NOTE_WORDS = /^(do|ok|około|nawet|bardzo|m\.?\s?in|głównie|w|z|wysok|bogat|bogactwo|działa|działanie|naturaln|nadaj|która|który|które|więcej|mniej|porównywalnie|silne|ogromne|zwłaszcza|szczególnie)\b/i;
    const CHEM_SUFFIX = /(yna|ina|ol|en|yd|ozyd|on|ony|an|any|oid|oidy|yny|iny|ena|eina|aza|azy|ąg|ny)$/i;

    function appendTextWithTerms(parent, text) {
        const holder = document.createElement('span');
        holder.textContent = text;
        parent.appendChild(holder);
        scanText(holder);
        while (holder.firstChild) parent.insertBefore(holder.firstChild, holder);
        holder.remove();
    }

    function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

    function buildIngredient(el) {
        if (el.dataset.wikiDone) return;
        el.dataset.wikiDone = '1';
        const raw = el.textContent.replace(/\s+/g, ' ').trim();
        if (!raw) return;
        const icon = el.querySelector('i');
        let main = raw, inner = '', rest = '';
        const sep = raw.search(/\s[-–—]\s|:\s/);
        const paren = raw.indexOf('(');
        if (paren > 0 && (sep < 0 || paren < sep)) {
            main = raw.slice(0, paren).trim();
            const close = raw.indexOf(')', paren);
            inner = close > 0 ? raw.slice(paren + 1, close) : raw.slice(paren + 1);
            rest = close > 0 ? raw.slice(close + 1) : '';
        } else if (sep > 0) {
            main = raw.slice(0, sep).trim();
            rest = raw.slice(sep);
        }

        el.textContent = '';
        // główna nazwa: jeśli słownik coś w niej rozpoznaje (np. „Witamina C i K”) – po pojęciach, inaczej całość
        if (findTerms(main).length) appendTextWithTerms(el, main);
        else el.appendChild(makeTerm(main, capitalize(main)));

        if (inner) {
            el.appendChild(document.createTextNode(' ('));
            const isAcid = /^kwas/i.test(main);
            inner.split(/(,\s*|;\s*|\s+i\s+|\s+oraz\s+)/).forEach(part => {
                const t = part.trim();
                if (!t || /^[,;]$/.test(t) || /^(i|oraz)$/.test(t)) { el.appendChild(document.createTextNode(part)); return; }
                if (findTerms(t).length) { appendTextWithTerms(el, part); return; }
                const word = t.replace(/\s*-\s.*$/, '');
                if (isAcid && /^[a-ząćęłńóśźż-]+owy$/i.test(word)) {
                    el.appendChild(makeTerm(part, 'Kwas ' + word.toLowerCase()));
                } else if (!/\d%|\d/.test(word) && !NOTE_WORDS.test(word) && /^[a-ząćęłńóśźżα-ω-]+(?:-\d+-[a-z]+)?$/i.test(word) && CHEM_SUFFIX.test(word) && word.length > 3) {
                    const extra = t.slice(word.length);
                    el.appendChild(makeTerm(word, capitalize(word.toLowerCase())));
                    if (extra) el.appendChild(document.createTextNode(extra + (part.endsWith(' ') ? ' ' : '')));
                } else {
                    el.appendChild(document.createTextNode(part));
                }
            });
            el.appendChild(document.createTextNode(')'));
        }
        if (rest && rest.trim()) appendTextWithTerms(el, rest);
        if (icon) { el.appendChild(document.createTextNode(' ')); el.appendChild(icon); }
    }

    function scan(root) {
        root = root || document;
        root.querySelectorAll('[data-wiki-ingredient]').forEach(buildIngredient);
        root.querySelectorAll('[data-wiki-term]').forEach(el => {
            if (el.dataset.wikiDone) return;
            el.dataset.wikiDone = '1';
            const q = el.getAttribute('data-wiki-term') || el.textContent.trim();
            if (!q) return;
            el.classList.add('kw-wiki');
            el.dataset.wiki = q;
            if (!/^(a|button)$/i.test(el.tagName)) { el.tabIndex = 0; el.setAttribute('role', 'button'); }
        });
        const roots = root.matches && root.matches('[data-wiki-scan]') ? [root] : Array.from(root.querySelectorAll('[data-wiki-scan]'));
        roots.forEach(scanText);
    }

    // ------------------------------------------
    // POBIERANIE OPISU Z WIKIPEDII (z pamięcią podręczną)
    // ------------------------------------------
    const memCache = new Map();
    const CACHE_PREFIX = 'kw_wiki_v3:';   // v2: odrzucanie niepasujących wyników wyszukiwania

    function cacheGet(q) {
        if (memCache.has(q)) return memCache.get(q);
        try { const v = sessionStorage.getItem(CACHE_PREFIX + q); if (v) { const d = JSON.parse(v); memCache.set(q, d); return d; } } catch (e) { /* brak pamięci */ }
        return undefined;
    }
    function cacheSet(q, d) {
        memCache.set(q, d);
        try { sessionStorage.setItem(CACHE_PREFIX + q, JSON.stringify(d)); } catch (e) { /* brak pamięci */ }
    }

    async function getJson(url) {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 7000);
        try {
            const r = await fetch(url, { signal: ctrl.signal, headers: { 'Accept': 'application/json' } });
            if (r.status === 404) return null;
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return await r.json();
        } finally { clearTimeout(t); }
    }

    async function summary(title, lang) {
        lang = lang || 'pl';
        const host = wikiHost(lang);
        const d = await getJson(`${host}/api/rest_v1/page/summary/${encodeURIComponent(title.replace(/ /g, '_'))}`);
        if (!d || !d.extract) return null;
        return {
            title: d.title,
            extract: d.extract,
            type: d.type,
            lang,
            thumb: d.thumbnail && /^https:\/\//.test(d.thumbnail.source) ? d.thumbnail.source : '',
            url: (d.content_urls && d.content_urls.desktop && d.content_urls.desktop.page) || `${host}/wiki/${encodeURIComponent(d.title.replace(/ /g, '_'))}`
        };
    }

    // --- Wikidata: hasło po polsku -> ten sam obiekt w Wikipediach w innych językach ---
    // (np. „aukubina” nie ma artykułu po polsku, ale Wikidata zna polską nazwę i ma artykuł angielski „Aucubin”)
    async function viaWikidata(q) {
        const found = await getJson(`${WIKIDATA}?action=wbsearchentities&search=${encodeURIComponent(q)}&language=pl&uselang=pl&type=item&limit=5&format=json&origin=*`);
        const hits = (found && found.search ? found.search : [])
            .filter(h => !/ujednoznaczn|disambiguation|nazwisko|imię|film|album|singel|gra /i.test(h.description || ''))
            // dopasowana etykieta/alias musi zawierać rdzeń szukanego słowa (bez przypadkowych trafień)
            .filter(h => relevant({ title: (h.match && h.match.text) || h.label || '', extract: '' }, q));
        if (!hits.length) return null;
        const ids = hits.map(h => h.id).join('|');
        const ent = await getJson(`${WIKIDATA}?action=wbgetentities&ids=${ids}&props=sitelinks|descriptions&languages=pl|en&format=json&origin=*`);
        const entities = ent && ent.entities ? ent.entities : {};
        for (const h of hits) {
            const e = entities[h.id];
            if (!e || !e.sitelinks) continue;
            const desc = (e.descriptions && e.descriptions.pl && e.descriptions.pl.value) || h.description || '';
            for (const lang of ['pl'].concat(OTHER_LANGS)) {
                const link = e.sitelinks[`${lang}wiki`];
                if (!link) continue;
                const s = await summary(link.title, lang);
                if (s && s.type !== 'disambiguation') {
                    s.wdDesc = desc;
                    s.wdUrl = `https://www.wikidata.org/wiki/${h.id}`;
                    return s;
                }
            }
        }
        return null;
    }

    // „2 łyżki miodu” -> „miodu”: usuwamy ilości i miary przed szukaniem
    function cleanQuery(q) {
        return String(q)
            .replace(/^[\d\s.,/½¼¾⅓⅔-]+/, '')
            .replace(/^(?:g|kg|mg|ml|l|łyż\S*|szklan\S*|garś\S*|szczyp\S*|kropl\S*|sztuk\S*|szt\.?|porcj\S*|plast\S*|ząb\S*|ząbk\S*)\s+/i, '')
            .trim() || String(q);
    }

    async function search(q, lang) {
        q = cleanQuery(q);
        const d = await getJson(`${wikiHost(lang || 'pl')}/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q)}&srlimit=5&srnamespace=0&format=json&origin=*`);
        return d && d.query && d.query.search ? d.query.search.map(s => s.title) : [];
    }

    // --- czy znaleziony artykuł naprawdę dotyczy szukanego hasła ---
    // (wyszukiwarka Wikipedii potrafi zwrócić coś zupełnie innego, np. „Melasa” dla „Sole mineralne”)
    const PL = { 'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z' };
    function normPl(t) { return String(t || '').toLowerCase().replace(/[ąćęłńóśźż]/g, m => PL[m]); }
    function stemsOf(q) {
        return normPl(q).split(/[^\p{L}\p{N}]+/u).filter(w => w.length >= 4)
            .map(w => w.slice(0, Math.max(4, Math.ceil(w.length * 0.6))));
    }
    function relevant(res, query) {
        const stems = stemsOf(query);
        if (!stems.length) return true;
        const title = normPl(res.title);
        if (stems.some(st => title.includes(st))) return true;
        const text = normPl(`${res.title} ${String(res.extract || '').slice(0, 400)}`);
        return stems.every(st => text.includes(st));
    }

    // Porównanie nazwy polskiej z tytułem obcojęzycznym: „katalpol” ~ „Catalpol”, „aukubina” ~ „Aucubin”
    // (k→c, w→v, j/y→i, bez końcowych samogłosek; dopuszczalna różnica do 2 znaków na końcu)
    function skeleton(t) {
        return normPl(t).replace(/\([^)]*\)/g, '').replace(/[^a-z]/g, '')
            .replace(/ph/g, 'f').replace(/th/g, 't').replace(/ch/g, 'h').replace(/k/g, 'c').replace(/w/g, 'v')
            .replace(/[jy]/g, 'i').replace(/[aeiou]+$/, '');
    }
    function foreignMatch(title, q) {
        const a = skeleton(title), b = skeleton(q);
        if (a.length < 4 || b.length < 4) return a === b;
        return (a.startsWith(b) || b.startsWith(a)) && Math.abs(a.length - b.length) <= 2;
    }

    const inflight = new Map();
    function lookup(q) {
        const cached = cacheGet(q);
        if (cached !== undefined) return Promise.resolve(cached);
        if (inflight.has(q)) return inflight.get(q);
        const p = (async () => {
            let result = null;
            let disamb = null;
            // hasło może mieć warianty: "Składniki mineralne|Sole mineralne|Makroelementy"
            const alts = String(q).split('|').map(x => x.trim()).filter(Boolean);
            try {
                for (const a of alts) {
                    const s = await summary(a);
                    if (s && s.type !== 'disambiguation') { result = s; break; }
                    if (s && !disamb) disamb = s;
                }
                if (!result) {
                    const base = cleanQuery(alts[0] || q);
                    const titles = await search(base);
                    // najpierw tytuły, które zawierają rdzeń szukanego słowa
                    const st = stemsOf(base);
                    titles.sort((x, y) => (st.some(s => normPl(y).includes(s)) ? 1 : 0) - (st.some(s => normPl(x).includes(s)) ? 1 : 0));
                    for (const t of titles) {
                        const s = await summary(t);
                        if (s && s.type !== 'disambiguation' && relevant(s, base)) { result = s; break; }
                    }
                }
                // 3. Wikidata -> artykuł w innym języku (polska nazwa, etykieta albo alias)
                if (!result) {
                    for (const a of alts) {
                        result = await viaWikidata(cleanQuery(a));
                        if (result) break;
                    }
                }
                // 4. wyszukiwarka angielskiej i niemieckiej Wikipedii (nazwy łacińskie, międzynarodowe)
                if (!result) {
                    const base = cleanQuery(alts[alts.length - 1] || q);
                    for (const lang of ['en', 'de']) {
                        const titles = await search(base, lang);
                        for (const t of titles.slice(0, 3)) {
                            const s = await summary(t, lang);
                            if (s && s.type !== 'disambiguation' && foreignMatch(s.title, base)) { result = s; break; }
                        }
                        if (result) break;
                    }
                }
                if (!result && disamb && relevant(disamb, alts[0] || q)) result = disamb;
                cacheSet(q, result || { missing: true });
            } catch (e) {
                result = { error: true };   // błąd sieci – nie zapisujemy, spróbujemy ponownie
            } finally {
                inflight.delete(q);
            }
            return result || { missing: true };
        })();
        inflight.set(q, p);
        return p;
    }

    // ------------------------------------------
    // DYMEK
    // ------------------------------------------
    let tip = null;
    let current = null;     // element pojęcia, dla którego pokazujemy dymek
    let pinned = false;
    let showTimer = null, hideTimer = null;
    let requestId = 0;

    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

    function ensureTip() {
        if (tip) return tip;
        tip = document.createElement('div');
        tip.className = 'kw-wiki-tip';
        tip.id = 'kwWikiTip';
        tip.setAttribute('role', 'dialog');
        tip.setAttribute('aria-live', 'polite');
        tip.hidden = true;
        document.body.appendChild(tip);
        tip.addEventListener('pointerenter', () => clearTimeout(hideTimer));
        tip.addEventListener('pointerleave', e => { if (e.pointerType === 'mouse' && !pinned) scheduleHide(); });
        tip.addEventListener('click', e => { if (e.target.closest('.kw-wiki-close')) { e.preventDefault(); hide(true); } });
        return tip;
    }

    function shortExtract(text) {
        const t = String(text).replace(/\s+/g, ' ').trim();
        if (t.length <= 420) return t;
        const cut = t.slice(0, 420);
        const dot = cut.lastIndexOf('. ');
        return (dot > 200 ? cut.slice(0, dot + 1) : cut.replace(/\s+\S*$/, '')) + ' …';
    }

    function render(term, data) {
        const label = term.textContent.trim();
        const q = String(term.dataset.wiki || '').split('|')[0];
        let html = `<button type="button" class="kw-wiki-close" aria-label="Zamknij">&times;</button>`;
        if (!data) {
            html += `<div class="kw-wiki-head">${esc(label)}</div><div class="kw-wiki-loading"><span class="kw-wiki-spinner"></span> Szukam w Wikipedii…</div>`;
        } else if (data.error) {
            html += `<div class="kw-wiki-head">${esc(label)}</div><p class="kw-wiki-text">Nie udało się połączyć z Wikipedią. Spróbuj ponownie za chwilę.</p>
                <a class="kw-wiki-more" href="${WIKI}/w/index.php?search=${encodeURIComponent(q)}" target="_blank" rel="noopener">Szukaj w Wikipedii ↗</a>`;
        } else if (data.missing) {
            html += `<div class="kw-wiki-head">${esc(label)}</div><p class="kw-wiki-text">Wikipedia nie ma jeszcze krótkiego opisu tego hasła – ani po polsku, ani w innych językach.</p>
                <a class="kw-wiki-more" href="${WIKI}/w/index.php?search=${encodeURIComponent(q)}" target="_blank" rel="noopener">Szukaj w Wikipedii ↗</a>`;
        } else {
            const differs = label.length > 2 && !label.toLowerCase().startsWith(data.title.toLowerCase());   // znaczek „W” bez dopisku
            html += `<div class="kw-wiki-head">${esc(data.title)}</div>`;
            if (differs) html += `<div class="kw-wiki-sub">dla: „${esc(label)}”</div>`;
            const lang = data.lang || 'pl';
            const foreign = lang !== 'pl';
            if (foreign) {
                html += `<div class="kw-wiki-lang">🌐 Brak artykułu po polsku – opis z ${esc(LANG_NAMES[lang] || lang)} Wikipedii</div>`;
                if (data.wdDesc) html += `<div class="kw-wiki-sub">Wikidata: ${esc(data.wdDesc)}</div>`;
            }
            html += `<div class="kw-wiki-body">${data.thumb ? `<img class="kw-wiki-img" src="${esc(data.thumb)}" alt="" loading="lazy">` : ''}<p class="kw-wiki-text" lang="${esc(lang)}">${esc(shortExtract(data.extract))}</p></div>`;
            if (data.type === 'disambiguation') html += `<p class="kw-wiki-sub">To hasło ma kilka znaczeń – szczegóły w Wikipedii.</p>`;
            const translate = foreign
                ? ` <a class="kw-wiki-more" href="https://translate.google.com/translate?sl=${encodeURIComponent(lang)}&tl=pl&u=${encodeURIComponent(data.url)}" target="_blank" rel="noopener">Przetłumacz ↗</a>` : '';
            html += `<div class="kw-wiki-foot"><span><a class="kw-wiki-more" href="${esc(data.url)}" target="_blank" rel="noopener">Czytaj w Wikipedii${foreign ? ` (${esc(lang.toUpperCase())})` : ''} ↗</a>${translate}</span><span class="kw-wiki-lic">Wikipedia${foreign ? ` (${esc(lang)})` : ''} · CC BY-SA</span></div>`;
        }
        tip.innerHTML = html;
    }

    function position() {
        if (!tip || tip.hidden || !current) return;
        if (!document.body.contains(current)) { hide(true); return; }
        if (window.innerWidth < 576) { tip.classList.add('kw-wiki-sheet'); tip.style.left = ''; tip.style.top = ''; return; }
        tip.classList.remove('kw-wiki-sheet');
        const r = current.getBoundingClientRect();
        const tw = tip.offsetWidth, th = tip.offsetHeight, gap = 8, margin = 8;
        let top = r.bottom + gap;
        if (top + th > window.innerHeight - margin && r.top - gap - th > margin) top = r.top - gap - th;
        let left = r.left + r.width / 2 - tw / 2;
        left = Math.max(margin, Math.min(left, window.innerWidth - tw - margin));
        tip.style.left = `${Math.round(left)}px`;
        tip.style.top = `${Math.round(Math.max(margin, top))}px`;
    }

    function show(term, pin) {
        ensureTip();
        clearTimeout(hideTimer);
        if (current && current !== term) current.classList.remove('kw-wiki-active');
        current = term;
        pinned = !!pin;
        term.classList.add('kw-wiki-active');
        term.setAttribute('aria-expanded', 'true');
        const q = term.dataset.wiki;
        const cached = cacheGet(q);
        render(term, cached);
        tip.hidden = false;
        position();
        if (cached === undefined) {
            const id = ++requestId;
            lookup(q).then(data => {
                if (id !== requestId || current !== term || tip.hidden) return;
                render(term, data);
                position();
            });
        }
    }

    function hide(force) {
        if (!tip || (pinned && !force)) return;
        tip.hidden = true;
        pinned = false;
        if (current) { current.classList.remove('kw-wiki-active'); current.setAttribute('aria-expanded', 'false'); }
        current = null;
    }
    function scheduleHide() { clearTimeout(hideTimer); hideTimer = setTimeout(() => hide(false), 250); }

    // --- zdarzenia (delegacja) ---
    document.addEventListener('pointerover', e => {
        if (e.pointerType !== 'mouse') return;
        const term = e.target.closest && e.target.closest('.kw-wiki');
        if (!term) return;
        clearTimeout(hideTimer);
        if (pinned && current !== term) return;      // przypięty dymek zostaje, dopóki nie klikniesz innego
        clearTimeout(showTimer);
        showTimer = setTimeout(() => show(term, false), 300);
        lookup(term.dataset.wiki);                   // pobieramy od razu, żeby dymek był gotowy
    });
    document.addEventListener('pointerout', e => {
        if (e.pointerType !== 'mouse') return;
        const term = e.target.closest && e.target.closest('.kw-wiki');
        if (!term || (e.relatedTarget && term.contains(e.relatedTarget))) return;
        clearTimeout(showTimer);
        if (!pinned) scheduleHide();
    });
    document.addEventListener('click', e => {
        const term = e.target.closest && e.target.closest('.kw-wiki');
        if (term) {
            e.preventDefault();
            e.stopPropagation();
            clearTimeout(showTimer);
            if (current === term && pinned) hide(true); else show(term, true);
            return;
        }
        if (tip && !tip.hidden && !tip.contains(e.target)) hide(true);
    }, true);
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && tip && !tip.hidden) { const t = current; hide(true); if (t) t.focus(); return; }
        const term = e.target.closest && e.target.closest('.kw-wiki');
        if (term && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); if (current === term && pinned) hide(true); else show(term, true); }
    });
    document.addEventListener('focusout', e => {
        if (!tip || tip.hidden || pinned) return;
        if (e.relatedTarget && (tip.contains(e.relatedTarget) || (current && current.contains(e.relatedTarget)))) return;
        scheduleHide();
    });
    window.addEventListener('scroll', () => requestAnimationFrame(position), true);
    window.addEventListener('resize', () => requestAnimationFrame(position));

    // --- automatyczne skanowanie treści dodawanej później (modale, zakładki) ---
    let scanQueued = false;
    const pending = new Set();
    const observer = new MutationObserver(muts => {
        muts.forEach(m => m.addedNodes.forEach(n => {
            if (n.nodeType !== 1 || n === tip || (tip && tip.contains(n))) return;
            if (n.classList && n.classList.contains('kw-wiki')) return;
            const root = n.closest('[data-wiki-scan]') || (n.querySelector && n.querySelector('[data-wiki-scan],[data-wiki-ingredient],[data-wiki-term]') ? n : null);
            if (root) pending.add(root);
        }));
        if (pending.size && !scanQueued) {
            scanQueued = true;
            requestAnimationFrame(() => {
                scanQueued = false;
                const roots = Array.from(pending);
                pending.clear();
                roots.forEach(r => { if (document.body.contains(r)) scan(r); });
            });
        }
    });

    function init() {
        scan(document);
        observer.observe(document.body, { childList: true, subtree: true });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();

    window.KwWiki = { scan, lookup, findTerms };
})();
