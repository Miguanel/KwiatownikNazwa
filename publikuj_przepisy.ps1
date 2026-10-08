# Publikuje dane z Siedziby Kwiatownika na kwiatownik.onrender.com: magazyn przepisow (data/przepisy/*.json,
# w tym eksporty Siedziby siedziba_przepisy_RRRR-MM-DD.json - strona czyta najnowszy plik z kazdej serii)
# oraz wiedze o roslinach (data/plants/*.json - blok "wiedza" i nowe rosliny). Commit + push tylko tych plikow.
# Uzycie (w terminalu PyCharma, w folderze Kwiatownik2):  .\publikuj_przepisy.ps1
#                                             z opisem:  .\publikuj_przepisy.ps1 -Message "Nowe syropy"
param([string]$Message = "")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$recipeFiles = @(Get-ChildItem "data/przepisy" -Filter *.json -File | Where-Object { $_.Name -ne "wzorzec_przepisu.json" } |
    ForEach-Object { "data/przepisy/" + $_.Name })
$plants = Get-ChildItem "data/plants" -Filter *.json -File | ForEach-Object { "data/plants/" + $_.Name }
# czy strony-zrodla przepisow wciaz dzialaja (dymek "zrodlo" na stronie) - blad sprawdzania nie zatrzymuje publikacji
try { python sprawdz_zrodla.py } catch { Write-Host "Nie udalo sie sprawdzic zrodel: $_" -ForegroundColor Yellow }

$files = @()
$files += $recipeFiles
$files += $plants
if (Test-Path "data/zrodla_podglad.json") { $files += "data/zrodla_podglad.json" }

# sprawdzenie, czy kazdy plik to poprawny JSON (zeby nie opublikowac uszkodzonych danych)
foreach ($f in $files) {
    try { Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json | Out-Null }
    catch { Write-Host "Plik $f nie jest poprawnym JSON-em - przerywam." -ForegroundColor Red; exit 1 }
}
# liczba przepisow w najnowszym eksporcie Siedziby (seria siedziba_przepisy)
$count = 0
$latest = Get-ChildItem "data/przepisy" -Filter "siedziba_przepisy*.json" -File | Sort-Object Name | Select-Object -Last 1
if ($latest) { $count = @(Get-Content $latest.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).Count }

git add -- $files
$changed = @(git diff --cached --name-only -- $files)
if ($changed.Count -eq 0) {
    Write-Host "Brak zmian w przepisach ani roslinach - nie ma czego publikowac." -ForegroundColor Green
    exit 0
}
$nPlants = @($changed | Where-Object { $_ -like "data/plants/*" }).Count
if (-not $Message) { $Message = "Siedziba Kwiatownika: przepisy ($count), zmienione rosliny ($nPlants)" }

git commit -m $Message -- $changed
git push
Write-Host "Opublikowano: przepisy $count, zmienione pliki roslin $nPlants. Render zbuduje nowa wersje strony." -ForegroundColor Green
