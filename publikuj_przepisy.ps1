# Publikuje dane z Siedziby Kwiatownika na kwiatownik.onrender.com: przepisy (data/przepisy/siedziba_przepisy.json)
# oraz wiedze o roslinach (data/plants/*.json - blok "wiedza" i nowe rosliny). Commit + push tylko tych plikow.
# Uzycie (w terminalu PyCharma, w folderze Kwiatownik2):  .\publikuj_przepisy.ps1
#                                             z opisem:  .\publikuj_przepisy.ps1 -Message "Nowe syropy"
param([string]$Message = "")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$recipes = "data/przepisy/siedziba_przepisy.json"
$plants = Get-ChildItem "data/plants" -Filter *.json -File | ForEach-Object { "data/plants/" + $_.Name }
$files = @()
if (Test-Path $recipes) { $files += $recipes }
$files += $plants

# sprawdzenie, czy kazdy plik to poprawny JSON (zeby nie opublikowac uszkodzonych danych)
foreach ($f in $files) {
    try { Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json | Out-Null }
    catch { Write-Host "Plik $f nie jest poprawnym JSON-em - przerywam." -ForegroundColor Red; exit 1 }
}
$count = 0
if (Test-Path $recipes) { $count = @(Get-Content $recipes -Raw -Encoding UTF8 | ConvertFrom-Json).Count }

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
