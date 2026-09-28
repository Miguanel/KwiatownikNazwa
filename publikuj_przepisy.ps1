# Publikuje przepisy z Siedziby Kwiatownika na kwiatownik.onrender.com (commit + push tylko pliku z przepisami).
# Uzycie (w terminalu PyCharma, w folderze Kwiatownik2):  .\publikuj_przepisy.ps1
#                                             z opisem:  .\publikuj_przepisy.ps1 -Message "Nowe syropy"
param([string]$Message = "")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$file = "data/przepisy/siedziba_przepisy.json"
if (-not (Test-Path $file)) {
    Write-Host "Brak pliku $file - najpierw zrob eksport w Siedzibie (zakladka Eksport)." -ForegroundColor Yellow
    exit 1
}

# sprawdzenie, czy plik to poprawny JSON (zeby nie opublikowac uszkodzonych danych)
try {
    $count = @(Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json).Count
} catch {
    Write-Host "Plik $file nie jest poprawnym JSON-em - przerywam." -ForegroundColor Red
    exit 1
}

git add -- $file
$changed = git diff --cached --name-only -- $file
if (-not $changed) {
    Write-Host "Brak zmian w przepisach - nie ma czego publikowac." -ForegroundColor Green
    exit 0
}
if (-not $Message) { $Message = "Przepisy z Siedziby Kwiatownika ($count)" }

git commit -m $Message -- $file
git push
Write-Host "Opublikowano $count przepisow. Render zbuduje nowa wersje strony (przy wlaczonym auto-deploy)." -ForegroundColor Green
