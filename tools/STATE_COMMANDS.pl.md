# Komendy 2B Core

To kandydat implementacji lokalnego stanu. Nie aktywuje modelu ani instalacji.
Nie podpisuje opinii Echo lub Worka. Operator podpisuje własną decyzję swoim
wcześniej sprawdzonym, lokalnie uprawnionym kluczem Ed25519.

| Komenda | Co robi | Czy zmienia stan decyzji? |
| --- | --- | --- |
| `state init` | Wiąże istniejący dokument początkowy i jawną politykę kluczy w nowym prywatnym katalogu. | Tworzy pusty, nieprzyjęty stan. |
| `state status` | Sprawdza historię i pokazuje jej stan oraz digest do kolejnego zapisu. | Nie. |
| `state verify` | Sprawdza podpisy, łańcuch i opcjonalny zaufany checkpoint. | Nie. |
| `decision prepare` | Sprawdza źródła i przygotowuje konkretną decyzję z raportem. | Nie; tworzy osobny plik kandydata. |
| `decision sign` | Sprawdza kandydata i podpisuje go wskazanym kluczem. | Nie; tworzy osobny podpisany plik. |
| `decision apply` | Ponownie sprawdza źródła, podpis i oczekiwany stan, potem zapisuje decyzję. | Tak, po przejściu wszystkich kontroli. |

Cztery decyzje to `accepted` (przyjmuję), `accepted_with_reservations`
(przyjmuję z jawnymi zastrzeżeniami), `declined` (odrzucam) i
`quarantined_integrity_failure` (kwarantanna z powodu naruszenia integralności).
Nie każda decyzja jest dozwolona przy każdym wyniku weryfikacji.

`--state-dir` wskazuje prywatny katalog poza repozytoriami. Przy `init` ten
katalog nie może jeszcze istnieć. `--expected-root-hash` to protokołowy hash
dokumentu początkowego; `--root-artifact-id` to jego jawny identyfikator artefaktu.
`--expected-state-digest` pochodzi z poprzedniego `state status` i chroni przed
zapisem do zmienionego w międzyczasie stanu. `--request-id` identyfikuje jeden
konkretny wniosek. `--verification-time` podaje jawny czas UTC.

`--actor-id` i `--operator-id` muszą być takie same w tym pierwszym profilu.
`--key-file` jest ścieżką do prywatnego pliku klucza; zawartości klucza nie wolno
wpisywać jako argumentu ani wklejać do rozmowy. Polecenia nie szukają klucza same.
`--out` zawsze tworzy nowy prywatny plik i nie nadpisuje istniejącego.
Katalog nadrzędny pliku `--out` musi już istnieć, należeć do użytkownika i mieć
uprawnienia 0700; jego katalogi nadrzędne też przechodzą kontrolę bezpieczeństwa.

Przykład samego odczytu, z fikcyjną ścieżką do zastąpienia:

```sh
python3 -B tools/tools/echo_state.py state status --state-dir /prywatny/katalog/stanu --json
```

`python3` uruchamia Pythona, `-B` wyłącza zapis plików cache `.pyc`, plik
`echo_state.py` jest osobnym narzędziem 2B, `state status` wybiera odczyt stanu,
a `--json` wybiera format danych (jest też formatem domyślnym).

Kod zakończenia 0 oznacza wykonanie operacji, 10 brak obsługi danego profilu lub
możliwości uwierzytelnienia, a 2 odmowę lub niepewny zapis. Przy
`commit_uncertain=true` najpierw sprawdź istniejący stan i wniosek; nie ponawiaj
zapisów w ciemno. Przy `output_uncertain=true` sprawdź utworzony plik pomocniczy.

Historyczne przyjęcie, aktualnie sprawdzone źródła i aktywacja są osobnymi
rzeczami. `state status` nie sprawdza ponownie źródeł, a
`runtime_activation=false` obowiązuje zawsze. Pełne argumenty i granice gwarancji:
[specyfikacja lokalnego stanu](spec/echo-lineage-state-v1/README.md).
