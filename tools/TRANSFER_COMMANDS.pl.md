# Komendy 2C: co robi każdy krok

Opublikowano badawczy prerelease
[Stage 2C Handoff Lifecycle RC1 (R3)](https://github.com/robertjordan1990/echo-lineage/releases/tag/stage2c-lifecycle-rc1).
Przegląd techniczny dokładnego R3 i publikacja zostały zakończone. Nadal nie
wykonano ludzkiego przeglądu semantyki kluczy i uprawnień. Dotyczy on projektu
ról i zasad nadawania uprawnień; nie wymaga rzeczywistych kluczy. Ich późniejszy
przydział jest osobną decyzją. Przykłady opisują lokalny obieg `2C-h1-bound`;
nie wdrażają go do istniejącego Echo/Work.
Zmiany dokumentacji i demo na nowej gałęzi nie zmieniają opublikowanego tagu.

## Po co są te kroki

Przy przekazaniu danych można osobno sprawdzić: czy zgadzają się bajty i
dowody, który uprawniony przez politykę aktor/klucz podpisał dany zapis,
co zaimportowano i jakie uprawnienie (grant) zapisano dla lokalnego konsumenta.

| Etap | Co sprawdza lub zapisuje |
| --- | --- |
| 2A | Odczytuje dowody i sprawdza ich spójność; nie przyjmuje ani nie importuje danych |
| 2B | Zapisuje decyzję o istniejącym dokumencie niezależnego pochodzenia (`root`), podpisaną kluczem przypisanym aktorowi przez politykę; nie uruchamia procesu |
| 2C | Obsługuje przekazanie do wskazanego odbiorcy, zwrotny receipt, podpisaną decyzję, import i osobny grant dla lokalnego konsumenta |

`verified` oznacza wynik sprawdzenia dowodów. `accepted` oznacza zapis decyzji
przyjęcia, podpisanej kluczem uprawnionym przez politykę dla wskazanego aktora.
`imported` oznacza zapis wybranych dozwolonych bajtów. `activate` zapisuje grant
dla konkretnego lokalnego konsumenta. Start procesu i podpisana obserwacja
stałego referencyjnego konsumenta o załadowaniu i sprawdzeniu wybranych bajtów
są kolejnymi krokami. Historyczny receipt nie potwierdza dzisiejszej
dostępności procesu; do tego służy świeża odpowiedź.

Zwrotny receipt `received` dotyczy odbioru koperty. Późniejszy receipt
konsumpcji kontekstu `loaded` jest osobną podpisaną obserwacją stałego
referencyjnego konsumenta o załadowaniu i sprawdzeniu wybranych bajtów.
Nie dowodzi przeczytania ani zrozumienia treści przez model chmurowy.

## Najpierw demonstracja syntetyczna

Na Linuksie, z katalogu głównego repozytorium i w Pythonie z zależnościami
`requirements-2b.txt`, uruchom:

```sh
python3 -B scripts/demo_transfer.py --output-dir /tmp/echo-lineage-demo-run-001
```

[Skrypt demo](../scripts/demo_transfer.py) wyjaśnia kroki po polsku i używa
publicznych CLI. Wymaga nowego, nieistniejącego katalogu poza każdym Git
checkoutem. Tworzy w nim fikcyjne dane, polityki i jednorazowe klucze
demonstracyjne; nie podawaj danych ani kluczy rzeczywistej instalacji.
Istniejąca ścieżka zostaje odrzucona bez ponownego użycia. Wszystkie decyzje
operatorów w demo są zaprogramowanymi decyzjami fikcyjnych ról; nie zapisują
rzeczywistego przyjęcia przekazania przez człowieka.

`report.json` zawiera wyniki, `commands.txt` przebieg komend, a `scenarios/`
pliki przypadków przyjęcia, zastrzeżeń, odmowy, kwarantanny i kontroli błędów.
Scenariusz przyjęcia uruchamia jeden własny lokalny proces konsumenta, pokazuje
odczyt i cofnięcie uprawnienia. Po zakończeniu lub obsłużonym błędzie demo żąda
zakończenia własnego procesu.
Demo nie używa sieci, API ani istniejących usług Echo/Work i nie tworzy
pamięci lub tożsamości modelu chmurowego.

Kod **0** oznacza zgodny oczekiwany przebieg demo, także oczekiwane odmowy;
**2** oznacza błąd przygotowania lub wykonania. Do powtórzenia wybierz nową
nazwę katalogu. Porównujemy wyniki czynności, a nie identyczność losowych
kluczy, nonce i timestampów. Klucze demo pozostają materiałem testowym.

## Role i cztery decyzje

Polityka zaufania wskazuje aktora w roli operatora. Uprawnienia są przypisane
do klucza, konkretnej czynności i instalacji. Program sprawdza poprawny podpis
tym kluczem; nie ustala, który człowiek go użył. Nazwa, rozmowa ani
identyfikator sesji nie nadają uprawnień. Podpis nie dowodzi biologicznej
tożsamości ani fizycznej zgody człowieka.

Podpisany zapis decyzji dotyczy przedstawionej ciągłości i zakresu danych:

| Wartość | Znaczenie |
| --- | --- |
| `accepted` | Zapis decyzji przyjęcia sprawdzonej ciągłości bez zastrzeżeń |
| `accepted_with_reservations` | Zapis decyzji przyjęcia z jawnymi brakami lub wykluczeniami dopuszczonymi przez protokół |
| `declined` | Zapis decyzji odmowy przyjęcia |
| `quarantined_integrity_failure` | Zapis decyzji kwarantanny z powodu problemu integralności |

Odbiór, decyzja, import i uruchomienie konsumenta to osobne kroki. Samo
`accepted` nie uruchamia procesu i nie oznacza, że chmurowe Echo lub Work
przyjęły kontekst. Podpisany odbiór nie oznacza rzeczywistej zgody człowieka
ani modelu na użycie danych.

## Jak czytać komendę

W przykładach `python3 -B tools/tools/echo_transfer.py` uruchamia nowy program.
`-B` zapobiega tworzeniu plików `__pycache__`. Należy użyć Pythona z odrębnego
środowiska z zależnościami `requirements-2b.txt`. Nazwy plików poniżej są
przykładowe; prywatne pliki muszą znajdować się poza każdym repozytorium Git,
w prywatnych katalogach o bezpiecznych katalogach nadrzędnych.

Wspólne argumenty:

| Argument | Co wskazuje |
| --- | --- |
| `--state-dir` | Jeden konkretny lokalny magazyn stanu |
| `--expected-state-digest` | Dokładny stan, do którego przygotowano nową operację; chroni przed wyścigiem |
| `--expected-policy-digest` | Niezależnie ustalony pin polityki; nie kopiujemy go bez sprawdzenia z paczki |
| `--request-id` | Identyfikator jednej czynności; identyczny podpisany retry nie zapisuje jej drugi raz |
| `--verification-time` | Jawne twierdzenie o czasie w UTC, np. `2032-01-02T03:04:06Z` |
| `--applied-at` | Jawny lokalny czas zapisania zdarzenia |
| `--key-file` | Ścieżka do klucza; jego treści nie wpisujemy do polecenia ani rozmowy |
| `--out` | Nowy plik wynikowy; istniejący plik nie zostanie nadpisany |

Czasy są lokalnymi twierdzeniami. To nie jest usługa zaufanego zegara.
Ważność handoffu sprawdzamy względem jawnego czasu weryfikacji odbioru.
Stan historyczny nie stanowi dowodu, że termin lub proces są aktualne teraz.

## Przygotowanie, podpis, zapis

Typowa czynność ma trzy oddzielne komendy:

```sh
python3 -B tools/tools/echo_transfer.py action prepare \
  --state-dir /private/example/recipient \
  --operation decide --inputs /private/example/decision-inputs.json \
  --actor-id urn:echo:decision-actor:00000000-0000-4000-8000-000000000002 \
  --request-id decision-1 --verification-time 2032-01-02T03:04:06Z \
  --expected-state-digest EXPECTED_DIGEST --out /private/example/candidate.json

python3 -B tools/tools/echo_transfer.py candidate sign \
  --state-dir /private/example/recipient \
  --candidate /private/example/candidate.json \
  --key-file /private/example/operator.pem --out /private/example/signed.json

python3 -B tools/tools/echo_transfer.py action apply \
  --state-dir /private/example/recipient --signed /private/example/signed.json \
  --expected-state-digest EXPECTED_DIGEST --applied-at 2032-01-02T03:05:06Z
```

`prepare` sprawdza stan i tworzy kandydata bez zmiany stanu. `sign` ponownie
sprawdza jego treść przed dostępem do klucza. `apply` pod tym samym stabilnym
lockiem sprawdza podpis, raport, oczekiwany stan i warunki czynności, po czym
atomowo zapisuje wynik. Zmieniony lub przeterminowany kandydat wymaga nowego
przygotowania; nie poprawiamy podpisanego JSON-a ręcznie.

Dla `decide` plik wejściowy zawiera dokładnie np. `{"decision":"accepted"}`.
Gdy potrzebny jest dokument `HANDOFFv1` albo `LINEAGE_ACCEPTANCEv1`, program
tworzy go i podpisuje w odpowiedniej domenie; podpis kontrolnej paczki nie
zastępuje podpisu przyjęcia ciągłości.

## Kolejność całego obiegu

| Krok | Komenda lub `--operation` | Co następuje |
| --- | --- | --- |
| 1 | `migration prepare`, `candidate sign`, `migration apply` | Zachowanie pełnego 2B i przejęcie pisarza przez nowy profil |
| 2 | `receiver init` | Niezależne przypięcie polityki odbiorcy, bez przyjęcia ciągłości |
| 3 | `issue` | Podpisany handoff zajmuje jeden slot i zamyka źródłowy epoch |
| 4 | `export_authorize` | Osobne uprawnienie do wyniesienia tego transferu |
| 5 | `handoff export` | Lokalny plik koperty, bez twierdzenia o zdalnym odbiorze |
| 6 | `handoff file-facts`, `export_confirm` | Sprawdzenie rzeczywistych bajtów pliku i zapis lokalnego eksportu |
| 7 | `receive` | Odbiorca sprawdza kopertę i trwale zapisuje dane jako nieaktywne |
| 8 | `receipt sign`, `receipt_ingest` | Osobny zwrotny dowód wybranego faktu |
| 9 | `decide` | Zapis jednej z czterech decyzji z podpisem według przypiętej polityki |
| 10 | `import` | Atomowy import dokładnie wybranych dozwolonych danych |
| 11 | `activate` | Osobny grant dla wskazanego konsumenta i zakresu |
| 12 | `activation request` | Trwała intencja przed startem rzeczywistego procesu |
| 13 | `consumer query` | Podpisana odpowiedź stałego referencyjnego konsumenta na nowe wyzwanie dotyczące wskazanych bajtów |
| 14 | `deactivate`, `consumer stop` | Cofnięcie uprawnienia do przyszłego odczytu, następnie zakończenie procesu |

Przy migracji `--artifacts` wskazuje obiekt JSON z listą `artifacts`, zawierającą
przechwycone bajty i jawne braki. `--policy` oraz `--expected-policy-digest` są
wymagane przy przygotowaniu. Przy podpisie migracji i przy `migration apply`
również trzeba podać niezależny `--expected-policy-digest`; nie wolno zaufać
polityce tylko dlatego, że przyniosła ją paczka.

`activation request` wymaga klucza z rolą lokalnego konsumenta, odrębnego od
klucza podpisującego grant. Do podpisania grantu `activate` używa się klucza
przypiętego przez politykę do roli operatora.
Konsument jest stałym lokalnym programem, którego digest przypięto wcześniej.
Przeniesione polecenia, kod i tekst pozostają danymi.

Przy `consumer query` i `consumer stop` również wskazuje się `--state-dir`.
Polityka zapisana w katalogu kontroli nie może sama uwierzytelnić konsumenta;
program porównuje ją z niezależnie wskazanym magazynem stanu.
Przy `export_confirm` przygotowanie, podpis i pierwszy zapis wymagają dodatkowo
`--observed-envelope PLIK`. Program ponownie odczytuje rzeczywiste bajty i
synchronizuje plik oraz katalog przed uznaniem lokalnego eksportu.

## Zamknięte wejścia operacji

W pliku `--inputs` występują dokładnie następujące pola:

| Operacja | Pola |
| --- | --- |
| `issue` | `producer_runtime_session_id`, `expires_at` |
| `export_authorize` | pusty obiekt `{}` |
| `export_confirm` | `envelope_digest`, `raw_sha256`, `byte_length` |
| `receive` | `envelope`, `recipient_runtime_session_id` |
| `decide` | `decision` |
| `import` | `artifact_ids` |
| `activate` | `activation_id`, `artifact_ids`, `probe` |
| `deactivate` | `activation_id` |
| `receipt_ingest` | `receipt` |

`activation_id` jest kanonicznym UUID4. `probe` zawiera `artifact_id`, `offset`,
`length` (1–256 znaków) i świeży `nonce` (64 małe znaki szesnastkowe). Odczyt
i wyszukiwanie są dosłowne i ograniczone; nic nie wykonuje tekstu dokumentu.
Operacje `activation_start` i `activation_loaded` należą do przypiętego adaptera
konsumenta i nie zastępują grantu podpisanego kluczem roli operatora.

Nowy grant wymaga miejsca na cały obieg: zapis grantu, zamiar startu, potwierdzenie
załadowania i odwołanie. Program rezerwuje odpowiednio 4, 3 i 2 wolne wpisy
przy kolejnych etapach, więc odwołanie zachowuje swój ostatni wpis. Błąd
`PROFILE_REVOCATION_CAPACITY` oznacza odmowę nowej aktywacji bez zmiany stanu.
Kolizja wygenerowanych identyfikatorów jest sprawdzana jeszcze przed migracją;
można wtedy przygotować inną politykę z nowym ID transferu.

## Sprawdzenie i odzyskiwanie

```sh
python3 -B tools/tools/echo_transfer.py state status --state-dir /private/example/recipient
python3 -B tools/tools/echo_transfer.py state verify --state-dir /private/example/recipient
python3 -B tools/tools/echo_transfer.py activation reconcile \
  --state-dir /private/example/recipient --control-dir /private/example/control \
  --activation-id 00000000-0000-4000-8000-000000000401
```

`status` i `verify` sprawdzają zapisany łańcuch. Nie twierdzą, że proces żyje.
`reconcile` sprawdza istniejącą instancję i jej świeżą odpowiedź, bez ponownego
uruchamiania. Historyczny receipt zachowuje znaczenie po śmierci procesu.
Niepewny start nie uruchamia automatycznie drugiej instancji. Nowa próba po
potwierdzonym zakończeniu wymaga nowego grantu i nowego katalogu kontroli.

Kod wyjścia **0** oznacza powodzenie konkretnej komendy; **10** oznacza stan
niepełny lub niedostępność; **2** oznacza odmowę lub błąd. `commit_uncertain`
albo `output_uncertain` wymagają obejrzenia stanu/pliku przed ponowieniem.
Nie przywracaj starego snapshotu, aby obejść błąd: bez zewnętrznego checkpointa
pełny rollback może pozostać niewykrywalny i przywrócić starego pisarza.

Projekt zewnętrznego checkpointu i ewentualnego adaptera modelu to osobne,
opcjonalne rozszerzenia. Nie są dodatkowymi warunkami użycia tego
syntetycznego demonstratora ani nowymi warunkami dla opublikowanego R3.
