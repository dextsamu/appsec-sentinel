# Banco di prova Django

**11 difetti noti** tipici dei gestionali Python (SECRET_KEY nel codice, DEBUG attivo per default, mass assignment, BOLA su dati con codice fiscale, deserializzazione con pickle e yaml.load, SSRF, redirect aperto, `pull_request_target` con checkout della PR, dipendenze vulnerabili, un segreto rimasto nella storia Git, la ricerca senza filtro per sezione) e **5 esche** (filtro per sezione corretto, query parametrizzata, porta legata a 127.0.0.1, `.env.example` con segnaposto, template con autoescape).

```bash
python3 tests/bench-django/score_bench.py prepare ~/prova-dj
cd ~/prova-dj/bench-app && <agente>: /appsec-sentinel rapido .
python3 tests/bench-django/score_bench.py score ~/prova-dj/audit-A [~/prova-dj/audit-B]
```
