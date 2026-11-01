# Banco di prova Laravel

La stessa idea di `tests/bench-app` (Node/Next.js), in PHP/Laravel: **13 difetti noti** (route di demo e di debug esposte, mass assignment, SQL injection, XSS in Blade, redirect aperto, gate troppo largo, APP_DEBUG forzato, APP_KEY nel compose, porta del database, azione CI non fissata, segreto rimasto nella storia Git) e **5 esche**. Serve a verificare che skill e pre-passaggio funzionino anche fuori dall'ecosistema JavaScript, dove lavorano molti gestionali di PA e associazioni.

```bash
python3 tests/bench-php/score_bench.py prepare ~/prova-php
cd ~/prova-php/bench-app && <agente>: /appsec-sentinel rapido .
python3 tests/bench-php/score_bench.py score ~/prova-php/audit-A [~/prova-php/audit-B]
```
