# Banco di prova pubblico per l'agente

Un'app Next.js finta («gestionale volontari») con **16 difetti noti** e **5 esche**, costruita sulle classi di difetti trovate nei giri reali su due repository privati (route di servizio esposte, mass assignment, secondo fattore non verificato, header interni non ripuliti, segreti in compose e nella storia, socket Docker, redirect dopo il login…). Serve a misurare la skill senza dipendere da codice privato.

```bash
python3 tests/bench-app/score_bench.py prepare ~/prova        # crea ~/prova/bench-app con storia Git e segreti generati a caso
cd ~/prova/bench-app && <agente>: /appsec-sentinel rapido .    # audit FUORI dalla cartella dell'app
python3 tests/bench-app/score_bench.py score ~/prova/audit-A [~/prova/audit-B]
```

Il punteggio: difetti trovati su 16, difetti alti su 6, falsi allarmi sulle esche (con severità media o superiore), finding fuori elenco da valutare a mano; con più audit, tabella difetto × giro e accordo.

La verità è in `truth.json`, fuori dalla cartella copiata: non va data all'agente. Il codice non contiene commenti che indichino i difetti (lo verifica `tests/run_checks.py`).

Limiti: i difetti sono quelli che conosciamo e il riconoscimento è meccanico (file citato + parole chiave). Un buon punteggio dice che la skill trova queste classi, non che trova tutto. Il pre-passaggio deterministico porta da solo l'agente vicino a 10 dei 16 difetti; gli altri 6 richiedono di ricostruire un flusso.
