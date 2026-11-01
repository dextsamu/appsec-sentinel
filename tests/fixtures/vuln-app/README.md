# App di prova con vulnerabilità note

Applicazione **finta e piccola**, scritta apposta per collaudare le skill: ogni difetto è noto e elencato in `expected.json`.
Non è un'app da eseguire né da copiare: contiene volutamente errori. Tutti i valori sono segnaposto inventati.

| Difetto noto | Dove |
|---|---|
| Endpoint amministrativo senza autenticazione | `src/app/api/admin/users/route.ts` |
| Accesso a oggetto senza controllo di proprietà (BOLA) | `src/app/api/orders/[id]/route.ts` |
| Endpoint di debug che restituisce variabili d'ambiente | `server.js` |
| Segreto JWT scritto nel codice | `server.js` |
| Dipendenze datate | `package.json` |
| Dati personali nello schema senza cancellazione | `prisma/schema.prisma` |
| Font e SMS verso terzi non dichiarati | `src/app/layout.tsx`, `package.json` |
