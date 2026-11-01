// FIXTURE: difetti volutamente presenti. Valori inventati.
const express = require('express')
const cron = require('node-cron')
const app = express()
const JWT_SECRET = 'changeme-fixture-secret-0000'   // segreto nel codice (difetto noto)

app.get('/api/debug/env', (req, res) => res.json(process.env))   // nessuna auth (difetto noto)
app.get('/api/products', requireAuth, (req, res) => res.json([]))
app.post('/api/login', (req, res) => res.json({ token: sign(req.body, JWT_SECRET) }))

cron.schedule('0 3 * * *', async () => {
  const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)
  await prisma.accessLog.deleteMany({ where: { createdAt: { lt: cutoff } } })
})
app.listen(3000)
