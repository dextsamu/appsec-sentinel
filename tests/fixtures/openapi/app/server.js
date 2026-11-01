const express = require('express'); const app = express();
app.get('/api/orders/:id', requireAuth, (q,r)=>r.json({}));
app.get('/api/health', (q,r)=>r.json({}));
app.get('/api/secret-debug', (q,r)=>r.json({}));
