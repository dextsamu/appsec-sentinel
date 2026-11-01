# Gestionale volontari

Gestione di turni, ticket e preventivi per le sezioni. Next.js 15, Prisma, PostgreSQL.

    cp .env.example .env
    docker compose up -d
    npx prisma migrate deploy && npx prisma db seed
