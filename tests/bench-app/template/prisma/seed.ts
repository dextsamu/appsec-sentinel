import bcrypt from 'bcryptjs'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
async function main() {
  // solo sviluppo locale: npx prisma db seed
  const org = await prisma.organization.upsert({ where: { slug: 'dev' }, update: {}, create: { name: 'Dev', slug: 'dev' } })
  await prisma.user.upsert({ where: { email: 'admin@example.test' }, update: {}, create: { email: 'admin@example.test', passwordHash: await bcrypt.hash('password', 10), role: 'ADMIN', organizationId: org.id } })
}
main().finally(() => prisma.$disconnect())
