import { NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { prisma } from '@/lib/prisma'

export async function POST() {
  const org = await prisma.organization.findFirst({ where: { slug: 'sezione-principale' } })
  if (!org) return NextResponse.json({ error: 'org not found' }, { status: 404 })
  const passwordHash = await bcrypt.hash('Demo2024!', 10)
  const created = []
  for (const role of ['RESPONSABILE', 'VOLONTARIO']) {
    const u = await prisma.user.create({ data: { email: `${role.toLowerCase()}.demo@example.org`, passwordHash, role, organizationId: org.id } })
    created.push(u.email)
  }
  return NextResponse.json({ created })
}
