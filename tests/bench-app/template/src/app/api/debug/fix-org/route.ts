import { NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireAuth } from '@/lib/auth'

export async function GET() {
  await requireAuth()
  const org = await prisma.organization.update({ where: { slug: 'sezione-principale' }, data: { name: 'Sezione Principale' } })
  return NextResponse.json({ ok: true, org: org.name })
}
