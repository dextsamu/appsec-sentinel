import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireRole } from '@/lib/auth'

export async function DELETE(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const admin = await requireRole('ADMIN')
  const { id } = await params
  const target = await prisma.user.findFirst({ where: { id, organizationId: admin.organizationId } })
  if (!target) return NextResponse.json({ error: 'not found' }, { status: 404 })
  if (target.id === admin.id) return NextResponse.json({ error: 'cannot delete yourself' }, { status: 400 })
  await prisma.session.deleteMany({ where: { userId: id } })
  await prisma.user.delete({ where: { id } })
  return NextResponse.json({ ok: true })
}
