import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireRole, requireAuth } from '@/lib/auth'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const me = await requireAuth()
  const { id } = await params
  const user = await prisma.user.findFirst({ where: { id, organizationId: me.organizationId }, select: { id: true, email: true, role: true } })
  return user ? NextResponse.json(user) : NextResponse.json({ error: 'not found' }, { status: 404 })
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const me = await requireAuth()
  const { id } = await params
  if (me.id !== id && me.role !== 'ADMIN' && me.role !== 'RESPONSABILE') {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  }
  const body = await req.json()
  const updated = await prisma.user.update({ where: { id }, data: { ...body } })
  return NextResponse.json({ id: updated.id })
}
