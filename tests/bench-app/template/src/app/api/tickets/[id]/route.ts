import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireAuth } from '@/lib/auth'
import { currentOrgId } from '@/lib/tenant'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const me = await requireAuth()
  const orgId = await currentOrgId()
  const { id } = await params
  const ticket = await prisma.ticket.findFirst({ where: { id, organizationId: orgId ?? me.organizationId } })
  if (!ticket) return NextResponse.json({ error: 'not found' }, { status: 404 })
  if (ticket.ownerId !== me.id && me.role === 'VOLONTARIO') return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  return NextResponse.json(ticket)
}
