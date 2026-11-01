import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireRole } from '@/lib/auth'

export async function POST(req: NextRequest) {
  const admin = await requireRole('ADMIN')
  const { email, role } = await req.json()
  if (!['ADMIN', 'RESPONSABILE', 'VOLONTARIO'].includes(role)) return NextResponse.json({ error: 'invalid role' }, { status: 400 })
  const user = await prisma.user.create({ data: { email, role, passwordHash: '!', organizationId: admin.organizationId } })
  return NextResponse.json({ id: user.id })
}
