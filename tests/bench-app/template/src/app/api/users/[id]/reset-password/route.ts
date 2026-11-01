import { NextRequest, NextResponse } from 'next/server'
import { randomBytes } from 'crypto'
import { prisma } from '@/lib/prisma'
import { requireAuth } from '@/lib/auth'
import { hasPermission } from '@/lib/permissions'
import { sendResetEmail } from '@/lib/mail'

// Solo per amministratori
export async function POST(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const me = await requireAuth()
  if (!hasPermission(me.role, 'UPDATE_USER')) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  const { id } = await params
  const target = await prisma.user.findUnique({ where: { id } })
  if (!target) return NextResponse.json({ error: 'not found' }, { status: 404 })
  const token = randomBytes(32).toString('hex')
  await prisma.session.deleteMany({ where: { userId: id } })
  await sendResetEmail(target.email, token)
  return NextResponse.json({ ok: true })
}
