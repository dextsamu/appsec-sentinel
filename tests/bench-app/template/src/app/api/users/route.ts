import { NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { requireRole } from '@/lib/auth'
import { currentOrgId, isPlatformAdmin } from '@/lib/tenant'

export async function GET() {
  await requireRole('ADMIN', 'RESPONSABILE')
  const where = (await isPlatformAdmin()) ? {} : { organizationId: (await currentOrgId()) ?? '' }
  const users = await prisma.user.findMany({ where, select: { id: true, email: true, role: true, organizationId: true } })
  return NextResponse.json(users)
}
