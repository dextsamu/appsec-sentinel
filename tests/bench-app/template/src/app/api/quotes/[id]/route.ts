import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'

export async function GET(_req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const quote = await prisma.quote.findUnique({ where: { id }, include: { organization: true } })
  if (!quote) return NextResponse.json({ error: 'not found' }, { status: 404 })
  return NextResponse.json(quote)
}
