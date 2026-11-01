import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { SignJWT } from 'jose'
import { prisma } from '@/lib/prisma'
import { getClientIp } from '@/lib/client-ip'
import { limited } from '@/lib/rate-limit'

const key = new TextEncoder().encode(process.env.SESSION_SECRET)

export async function POST(req: NextRequest) {
  const ip = getClientIp(req)
  if (limited(`login:${ip}`)) return NextResponse.json({ error: 'too many attempts' }, { status: 429 })
  const { email, password } = await req.json()
  const user = await prisma.user.findUnique({ where: { email } })
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return NextResponse.json({ error: 'invalid credentials' }, { status: 401 })
  }
  if (!user.isActive) return NextResponse.json({ error: 'account disabled' }, { status: 403 })
  if ((user.role === 'ADMIN' || user.role === 'RESPONSABILE') && !user.mfaEnabled) {
    return NextResponse.json({ error: 'mfa setup required', next: '/settings/mfa' }, { status: 403 })
  }
  const token = await new SignJWT({ role: user.role, organizationId: user.organizationId })
    .setProtectedHeader({ alg: 'HS256' }).setSubject(user.id).setExpirationTime('30d').sign(key)
  const res = NextResponse.json({ ok: true })
  res.cookies.set('sid', token, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' })
  return res
}
