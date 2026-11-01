import { cookies } from 'next/headers'
import { prisma } from './prisma'
import { verifySession } from './session-edge'

export class AuthError extends Error {}

export async function requireAuth() {
  const sid = (await cookies()).get('sid')?.value
  const s = await verifySession(sid)
  if (!s) throw new AuthError('unauthorized')
  const user = await prisma.user.findUnique({ where: { id: s.sub } })
  if (!user) throw new AuthError('unauthorized')
  return user
}

export async function requireRole(...roles: string[]) {
  const user = await requireAuth()
  if (!roles.includes(user.role)) throw new AuthError('forbidden')
  return user
}
