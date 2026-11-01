import { jwtVerify } from 'jose'
const key = new TextEncoder().encode(process.env.SESSION_SECRET)
export async function verifySession(token?: string) {
  if (!token) return null
  try { const { payload } = await jwtVerify(token, key); return payload as { sub: string; role: string; organizationId: string } } catch { return null }
}
