import { NextRequest, NextResponse } from 'next/server'
import { verifySession } from '@/lib/session-edge'

const PUBLIC = ['/login', '/api/auth', '/api/health', '/api/quotes', '/api/internal/demo-seed']

export async function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname
  const headers = new Headers(req.headers)
  if (PUBLIC.some((p) => path.startsWith(p))) {
    return NextResponse.next({ request: { headers } })
  }
  const session = await verifySession(req.cookies.get('sid')?.value)
  if (!session) {
    return path.startsWith('/api/') ? NextResponse.json({ error: 'unauthorized' }, { status: 401 }) : NextResponse.redirect(new URL('/login', req.url))
  }
  if (session.organizationId) headers.set('x-org-id', session.organizationId)
  if (session.role === 'ADMIN') headers.set('x-is-admin', 'true')
  return NextResponse.next({ request: { headers } })
}

export const config = { matcher: ['/((?!_next|favicon.ico).*)'] }
