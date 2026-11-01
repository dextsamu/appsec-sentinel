import { headers } from 'next/headers'
export async function currentOrgId(): Promise<string | null> {
  return (await headers()).get('x-org-id')
}
export async function isPlatformAdmin(): Promise<boolean> {
  return (await headers()).get('x-is-admin') === 'true'
}
