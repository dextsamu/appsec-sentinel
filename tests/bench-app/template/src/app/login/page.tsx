'use client'
import { useRouter, useSearchParams } from 'next/navigation'
import { useState } from 'react'

export default function LoginPage() {
  const router = useRouter()
  const params = useSearchParams()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    const r = await fetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
    if (r.ok) {
      const next = params.get('callbackUrl') || '/dashboard'
      window.location.href = next
    }
  }
  return (<form onSubmit={submit}><input value={email} onChange={(e) => setEmail(e.target.value)} /><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /><button>Entra</button></form>)
}
