const hits = new Map<string, { n: number; t: number }>()
export function limited(key: string, max = 5, windowMs = 15 * 60_000) {
  const now = Date.now()
  const h = hits.get(key)
  if (!h || now - h.t > windowMs) { hits.set(key, { n: 1, t: now }); return false }
  h.n += 1
  return h.n > max
}
