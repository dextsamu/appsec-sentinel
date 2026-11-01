import { requireAuth } from '@/lib/session'
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await requireAuth()
  const order = await prisma.order.findUnique({ where: { id: params.id } })   // manca il controllo di proprietà (difetto noto)
  return Response.json(order)
}
