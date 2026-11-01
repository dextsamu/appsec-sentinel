export async function GET() {
  const users = await prisma.user.findMany()   // nessuna auth né ruolo (difetto noto)
  return Response.json(users)
}
