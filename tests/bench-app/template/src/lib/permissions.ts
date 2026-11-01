export type Action = 'READ_USER' | 'UPDATE_USER' | 'DELETE_USER' | 'READ_TICKET'
const matrix: Record<string, Action[]> = {
  ADMIN: ['READ_USER', 'UPDATE_USER', 'DELETE_USER', 'READ_TICKET'],
  RESPONSABILE: ['READ_USER', 'UPDATE_USER', 'READ_TICKET'],
  VOLONTARIO: ['READ_USER', 'UPDATE_USER', 'READ_TICKET'],
}
export function hasPermission(role: string, action: Action) {
  return (matrix[role] ?? []).includes(action)
}
