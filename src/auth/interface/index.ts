export interface RefreshTokenPayload {
  id: string
}

export interface AccessTokenPayload {
  id: string
}

export interface SessionPayload {
  userId: string
  token: string
}
