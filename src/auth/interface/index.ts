export interface RefreshTokenPayload {
  id: string
  tokenKey: string
}

export interface AccessTokenPayload {
  id: string
}

export interface SessionPayload {
  userId: string
  token: string
}
