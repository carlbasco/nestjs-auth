import { Injectable, UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import * as jwt from 'jsonwebtoken'

import { AccessTokenPayload, RefreshTokenPayload } from '../interface'

@Injectable()
export class JwtService {
  constructor(private configService: ConfigService) {}

  verifyAccessToken(token: string) {
    try {
      const key = this.configService.get<string>('ACCESS_KEY')
      const accessToken = <AccessTokenPayload>jwt.verify(token, key)
      return accessToken
    } catch (err) {
      throw new UnauthorizedException()
    }
  }

  verifyRefreshToken(token: string) {
    try {
      const key = this.configService.get<string>('REFRESH_KEY')
      const refreshToken = <RefreshTokenPayload>jwt.verify(token, key)
      return refreshToken
    } catch (err) {
      if (err.message === 'jwt expired')
        throw new UnauthorizedException('Session Expired')
      throw new UnauthorizedException()
    }
  }

  decodeAccessToken(token: string) {
    return <AccessTokenPayload>jwt.decode(token)
  }

  decodeRefreshToken(token: string) {
    return <RefreshTokenPayload>jwt.decode(token)
  }

  createAccessToken(payload: AccessTokenPayload) {
    const key = this.configService.get<string>('ACCESS_KEY')
    const expiresIn = this.configService.get<string>('ACCESS_TIME')
    const token = jwt.sign(payload, key, { expiresIn })
    return token
  }

  createRefreshToken(payload: RefreshTokenPayload) {
    const expiresIn = this.configService.get<string>('REFRESH_TIME')
    const key = this.configService.get<string>('REFRESH_KEY')
    const token = jwt.sign(payload, key, { expiresIn })
    return token
  }
}
