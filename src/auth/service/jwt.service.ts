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
      return <AccessTokenPayload>jwt.verify(token, key)
    } catch (err) {
      throw new UnauthorizedException()
    }
  }

  verifyRefreshToken(token: string) {
    try {
      const key = this.configService.get<string>('REFRESH_KEY')
      return <RefreshTokenPayload>jwt.verify(token, key)
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
    return jwt.sign(payload, key, { expiresIn })
  }

  createRefreshToken(payload: RefreshTokenPayload) {
    const expiresIn = this.configService.get<string>('REFRESH_TIME')
    const key = this.configService.get<string>('REFRESH_KEY')
    return jwt.sign(payload, key, { expiresIn })
  }
}
