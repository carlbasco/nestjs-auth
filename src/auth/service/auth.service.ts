import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { FastifyReply, FastifyRequest } from 'fastify'
import * as bcrypt from 'bcrypt'

import { UserService } from 'src/user/user.service'
import { SessionService } from './session.service'
import { JwtService } from './jwt.service'
import { LoginDto } from '../dto'

@Injectable()
export class AuthService {
  constructor(
    private jwt: JwtService,
    private userService: UserService,
    private configService: ConfigService,
    private sessionService: SessionService,
  ) {}

  private setCookie(token: string, res: FastifyReply) {
    const cookie = this.configService.get<string>('COOKIE') || 'token'
    return res.setCookie(cookie, token, {
      httpOnly: true,
      path: '/',
      domain: this.configService.get<string>('DOMAIN') || 'localhost',
      secure:
        this.configService.get('NODE_ENV') === 'production' ? true : false,
      sameSite:
        this.configService.get('NODE_ENV') === 'production' ? true : false,
    })
  }

  async login(data: LoginDto, req: FastifyRequest, res: FastifyReply) {
    const { email, password } = data
    const user = await this.userService.findByEmail(email)
    if (!user) throw new BadRequestException('Email or Password is incorrect')
    const validPassword = await bcrypt.compare(password, user.password)
    if (!validPassword)
      throw new BadRequestException('Email or Password is incorrect')
    if (!user.isActive)
      throw new BadRequestException('Your account has been banned')
    const refreshToken = this.jwt.createRefreshToken({
      id: user.id,
      tokenKey: user.tokenKey,
    })
    await this.sessionService.create(req, {
      userId: user.id,
      token: refreshToken,
    })
    this.setCookie(refreshToken, res)
    return this.jwt.createAccessToken({ id: user.id })
  }

  async logout(req: FastifyRequest, res: FastifyReply) {
    const cookie = this.configService.get<string>('COOKIE') || 'token'
    const token = req.cookies[cookie]
    if (!token) {
      res.clearCookie(cookie, {
        path: '/',
        domain: this.configService.get('DOMAIN'),
      })
      return { message: `Logout Successfully` }
    }
    const decodedToken = this.jwt.decodeRefreshToken(token)
    const session = await this.sessionService.findFirst({
      userId: decodedToken.id,
      ip: req.ip,
      token,
    })
    if (session) {
      await this.sessionService.delete(session.id)
    }
    res.clearCookie(cookie, {
      path: '/',
      domain: this.configService.get('DOMAIN'),
    })
    return { message: `Logout Successfully` }
  }

  async requestToken(req: FastifyRequest, res: FastifyReply) {
    const cookie = this.configService.get<string>('COOKIE') || 'token'
    const token = req.cookies[cookie]
    const ip = req.ip
    if (!token) throw new UnauthorizedException()
    const payload = this.jwt.verifyRefreshToken(token)
    const user = await this.userService.findById(payload.id)
    if (!user) throw new UnauthorizedException()
    if (user.tokenKey !== payload.tokenKey)
      throw new UnauthorizedException('Session Expired')
    const session = await this.sessionService.findFirst({
      ip,
      token,
      userId: user.id,
    })
    if (!session) throw new UnauthorizedException('Session Expired')
    const refreshToken = this.jwt.createRefreshToken({
      id: user.id,
      tokenKey: user.tokenKey,
    })
    await this.sessionService.update(session.id, refreshToken)
    this.setCookie(refreshToken, res)
    return this.jwt.createAccessToken({ id: user.id })
  }
}
