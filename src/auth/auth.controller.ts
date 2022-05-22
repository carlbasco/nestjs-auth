import { Body, Controller, Get, HttpCode, Post, Req, Res } from '@nestjs/common'
import { FastifyReply, FastifyRequest } from 'fastify'

import { AuthService } from './service/auth.service'
import { LoginDto } from './dto'

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(200)
  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: FastifyRequest,
    @Res() res: FastifyReply,
  ) {
    const data = await this.authService.login(loginDto, req, res)
    return res.send(data)
  }

  @HttpCode(200)
  @Post('logout')
  async logout(@Req() req: FastifyRequest, @Res() res: FastifyReply) {
    const data = await this.authService.logout(req, res)
    return res.send(data)
  }

  @HttpCode(200)
  @Get('token')
  async requestToken(@Req() req: FastifyRequest, @Res() res: FastifyReply) {
    const data = await this.authService.requestToken(req, res)
    return res.send(data)
  }
}
