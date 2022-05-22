import { Global, Module } from '@nestjs/common'

import { AuthService } from './service/auth.service'
import { AuthController } from './auth.controller'
import { UserModule } from 'src/user/user.module'
import { JwtService } from './service/jwt.service'
import { PrismaService } from 'src/prisma.service'
import { SessionService } from './service/session.service'

@Global()
@Module({
  imports: [UserModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtService,
    PrismaService,
    SessionService,
  ],
  exports: [JwtService],
})
export class AuthModule {}
