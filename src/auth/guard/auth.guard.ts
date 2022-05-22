import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common'
import { Observable } from 'rxjs'

import { JwtService } from '../service/jwt.service'

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwt: JwtService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest()
    const accessToken = req.headers.authorization?.split(' ')[1]
    if (!accessToken) throw new UnauthorizedException()
    try {
      this.jwt.verifyAccessToken(accessToken)
    } catch (err) {
      throw new UnauthorizedException()
    }
    return true
  }
}
