import { IsEmail, IsNotEmpty } from 'class-validator'
import { Match } from './match.decorator'

export class CreateUserDto {
  @IsEmail({}, { message: `invalid email` })
  @IsNotEmpty()
  email: string

  @IsNotEmpty()
  password: string

  @IsNotEmpty()
  @Match('password', { message: `password and confirm password do not match` })
  confirmPassword: string
}
