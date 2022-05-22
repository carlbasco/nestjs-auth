import {
  BadRequestException,
  Injectable,
  NotFoundException
} from '@nestjs/common'
import { Prisma } from '@prisma/client'
import * as bcrypt from 'bcrypt'
import { nanoid } from 'nanoid'
import { PrismaService } from 'src/prisma.service'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserPasswordDto } from './dto/update-userPassword.dto'

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findAll(
    where?: Prisma.UserWhereInput,
    orderBy?: Prisma.UserOrderByWithRelationInput,
  ) {
    return await this.prisma.user.findMany({ where, orderBy })
  }

  async findById(id: string) {
    const query = await this.prisma.user.findUnique({ where: { id } })
    return query
  }

  async findByEmail(email: string) {
    const query = await this.prisma.user.findUnique({ where: { email } })
    return query
  }

  private async hashPassword(password: string) {
    return await bcrypt.hash(password, await bcrypt.genSalt(10))
  }

  async create(data: CreateUserDto) {
    const { email, password } = data
    const userExist = await this.findByEmail(data.email)
    if (userExist) throw new BadRequestException('User already exist')
    const hashedPassword = await this.hashPassword(password)
    const tokenKey = nanoid(15)
    await this.prisma.user.create({
      data: { email, tokenKey, password: hashedPassword },
    })
    return { message: `User Account has been created` }
  }

  async updatePassword(id: string, data: UpdateUserPasswordDto) {
    const user = await this.findById(id)
    if (!user) throw new NotFoundException('User not found')
    const newPassword = await this.hashPassword(data.confirmPassword)
    await this.prisma.user.update({
      where: { id: user.id },
      data: { password: newPassword },
    })
    return `Password has been updated!`
  }

  async delete(id: string) {
    const user = await this.findById(id)
    await this.prisma.user.delete({ where: { id: user.id } })
    return { message: `User Account has been deleted` }
  }
}
