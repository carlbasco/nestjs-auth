import { Injectable } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { FastifyRequest } from 'fastify'

import { PrismaService } from 'src/prisma.service'
import { SessionPayload } from '../interface'

@Injectable()
export class SessionService {
  constructor(private prisma: PrismaService) {}

  async findFirst(where: Prisma.SessionWhereInput) {
    return await this.prisma.session.findFirst({ where })
  }

  async create(payload: SessionPayload, req: FastifyRequest) {
    const { token, userId } = payload
    const ip = req.ip
    const device = req.headers['user-agent']
    return await this.prisma.session.create({
      data: { token, userId, ip, device },
    })
  }

  async update(id: number, token: string) {
    return await this.prisma.session.update({ where: { id }, data: { token } })
  }

  async delete(id: number) {
    return await this.prisma.session.delete({ where: { id } })
  }
}
