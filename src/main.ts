import { ValidationPipe } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { NestFactory } from '@nestjs/core'
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify'
import fastifyCookie from 'fastify-cookie'
import fastifyHelmet from 'fastify-helmet'
import { AppModule } from './app.module'
import corsOption from './config/cors.config'

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  )
  app.enableCors(corsOption)
  app.register(fastifyCookie)
  await app.register(fastifyHelmet)
  app.useGlobalPipes(new ValidationPipe())
  const configService = app.get(ConfigService)
  const port = configService.get('PORT') || 3001
  await app.listen(port)
}

bootstrap()
