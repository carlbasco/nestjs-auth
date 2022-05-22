import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common'
import { AuthGuard } from 'src/auth/guard/auth.guard'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserPasswordDto } from './dto/update-userPassword.dto'
import { UserService } from './user.service'

@Controller('api/user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto)
  }

  @Get()
  @UseGuards(AuthGuard)
  findAll() {
    return this.userService.findAll()
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findById(id)
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updatePasswordDto: UpdateUserPasswordDto,
  ) {
    return this.userService.updatePassword(id, updatePasswordDto)
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.delete(id)
  }
}
