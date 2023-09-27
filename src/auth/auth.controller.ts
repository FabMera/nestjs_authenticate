import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';
import { AuthGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {
    }

    @Post()
    create(@Body() createUserDto: CreateUserDto) {
        return this.authService.create(createUserDto);
    }

    @Post('/login')
    login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('/register')
    register(@Body() registerDto: RegisterUserDto) {
        return this.authService.register(registerDto);
    }

    @Get()
    @UseGuards(AuthGuard)
    findAll() {
        return this.authService.findAll();
    }

    // LoginResponse
    @Get(':id')
    findOne(@Param('id') id: string) {
        return this.authService.findUserById(id);
    }

    @Get('/email/:email')
    findOneByEmail(@Param('email') email: string) {
        return this.authService.findOne(email);
    }

    // @Patch(':id')
    // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    //   return this.authService.update(+id, updateAuthDto);
    // }
    // @Delete(':id')
    // remove(@Param('id') id: string) {
    //   return this.authService.remove(+id);
    // }
}
