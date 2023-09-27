import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
    constructor(
      @InjectModel(User.name)
      private userModel: Model<User>,
      private jwtService: JwtService,
    ) {
    }

    //Metodo para crear un usuario
    async create(createUserDto: CreateUserDto): Promise<User> {
        try {
            const { password, ...userData } = createUserDto;
            const newUser = new this.userModel({
                password: bcryptjs.hashSync(password, 10),
                ...userData,
            });
            await newUser.save();
            const { password: _, ...user } = newUser.toJSON();
            return user;
        } catch (error) {
            if (error.code === 11000) {
                throw new BadRequestException(`${createUserDto.email} already exists!`);
            }
            throw new InternalServerErrorException('Something terribe happen!!!');
        }
    }

    //Metodo para registrarse
    async register(registerDto: RegisterUserDto): Promise<LoginResponse> {
        const user = await this.create(registerDto);
        return {
            user: user,
            token: this.getJwtToken({ id: user._id }),
        };
    }

    //Metodo para loguearse
    async login(loginDto: LoginDto): Promise<LoginResponse> {
        const { email, password } = loginDto;
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new UnauthorizedException('Not valid credentials - email');
        }
        if (!bcryptjs.compareSync(password, user.password)) {
            throw new UnauthorizedException('Not valid credentials - password');
        }
        const { password: _, ...rest } = user.toJSON();
        return {
            user: rest,
            token: this.getJwtToken({ id: user.id }),
        };
    }

    //Metodo para obtener todos los usuarios
    async findAll(): Promise<User[]> {
        return await this.userModel.find();
    }
    //Metodo para obtener un usuario por id
    async findUserById(id: string) {
        const user = await this.userModel.findOne({ _id: id });
        if(!user){
            throw new BadRequestException(`User with id ${id} not found`);
        }
        return {
            name:user.name,
            email:user.email,
            id:user._id
        }
    }
    //Metodo para obtener un usuario por email
    async findOne(email: string) {
       const user = await this.userModel.findOne({email});
       if(!user){
           throw new BadRequestException(`User with email ${email} not found`);
       }

       return {
            name:user.name,
            email:user.email,
            id:user._id
       }
    }
    //Metodo para actualizar un usuario
    update(id: number, updateAuthDto: UpdateAuthDto) {
        return `This action updates a #${id} auth`;
    }
    //Metodo para eliminar un usuario
    remove(id: number) {
        return `This action removes a #${id} auth`;
    }
    //Metodo para obtener el token
    getJwtToken(payload: JwtPayload) {
        const token = this.jwtService.sign(payload);
        return token;
    }
}
