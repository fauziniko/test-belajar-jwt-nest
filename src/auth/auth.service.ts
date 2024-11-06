import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async register(username: string, password: string, name: string, email: string) {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        id: uuidv4(),
        username,
        password: hashedPassword,
        name,
        email,
      },
    });

    return user;
  }

  async login(username: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Membuat token JWT
    const token = this.jwtService.sign({ username: user.username, sub: user.id });

    // Memperbarui token ke database
    await this.prisma.user.update({
      where: { id: user.id },
      data: { token },
    });

    return { token }; // Mengembalikan token
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { token: null },
    });

    return { message: 'Logged out successfully' };
  }
}
