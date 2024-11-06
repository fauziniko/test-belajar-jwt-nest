import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async register(username: string, password: string, name: string, email: string) {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Membuat user baru di database
    const user = await this.prisma.user.create({
      data: { username, password: hashedPassword, name, email },
    });

    // Membuat token JWT
    const token = this.jwtService.sign({ username: user.username, sub: user.id });

    // Memperbarui user dengan token yang baru dibuat
    await this.prisma.user.update({
      where: { id: user.id },
      data: { token },
    });

    // Mengembalikan user beserta token
    return { ...user, token };
  }

  async login(username: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const token = this.jwtService.sign({ username: user.username, sub: user.id });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { token },
    });

    return { token };
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { token: null },
    });
    return { message: 'Logged out successfully' };
  }
}
