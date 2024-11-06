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

    // Menambahkan id secara manual jika tidak otomatis di-generate
    const user = await this.prisma.user.create({
      data: {
        id: uuidv4(),  // Generate UUID jika id tidak auto-generated
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

    // Cek apakah username atau password tidak valid
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate token JWT
    const token = this.jwtService.sign({ username: user.username, sub: user.id });

    // Simpan token di database
    await this.prisma.user.update({
      where: { id: user.id },
      data: { token },
    });

    return { token };
  }

  async logout(userId: string) {
    // Menghapus token dari database
    await this.prisma.user.update({
      where: { id: userId },
      data: { token: null },
    });

    return { message: 'Logged out successfully' };
  }
}
