import * as dotenv from 'dotenv';

dotenv.config();  // Memuat file .env ke dalam process.env

export const jwtConstants = {
  secret: process.env.JWT_SECRET || 'defaultSecretKey',
};
