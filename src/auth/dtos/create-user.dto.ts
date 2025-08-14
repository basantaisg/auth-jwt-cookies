import { IsEmail, IsNotEmpty, MaxLength, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty({ message: 'It should contain something... not empty!' })
  @MinLength(8, { message: 'Min-length is 3' })
  @MaxLength(16, { message: 'Max-Length is 16' })
  password: string;
}
