import { IsOptional, Validate } from 'class-validator';
import {
  PasswordValidation,
  PasswordValidationRequirement,
} from 'class-validator-password-check';

const passwordRequirement: PasswordValidationRequirement = {
  mustContainLowerLetter: true,
  mustContainNumber: true,
  mustContainSpecialCharacter: true,
  mustContainUpperLetter: true,
};

export class UpdateUserDto {
  @IsOptional()
  username: string;

  @IsOptional()
  @Validate(PasswordValidation, [passwordRequirement])
  password: string;
}
