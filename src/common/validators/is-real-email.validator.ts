import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
  registerDecorator,
  ValidationOptions,
} from 'class-validator';
import { promises as dns } from 'dns';

@ValidatorConstraint({ async: true })
export class IsRealEmailDomainConstraint implements ValidatorConstraintInterface {
  async validate(email: string, args: ValidationArguments) {
    if (!email || !email.includes('@')) return false;

    const domain = email.split('@')[1];
    try {
      // DNS üzerinden domainin Mail Exchange (MX) kayıtlarını sorguluyoruz
      const records = await dns.resolveMx(domain);
      return records && records.length > 0;
    } catch (error) {
      // Domain yoksa veya MX kaydı bulunamazsa false döner
      return false;
    }
  }

  defaultMessage(args: ValidationArguments) {
    return 'Bu e-posta adresinin alan adı (domain) geçersiz veya mail kabul etmiyor.';
  }
}

// Bu dekoratörü DTO'larda kullanacağız
export function IsRealEmail(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsRealEmailDomainConstraint,
    });
  };
}