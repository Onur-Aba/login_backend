import { PartialType } from '@nestjs/mapped-types';
import { CreateOutboxDto } from './create-outbox.dto';

export class UpdateOutboxDto extends PartialType(CreateOutboxDto) {}
