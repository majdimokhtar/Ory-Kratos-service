integrates users with Ory Kratos

Project Overview


This project integrates users with Ory Kratos for identity and user management. Below is a detailed breakdown of the integration.

### Configuration
**Configuration Files:**
- The configuration for Ory Kratos is likely set in environment variables and accessed via the `ConfigService`.

### Services
**Infrastructure Service:**
- **UsersService**: Interacts with Ory Kratos via the `IdentityApi` from the `@ory/client` package.
- **Defined in**: `users.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Configuration, IdentityApi, JsonPatch } from '@ory/client';
import { User } from 'src/core/domain/models/user.model';
import { userDataEntityToDomain } from './datasource/mappers/users.mapper';

@Injectable()
export class UsersService {
  private identityApi: IdentityApi;

  constructor(config: ConfigService) {
    this.identityApi = new IdentityApi(
      new Configuration({
        basePath: config.get('AUTH_ADMIN_BASE_PATH'),
      }),
    );
  }

  async create(user: User, password: string): Promise<User> {
    const { data: userData } = await this.identityApi.createIdentity({
      createIdentityBody: {
        schema_id: 'default',
        traits: {
          email: user.email,
          name: {
            first: user.firstName,
            last: user.lastName,
          },
        },
        metadata_public: {
          role: user.role,
        },
        credentials: {
          password: {
            config: {
              password,
            },
          },
        },
        state: 'active',
      },
    });
    return userDataEntityToDomain({
      email: userData.traits.email,
      firstName: userData.traits.name.first,
      lastName: userData.traits.name.last,
      id: userData.id,
      role: userData.metadata_public?.['role'],
      acceptedTermsVersion: userData.metadata_public?.['acceptedTermsVersion'],
    });
  }

  async findById(userId: string): Promise<User> {
    const { data: userData } = await this.identityApi.getIdentity({ id: userId });
    return userData
      ? userDataEntityToDomain({
          email: userData.traits.email,
          firstName: userData.traits.name.first,
          lastName: userData.traits.name.last,
          id: userData.id,
          role: userData.metadata_public?.['role'],
          acceptedTermsVersion: userData.metadata_public?.['acceptedTermsVersion'],
        })
      : null;
  }

  async update(userId: string, user: User): Promise<User> {
    const jsonPatch: JsonPatch[] = [
      { op: 'replace', path: '/traits/name/first', value: user.firstName },
      { op: 'replace', path: '/traits/name/last', value: user.lastName },
      { op: 'replace', path: '/metadata_public/role', value: user.role },
      {
        op: 'replace',
        path: '/metadata_public/acceptedTermsVersion',
        value: user.acceptedTermsVersion,
      },
      {
        op: 'replace',
        path: '/state',
        value: user.isDisabled ? 'inactive' : 'active',
      },
    ];
    const { data: userData } = await this.identityApi.patchIdentity({
      id: userId,
      jsonPatch,
    });
    return userDataEntityToDomain({
      email: userData.traits.email,
      firstName: userData.traits.name.first,
      lastName: userData.traits.name.last,
      id: userData.id,
      role: userData.metadata_public?.['role'],
      acceptedTermsVersion: userData.metadata_public?.['acceptedTermsVersion'],
    });
  }

  async getRecoveryLink(userId: string): Promise<string> {
    const { data: recoveryLink } = await this.identityApi.createRecoveryLinkForIdentity({
      createRecoveryLinkForIdentityBody: {
        identity_id: userId,
      },
    });
    return recoveryLink.recovery_link;
  }
}
```

### Domain Models
**User Model:**
- **Defined in**: `user.model.ts`

```typescript
import { UnprocessableEntityException } from 'src/core/domain/exceptions/unprocessable-entity.exception';
import { Role } from '../types/role.type';

export class User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  isDisabled: boolean;
  acceptedTermsVersion: string;

  constructor(data: Partial<User>) {
    if (!data?.id) throw new UnprocessableEntityException('user id is required');
    this.id = data.id;
    this.firstName = data.firstName;
    this.lastName = data.lastName;
    this.email = data.email;
    this.role = data.role ?? Role.USER;
    this.isDisabled = data.isDisabled ?? false;
    this.acceptedTermsVersion = data.acceptedTermsVersion;
  }

  static create(data: {
    id: string;
    email: string;
    role: Role;
    firstName: string;
    lastName: string;
  }): User {
    const userEmail = data.email.toLowerCase();
    const user = new User({ ...data, email: userEmail });
    return user;
  }

  updateFullName(fullName: { firstName: string; lastName: string }): void {
    this.firstName = fullName.firstName;
    this.lastName = fullName.lastName;
  }

  enable(): void {
    this.isDisabled = false;
  }

  disable(): void {
    this.isDisabled = true;
  }
}
```

### Application Services
**Application Service:**
- **UsersService**: Uses the `UsersRepository` to interact with the infrastructure service.
- **Defined in**: `users.service.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { User } from 'src/core/domain/models/user.model';
import { UsersRepository } from 'src/infrastructure/datasource/repositories/users.repository';
import { CreateUserCommand } from '../commands/users/create-user-command';
import { UnprocessableEntityException } from 'src/core/domain/exceptions/unprocessable-entity.exception';
import { UpdateUserFullNameCommand } from '../commands/users/update-user-command';
import { UpdateUserStateCommand } from '../commands/users/update-user-state-command';
import { NotFoundException } from 'src/core/domain/exceptions/not-found.exception';
import { EditUserCommand } from '../commands/users/edit-user.command';
import { v4 as uuid } from 'uuid';

@Injectable()
export class UsersService {
  constructor(private usersRepository: UsersRepository) {}

  async create(command: CreateUserCommand): Promise<User> {
    if (!command.email) throw new UnprocessableEntityException('user email is required');
    if (!command.firstName) throw new UnprocessableEntityException('user first name is required');
    if (!command.lastName) throw new UnprocessableEntityException('user last name is required');
    if (!command.password) throw new UnprocessableEntityException('user password is required');
    const userId = uuid();
    const user = User.create({
      id: userId,
      firstName: command.firstName,
      lastName: command.lastName,
      email: command.email,
      role: command.role,
    });
    return this.usersRepository.create(user, command.password);
  }

  async updateCurrentUserFullName(command: UpdateUserFullNameCommand): Promise<User> {
    if (!command.userId) throw new UnprocessableEntityException('user id is required');
    if (!command.firstName) throw new UnprocessableEntityException('user first name is required');
    if (!command.lastName) throw new UnprocessableEntityException('user last name is required');
    const user = await this.usersRepository.findById(command.userId);
    if (!user) throw new NotFoundException('user does not exist');
    user.updateFullName({
      firstName: command.firstName,
      lastName: command.lastName,
    });
    return this.usersRepository.update(user.id, user);
  }

  async edit(command: EditUserCommand): Promise<User> {
    if (!command.userId) throw new UnprocessableEntityException('user id is required');
    if (!command.firstName) throw new UnprocessableEntityException('user first name is required');
    if (!command.lastName) throw new UnprocessableEntityException('user last name is required');
    const user = await this.usersRepository.findById(command.userId);
    user.update(
      {
        firstName: command.firstName,
        lastName: command.lastName,
      },
      command.role,
    );
    return this.usersRepository.update(user.id, user);
  }

  async enableUser(command: UpdateUserStateCommand): Promise<User> {
    if (!command.userId) throw new UnprocessableEntityException('user id is required');
    const user = await this.usersRepository.findById(command.userId);
    if (!user) throw new NotFoundException('user does not exist');
    user.enable();
    return this.usersRepository.update(user.id, user);
  }

  async disableUser(command: UpdateUserStateCommand): Promise<User> {
    if (!command.userId) throw new UnprocessableEntityException('user id is required');
    const user = await this.usersRepository.findById(command.userId);
    if (!user) throw new NotFoundException('user does not exist');
    user.disable();
    return this.usersRepository.update(user.id, user);
  }

  async getRecoveryLink(userId: string): Promise<string> {
    if (!userId) throw new UnprocessableEntityException('user id is required');
    const user = await this.usersRepository.findById(userId);
    if (!user) throw new NotFoundException('user does not exist');
    return this.usersRepository.getRecoveryLink(user.id);
  }
}
```

### Repositories
**Repository:**
- **UsersRepository**: Interacts with the `UsersService` in the infrastructure layer.
- **Defined in**: `users.repository.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { User } from 'src/core/domain/models/user.model';
import { UsersService } from 'src/infrastructure/users.service';

@Injectable()
export class UsersRepository {
  constructor(private usersService: UsersService) {}

  async create(user: User, password: string): Promise<User> {
    return this.usersService.create(user, password);
  }

  async findById(userId: string): Promise<User> {
    return this.usersService.findById(userId);
  }

  async update(userId: string, user: User): Promise<User> {
    return this.usersService.update(userId, user);
  }

  async getRecoveryLink(userId: string): Promise<string> {
    return this.usersService.getRecoveryLink(userId);
  }
}
```

### Controllers
**API Controller:**
- **UsersController**: Handles HTTP requests and uses the `UsersService` from the application layer.
- **Defined in**: `users.controller.ts`

```typescript
import { Body, Controller, Get, Param, Patch, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { UsersService } from 'src/core/application/services/users.service';
import { CreateUserCommand } from 'src/core/application/commands/users/create-user-command';
import { UsersQuery } from 'src/infrastructure/queries/users.query';
import { Role } from 'src/core/domain/types/role.type';
import { AuthenticatedUser } from '../auth/user.decorator';
import { UpdateUserFullNameDto } from '../models/users/update-user-full-name.dto';
import { UpdateUserFullNameCommand } from 'src/core/application/commands/users/update-user-command';
import { UpdateUserStateCommand } from 'src/core/application/commands/users/update-user-state-command';
import { UpdateUserStateDto } from '../models/users/update-user-state.dto';
import { EditUserCommand } from 'src/core/application/commands/users/edit-user.command';
import { EditUserDto } from '../models/users/edit-user.dto';
import { Authorize } from '../auth/auth.decorator';
import { CreateUserDto } from '../models/users/create-user.dto';
import { DisplayUserDto } from '../models/users/display-user.dto';
import { User } from 'src/core/domain/models/user.model';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private usersQuery: UsersQuery,
  ) {}

  @Authorize(Role.ADMIN)
  @Post()
  async create(@Body() dto: CreateUserDto): Promise<DisplayUserDto> {
    const command: CreateUserCommand = {
      email: dto.email,
      firstName: dto.firstName,
      lastName: dto.lastName,
      password: dto.password,
      role: dto.role,
    };
    return this.usersService.create(command);
  }

  @Authorize()
  @Get()
  async find(): Promise<DisplayUserDto[]> {
    return this.usersQuery.find();
  }

  @Authorize()
  @Get('/me')
  async findCurrentUser(@AuthenticatedUser() user): Promise<DisplayUserDto> {
    return this.usersQuery.findOne(user.id);
  }

  @Authorize()
  @Patch('/updateFullName')
  async updateCurrentUserFullName(
    @AuthenticatedUser() user,
    @Body() dto: UpdateUserFullNameDto,
  ) {
    const command: UpdateUserFullNameCommand = {
      userId: user.id,
      firstName: dto.firstName,
      lastName: dto.lastName,
    };
    return this.usersService.updateCurrentUserFullName(command);
  }

  @Authorize()
  @Patch('/edit')
  async editUser(@Body() dto: EditUserDto) {
    const command: EditUserCommand = {
      userId: dto.userId,
      firstName: dto.firstName,
      lastName: dto.lastName,
      role: dto.role,
    };
    return this.usersService.edit(command);
  }

  @Authorize()
  @Patch('/enableUser')
  async enableUser(@Body() dto: UpdateUserStateDto) {
    const command: UpdateUserStateCommand = {
      userId: dto.userId,
    };
    return this.usersService.enableUser(command);
  }

  @Authorize()
  @Patch('/disableUser')
  async disableUser(@Body() dto: UpdateUserStateDto) {
    const command: UpdateUserStateCommand = {
      userId: dto.userId,
    };
    return this.usersService.disableUser(command);
  }

  @Authorize()
  @Post('/get-recovery-link')
  async getRecoveryLink(@AuthenticatedUser() user: User) {
    return this.usersService.getRecoveryLink(user.id);
  }
}
```

### Queries
**Queries:**
- **UsersQuery**: Used to fetch user data.
- **Defined in**: `users.query.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Configuration, IdentityApi } from '@ory/client';
import { User } from 'src/core/domain/models/user.model';

@Injectable()
export class UsersQuery {
  private identityApi: IdentityApi;

  constructor(config: ConfigService) {
    this.identityApi = new IdentityApi(
      new Configuration({
        basePath: config.get('AUTH_ADMIN_BASE_PATH'),
      }),
    );
  }

  async find(ids?: string[]): Promise<User[]> {
    if (ids && ids.length === 0) return [];
    const { data } = await this.identityApi.listIdentities({ ids });
    let users = data.map(
      (u) =>
        new User({
          email: u.traits.email,
          id: u.id,
          isDisabled: u.state === 'inactive',
          firstName: u.traits.name.first,
          lastName: u.traits.name.last,
          role: u.metadata_public?.['role'],
          acceptedTermsVersion: u.metadata_public?.['acceptedTermsVersion'],
        }),
    );
    if ((ids?.length ?? 0) > 0) users = users.filter((u) => ids.includes(u.id));
    return users;
  }

  async findOne(id: string): Promise<User> {
    const { data } = await this.identityApi.getIdentity({ id });
    return new User({
      email: data.traits.email,
      firstName: data.traits.name.first,
      lastName: data.traits.name.last,
      id: data.id,
      role: data.metadata_public?.['role'],
      acceptedTermsVersion: data.metadata_public?.['acceptedTermsVersion'],
    });
  }
}
```

### Summary
To replicate this integration:
1. Set up Ory Kratos and configure it with the necessary schemas and endpoints.
2. Configure environment variables for Ory Kratos in your application.
3. Implement the `UsersService` in the infrastructure layer to interact with Ory Kratos using the `IdentityApi`.
4. Define the `User` domain model to represent user data.
5. Create application services to handle user-related business logic.
6. Implement repositories to abstract the interaction with the infrastructure service.
7. Create controllers to handle HTTP requests and use the application services.
8. Implement query classes to fetch user data from Ory Kratos.

By following these steps, you can replicate the integration of users with Ory Kratos in your project.

---
