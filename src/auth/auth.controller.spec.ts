import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from 'nestjs-pino';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { CreateNewUser } from './dto/create-new-user.dto';
import { ResendVerification } from './dto/resend-verification.dto';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: { register: jest.Mock; resendVerifyEmail: jest.Mock; verifyEmail: jest.Mock };
  let logger: { log: jest.Mock };

  beforeEach(async () => {
    authService = {
      register: jest.fn(),
      resendVerifyEmail: jest.fn(),
      verifyEmail: jest.fn(),
    };
    logger = { log: jest.fn() };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: authService,
        },
        {
          provide: Logger,
          useValue: logger,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('calls authService.register with the request body and returns its result unchanged', async () => {
      const body: CreateNewUser = {
        firstName: 'Jane',
        lastName: 'Doe',
        displayName: 'JaneD',
        email: 'jane@example.com',
        password: 'Sup3r$ecret!',
      };
      const serviceResult = {
        success: true,
        data: { id: 'user-1' },
        emailStatus: 'QUEUED',
        message: 'Account created successfully. Please verify your email to continue.',
      };
      authService.register.mockResolvedValue(serviceResult);

      const result = await controller.register(body);

      expect(authService.register).toHaveBeenCalledTimes(1);
      expect(authService.register).toHaveBeenCalledWith(body);
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.register without swallowing or transforming them', async () => {
      const body: CreateNewUser = {
        firstName: 'Jane',
        lastName: 'Doe',
        displayName: 'JaneD',
        email: 'jane@example.com',
        password: 'Sup3r$ecret!',
      };
      const error = new Error('registration failed');
      authService.register.mockRejectedValue(error);

      await expect(controller.register(body)).rejects.toBe(error);
    });
  });

  describe('resendVerifyEmail', () => {
    it('calls authService.resendVerifyEmail with the email from the body and returns its result unchanged', async () => {
      const body: ResendVerification = { email: 'jane@example.com' };
      const serviceResult = { success: true, message: 'generic response' };
      authService.resendVerifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.resendVerifyEmail(body);

      expect(authService.resendVerifyEmail).toHaveBeenCalledTimes(1);
      expect(authService.resendVerifyEmail).toHaveBeenCalledWith(body.email);
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.resendVerifyEmail without swallowing or transforming them', async () => {
      const body: ResendVerification = { email: 'jane@example.com' };
      const error = new Error('resend failed');
      authService.resendVerifyEmail.mockRejectedValue(error);

      await expect(controller.resendVerifyEmail(body)).rejects.toBe(error);
    });
  });

  describe('verifyEmail', () => {
    it('passes the raw token (and tokenId) from the query params to authService.verifyEmail and returns its result unchanged', async () => {
      const params = { tokenId: 'token-id-1', rawToken: 'raw-token-value' };
      const serviceResult = { message: 'Email verified successfully' };
      authService.verifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.verifyEmail(params);

      expect(authService.verifyEmail).toHaveBeenCalledTimes(1);
      expect(authService.verifyEmail).toHaveBeenCalledWith(params);
      expect(result).toBe(serviceResult);
    });

    it('passes the raw token through even when tokenId is not provided', async () => {
      const params = { rawToken: 'raw-token-only' };
      const serviceResult = { message: 'Email verified successfully' };
      authService.verifyEmail.mockResolvedValue(serviceResult);

      const result = await controller.verifyEmail(params);

      expect(authService.verifyEmail).toHaveBeenCalledWith(params);
      expect(authService.verifyEmail.mock.calls[0][0].rawToken).toBe('raw-token-only');
      expect(result).toBe(serviceResult);
    });

    it('propagates errors thrown by authService.verifyEmail without swallowing or transforming them', async () => {
      const params = { rawToken: 'raw-token-value' };
      const error = new Error('Invalid verification token');
      authService.verifyEmail.mockRejectedValue(error);

      await expect(controller.verifyEmail(params)).rejects.toBe(error);
    });
  });
});
