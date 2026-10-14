import type { NextFunction, Request, RequestHandler, Response, Router } from "express";
import type { Knex } from "knex";

/** Ordered privilege ladder, lowest first, e.g. ["user", "support", "admin"]. */
export type Roles = readonly string[];

export interface AuditEvent {
  action: string;
  userId?: string | number | null;
  status?: "success" | "failure" | "pending" | string;
  ip?: string;
  email?: string;
  meta?: Record<string, unknown>;
}

export interface Logger {
  info?(...args: unknown[]): void;
  warn?(...args: unknown[]): void;
  error?(...args: unknown[]): void;
  debug?(...args: unknown[]): void;
  log?(...args: unknown[]): void;
}

export interface UserRecord {
  id: string | number;
  email: string;
  password?: string;
  role?: string | null;
  mfa_enabled?: boolean | number | null;
  tenant_id?: string | null;
  failed_login_attempts?: number | null;
  locked_until?: Date | string | null;
  [column: string]: unknown;
}

export interface UserRepository {
  getById(id: string | number): Promise<UserRecord | null | undefined>;
  update(id: string | number, data: Record<string, unknown>): Promise<unknown>;
  delete(id: string | number): Promise<unknown>;
}

export interface TokenBlacklistEntry {
  token: string;
  userId: string | number;
  tokenType: "access" | "refresh";
  expiresAt: Date;
  reason: string;
  ip?: string;
}

export interface LockoutPolicy {
  maxAttempts: number;
  /** Minutes, or a duration string such as "15m", "2h", "1d". */
  duration: number | string;
}

export interface RateLimitOptions {
  windowMs?: number;
  max?: number;
}

export type HandlerChain = RequestHandler[];
export type Override = RequestHandler | RequestHandler[];

export interface IamConfig {
  // Required
  db: Knex;
  tokenService: TokenService;
  userRepo: UserRepository;

  // Infrastructure
  redis?: { del(key: string): Promise<unknown> };
  logger?: Logger;
  overrides?: Partial<Record<HandlerName, Override>>;
  rbacMiddleware?: RequestHandler;
  roles?: Roles;
  getRole?: (userId: string | number) => Promise<string | null | undefined>;
  strictTokenType?: boolean;
  rateLimits?: Partial<Record<HandlerName | "me", RateLimitOptions>>;
  defaultTenantId?: string;

  // Registration
  allowRegistration?: boolean | (() => boolean | Promise<boolean>);
  requireAdminApproval?: boolean | (() => boolean | Promise<boolean>);
  registerSchema?: import("joi").ObjectSchema;
  resolveTenantId?: (req: Request) => string | null | undefined | Promise<string | null | undefined>;
  extraUserFields?: (data: Record<string, unknown>, req: Request) => Record<string, unknown> | Promise<Record<string, unknown>>;
  onUserCreated?: (user: { id: string | number; email: string; role: string; tenant_id: string }, ctx: { data: Record<string, unknown>; req: Request }) => void | Promise<void>;

  // Login
  lockout?: false | LockoutPolicy | (() => LockoutPolicy | null | undefined | Promise<LockoutPolicy | null | undefined>);
  checkAccountState?: (
    user: UserRecord,
    ctx: { audit: (event: AuditEvent) => void; phase: "login" | "refresh" },
  ) => void | Promise<void>;
  onLoginSuccess?: (user: UserRecord, req: Request) => void | Promise<void>;
  requireMfaForAdmins?: (user: UserRecord) => boolean | Promise<boolean>;

  // Password and MFA
  verifyMfa?: (userId: string | number, code: string) => Promise<{ verified: boolean }>;
  extraPasswordUpdateFields?: (userId: string | number, trx: Knex.Transaction) => Record<string, unknown> | Promise<Record<string, unknown>>;
  onPasswordChanged?: (userId: string | number, ctx: { trx: Knex.Transaction }) => void | Promise<void>;
  onPasswordResetRequested?: (args: { email: string; userName: string; resetToken: string; expiresIn: string }) => void | Promise<void>;
  onPasswordReset?: (args: { email: string; userName: string }) => void | Promise<void>;

  // Profile and /me
  meFields?: readonly string[];
  profile?: {
    updatableFields?: readonly string[];
    canAccessOtherUsers?: (req: Request, targetId: string | number) => boolean | Promise<boolean>;
  };

  // Observability and sessions
  onAudit?: (event: AuditEvent) => void | Promise<void>;
  tokenBlacklist?: { add(entry: TokenBlacklistEntry): Promise<unknown> };
}

export type HandlerName =
  | "me"
  | "login"
  | "register"
  | "logout"
  | "changePw"
  | "refreshToken"
  | "forgotPassword"
  | "resetPassword";

export interface TokenService {
  signAccessToken(userId: string | number, claims?: Record<string, unknown>): Promise<string>;
  signRefreshToken(userId: string | number, opts?: { jti?: string; familyId?: string }): Promise<string>;
  verifyAccessToken(token: string): Promise<Record<string, any>>;
  verifyRefreshToken(token: string): Promise<Record<string, any>>;
  signMFAToken(claims: { userId: string | number; role?: string; email?: string; tenantId?: string }): Promise<string>;
  verifyMFAToken(token: string): Promise<Record<string, any>>;
  signMfaSetupToken(userId: string | number, claims?: Record<string, unknown>): Promise<string>;
  verifyMfaSetupToken(token: string): Promise<Record<string, any>>;
  decodeToken(token: string): Record<string, any> | null;
  getArgs(): { key: string | undefined; keys: string[]; algorithm: "RS256" | "HS256" };
}

export interface TokenServiceConfig {
  algorithm?: "RS256" | "HS256";
  privateKey?: string;
  publicKey?: string;
  extraPublicKeys?: string[];
  accessSecret?: string;
  refreshSecret?: string;
  accessExpiresIn?: string | (() => string);
  refreshExpiresIn?: string | (() => string);
}

export interface ProfileHandlers {
  getProfile: RequestHandler;
  updateProfile: RequestHandler;
  deleteProfile: RequestHandler;
}

export interface IamHandlers {
  me: HandlerChain;
  login: HandlerChain;
  register: HandlerChain;
  logout: HandlerChain;
  changePw: HandlerChain;
  refreshToken: HandlerChain;
  forgotPassword: HandlerChain;
  resetPassword: HandlerChain;

  requireRole: (required: string | string[]) => RequestHandler;
  profile: ProfileHandlers;

  verifyAccessToken: (token: string) => Promise<Record<string, any>>;
  accessTokenMiddleware: RequestHandler;

  registerServiceAccount(account: { id: string; privateKey: string; scopes?: string[] }): void;
  issueServiceToken(id: string): string;
  verifyServiceToken(token: string, publicKey: string): Record<string, any>;
  issueRefreshSession(userId: string | number, req?: Partial<Request>): Promise<{ refreshToken: string; familyId: string }>;

  rateLimiter: RequestHandler;
  tokenService: TokenService;
}

export function createIamHandlers(config: IamConfig): IamHandlers;
export function createTokenService(config: TokenServiceConfig): TokenService;
export function createAccessTokenVerifier(config: { key?: string; keys?: string[]; algorithm?: "RS256" | "HS256" }): (token: string) => Promise<Record<string, any>>;
export function accessTokenMiddleware(config: { key?: string; keys?: string[]; algorithm?: "RS256" | "HS256"; strictTokenType?: boolean }): RequestHandler;
export function verifyWithKeys(token: string, keys: string | string[], algorithm?: "RS256" | "HS256"): Promise<Record<string, any>>;
export function isSessionTokenType(payload: Record<string, any>, opts?: { strictTokenType?: boolean }): boolean;
export function requireRole(config: { roles: Roles; getRole: (userId: string | number) => Promise<string | null | undefined> }): (required: string | string[]) => RequestHandler;
export function normalizeRole(role: unknown): string | null;
export function highestRole(ladder: Roles, ...candidates: unknown[]): string | null;

export const TOKEN_TYPES: Readonly<{ ACCESS: "access"; REFRESH: "refresh"; MFA_PENDING: "mfa_pending"; MFA_SETUP: "mfa_setup_required" }>;

export function setSettingsProvider(fn: ((scope: string, key: string, fallback: unknown) => unknown | Promise<unknown>) | null): void;
export function readSetting(scope: string, key: string, fallback: unknown): Promise<unknown>;
export function validatePasswordStrength(password: string): Promise<{ valid: boolean; errors: string[] }>;
export const PASSWORD_MIN_LENGTH: number;
export const PASSWORD_REQUIREMENTS: readonly string[];
export function verifyCaptcha(token: string | undefined, remoteIp?: string): Promise<boolean>;
export function getRefreshIdleTimeoutMinutes(): Promise<number>;
export function refreshFailureReason(err: unknown): string;
export function auditLogger(options?: { logger?: Logger }): (event: AuditEvent) => void;
export const DEFAULT_ME_FIELDS: readonly string[];
export const DEFAULT_UPDATABLE_FIELDS: readonly string[];

export function initializeIAM(handlers: IamHandlers): IamHandlers;
export function getIAM(): IamHandlers;

export type { Router };
