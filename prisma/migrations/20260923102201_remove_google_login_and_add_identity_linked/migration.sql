/*
  Warnings:

  - The values [GOOGLE_LOGIN] on the enum `AuthEventType` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "AuthEventType_new" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'LOGOUT_ALL', 'PASSWORD_CHANGED', 'PASSWORD_RESET', 'EMAIL_VERIFIED', 'PHONE_VERIFIED', 'OTP_SENT', 'OTP_VERIFIED', 'OTP_FAILED', 'TOKEN_REFRESH', 'TOKEN_REUSE_DETECTED', 'SESSION_REVOKED', 'IDENTITY_LINKED');
ALTER TABLE "AuthEvent" ALTER COLUMN "eventType" TYPE "AuthEventType_new" USING ("eventType"::text::"AuthEventType_new");
ALTER TYPE "AuthEventType" RENAME TO "AuthEventType_old";
ALTER TYPE "AuthEventType_new" RENAME TO "AuthEventType";
DROP TYPE "public"."AuthEventType_old";
COMMIT;
