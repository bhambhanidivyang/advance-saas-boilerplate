export default () => ({
    app: {
        name: process.env.APP_NAME || 'backend',
        environment: process.env.NODE_ENV || 'development',
        port: parseInt(process.env.PORT || '3000', 10),
        frontendUrl: process.env.FRONTEND_URL
    },
    database: {
        url: process.env.DATABASE_URL
    },
    redis: {
        url: process.env.REDIS_URL
    },
    throttling: {
        default: {
            ttl: Number(process.env.THROTTLE_DEFAULT_TTL!),
            limit: Number(process.env.THROTTLE_DEFAULT_LIMIT!),
        },
        auth: {
            ttl: Number(process.env.THROTTLE_AUTH_TTL!),
            limit: Number(process.env.THROTTLE_AUTH_LIMIT!),
        },
        otp: {
            ttl: Number(process.env.THROTTLE_OTP_TTL!),
            limit: Number(process.env.THROTTLE_OTP_LIMIT!),
        }
    },
    email: {
        provider: process.env.EMAIL_PROVIDER,
        from: process.env.MAIL_FROM,
        verificationTokenTtl: Number(process.env.MAIL_VERIFICATION_TOKEN_TTL),
    
        smtp: {
            host: process.env.MAIL_HOST,
            port: Number(process.env.MAIL_PORT || '1025'),
            user: process.env.MAIL_USER,
            password: process.env.MAIL_PASS,
            secure: process.env.MAIL_SECURE === 'true',
            pool: process.env.MAIL_POOL !== 'false',
            maxConnections: Number(process.env.MAIL_MAX_CONNECTIONS || '5'),
            maxMessages: Number(process.env.MAIL_MAX_MESSAGES || '100'),
            connectionTimeout: Number(process.env.MAIL_CONNECTION_TIMEOUT || '10000'),
            greetingTimeout: Number(process.env.MAIL_GREETING_TIMEOUT || '10000'),
            socketTimeout: Number(process.env.MAIL_SOCKET_TIMEOUT || '30000'),
        },

        queue: {
            concurrency: Number(process.env.MAIL_QUEUE_CONCURRENCY || '5'),
            rateLimitMax: Number(process.env.MAIL_QUEUE_RATE_LIMIT_MAX || '50'),
            rateLimitDuration: Number(process.env.MAIL_QUEUE_RATE_LIMIT_DURATION || '1000'),
        },
    
        resend: {
            apiKey: process.env.RESEND_API_KEY,
        },
    },
    auth: {
        authVerificationResendCooldown: Number(process.env.AUTH_VERIFICATION_RESEND_COOLDOWN) || 60,
        passwordMaxFailedAttempts: Number(process.env.PASSWORD_MAX_FAILED_ATTEMPTS) || 5,
        passwordLockDurationSeconds: Number(process.env.PASSWORD_LOCK_DURATION_SECONDS) || 3600,
        authVerificationResendMaxRetries: Number(process.env.AUTH_VERIFICATION_RESEND_MAX_RETRIES) || 3,
        jwt: {
            accessSecret: process.env.JWT_ACCESS_SECRET,
            accessTtlSeconds: Number(process.env.JWT_ACCESS_TTL_SECONDS) || 600,
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE || 'backend',
            accessKid: process.env.JWT_ACCESS_KID,
        },
        session: {
            absoluteTtlSeconds: Number(process.env.SESSION_ABSOLUTE_TTL_SECONDS) || 2592000,
            refreshTtlSeconds: Number(process.env.SESSION_REFRESH_TTL_SECONDS) || 1209600,
            refreshReuseGraceSeconds: Number(process.env.SESSION_REFRESH_REUSE_GRACE_SECONDS) || 15,
            maxActivePerUser: Number(process.env.SESSION_MAX_ACTIVE_PER_USER) || 10,
            denylistEnabled: process.env.SESSION_DENYLIST_ENABLED === 'true',
        },
        cookie: {
            name: process.env.SESSION_COOKIE_NAME || 'mn_rt',
            domain: process.env.SESSION_COOKIE_DOMAIN || undefined,
            sameSite: (process.env.SESSION_COOKIE_SAME_SITE || 'lax') as 'lax' | 'strict' | 'none',
            secure: process.env.SESSION_COOKIE_SECURE ? process.env.SESSION_COOKIE_SECURE === 'true' : true,
        },
        trustProxy:
            process.env.TRUST_PROXY
            ? (process.env.TRUST_PROXY.trim() === 'true'
                ? true
                : process.env.TRUST_PROXY.trim() === 'false'
                    ? false
                    : !isNaN(Number(process.env.TRUST_PROXY))
                        ? Number(process.env.TRUST_PROXY)
                        : process.env.TRUST_PROXY.trim())
            : false,
        capabilities: {
            google: process.env.AUTH_GOOGLE_ENABLED === 'true'
        },
        google: {
            clientIds: (process.env.GOOGLE_CLIENT_IDS ?? '')
                .split(',')
                .map((id) => id.trim())
                .filter(Boolean),
            nonceRequired: process.env.AUTH_GOOGLE_NONCE_REQUIRED === 'true',
            nonceTtlSeconds: Number(process.env.AUTH_GOOGLE_NONCE_TTL_SECONDS) || 300,
        },
    },
    maintenance: {
        cleanupEnabled: process.env.MAINTENANCE_CLEANUP_ENABLED !== 'false',
        cleanupCron: process.env.MAINTENANCE_CLEANUP_CRON || '17 3 * * *',
        refreshTokenRetentionDays: Number(process.env.REFRESH_TOKEN_RETENTION_DAYS) || 30,
        userTokenRetentionDays: Number(process.env.USER_TOKEN_RETENTION_DAYS) || 7,
        authNonceRetentionDays: Number(process.env.AUTH_NONCE_RETENTION_DAYS) || 1,
    },
})