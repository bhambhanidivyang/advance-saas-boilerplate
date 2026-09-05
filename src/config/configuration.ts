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
            ttl: parseInt(process.env.THROTTLE_DEFAULT_TTL!, 10),
            limit: parseInt(process.env.THROTTLE_DEFAULT_LIMIT!, 10),
        },
        auth: {
            ttl: parseInt(process.env.THROTTLE_AUTH_TTL!, 10),
            limit: parseInt(process.env.THROTTLE_AUTH_LIMIT!, 10),
        },
        otp: {
            ttl: parseInt(process.env.THROTTLE_OTP_TTL!, 10),
            limit: parseInt(process.env.THROTTLE_OTP_LIMIT!, 10),
        }
    },
    email: {
        provider: process.env.EMAIL_PROVIDER,
        from: process.env.MAIL_FROM,
        verificationTokenTtl: process.env.MAIL_VERIFICATION_TOKEN_TTL,
    
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
    }
})