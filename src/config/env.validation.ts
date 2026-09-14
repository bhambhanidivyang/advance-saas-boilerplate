import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
    // Application Configuration
    NODE_ENV: Joi.string().valid('development', 'test', 'production').default('development'),
    APP_NAME: Joi.string().default('backend'),
    PORT: Joi.number().port().default(3000),
    FRONTEND_URL: Joi.string().uri().required(),

    // Password Check Configuration
    ENABLE_HIBP_CHECK: Joi.boolean().default(false),
    ENABLE_COMMON_PASSWORD_CHECK: Joi.boolean().default(false),

    // Database & RedisConfiguration
    DATABASE_URL: Joi.string().uri().required(),
    REDIS_URL: Joi.string().uri().required(),

    // Throttling Configuration
    THROTTLE_DEFAULT_TTL: Joi.number().integer().positive().required(),
    THROTTLE_DEFAULT_LIMIT: Joi.number().integer().positive().required(),
    THROTTLE_AUTH_TTL: Joi.number().integer().positive().required(),
    THROTTLE_AUTH_LIMIT: Joi.number().integer().positive().required(),
    THROTTLE_OTP_TTL: Joi.number().integer().positive().required(),
    THROTTLE_OTP_LIMIT: Joi.number().integer().positive().required(),

    // Email Configuration
    MAIL_HOST: Joi.string().when('EMAIL_PROVIDER', { is: 'smtp', then: Joi.required(), otherwise: Joi.optional() }),
    MAIL_PORT: Joi.number().default(1025),
    MAIL_USER: Joi.string().allow('').optional(),
    MAIL_PASS: Joi.string().allow('').optional(),
    MAIL_FROM: Joi.string().required(),
    MAIL_SECURE: Joi.boolean().default(false),
    MAIL_VERIFICATION_TOKEN_TTL: Joi.number().required().integer().positive(),

    EMAIL_PROVIDER: Joi.string().valid('smtp', 'resend').required().default('smtp'),
    RESEND_API_KEY: Joi.string().when('EMAIL_PROVIDER', { is: 'resend', then: Joi.required(), otherwise: Joi.optional().allow('') }),

    MAIL_POOL: Joi.boolean().default(true).required(),
    MAIL_MAX_CONNECTIONS: Joi.number().integer().positive().required().default(5),
    MAIL_MAX_MESSAGES: Joi.number().integer().positive().required().default(100),
    MAIL_CONNECTION_TIMEOUT: Joi.number().integer().positive().required().default(10000),
    MAIL_GREETING_TIMEOUT: Joi.number().integer().positive().required().default(10000),
    MAIL_SOCKET_TIMEOUT: Joi.number().integer().positive().required().default(30000),
    MAIL_QUEUE_CONCURRENCY: Joi.number().integer().positive().required().default(5),
    MAIL_QUEUE_RATE_LIMIT_MAX: Joi.number().integer().positive().required().default(50),
    MAIL_QUEUE_RATE_LIMIT_DURATION: Joi.number().integer().positive().required().default(1000),

    // Auth Configuration
    AUTH_VERIFICATION_RESEND_COOLDOWN: Joi.number().integer().positive().required().default(60),
    PASSWORD_MAX_FAILED_ATTEMPTS: Joi.number().integer().positive().required().default(5),
    PASSWORD_LOCK_DURATION_SECONDS: Joi.number().integer().positive().required().default(3600),

    // JWT Configuration
    JWT_ACCESS_SECRET: Joi.string().required().min(32).max(256),
    JWT_ACCESS_TTL_SECONDS: Joi.number().integer().positive().default(600),
    JWT_ISSUER: Joi.string().required(),
    JWT_AUDIENCE: Joi.string().required(),
    JWT_ACCESS_KID: Joi.string().required(),

    // Session Configuration
    SESSION_ABSOLUTE_TTL_SECONDS: Joi.number().integer().positive().default(2592000),
    SESSION_REFRESH_TTL_SECONDS: Joi.number().integer().positive().default(1209600),
    SESSION_REFRESH_REUSE_GRACE_SECONDS: Joi.number().integer().min(0).max(300).default(15),
    SESSION_MAX_ACTIVE_PER_USER: Joi.number().integer().positive().default(10),
    SESSION_DENYLIST_ENABLED: Joi.boolean().default(false),

    // Cookie Configuration
    SESSION_COOKIE_NAME: Joi.string().default('mn_rt'),
    SESSION_COOKIE_DOMAIN: Joi.string().optional().allow(''),
    SESSION_COOKIE_SAME_SITE: Joi.string().valid('lax', 'strict', 'none').default('lax'),
    SESSION_COOKIE_SECURE: Joi.boolean()
        .default(true)
        .when('NODE_ENV', {
            is: 'production',
            then: Joi.valid(true).messages({
                'any.only': 'SESSION_COOKIE_SECURE must be true when NODE_ENV=production',
            }),
        })
        .when('SESSION_COOKIE_SAME_SITE', {
            is: 'none',
            then: Joi.valid(true).messages({
                'any.only': 'SESSION_COOKIE_SECURE must be true when SESSION_COOKIE_SAME_SITE=none',
            }),
        }),

    // Trust Proxy Configuration
    TRUST_PROXY: Joi.alternatives()
        .try(
        Joi.boolean(),
        Joi.number().integer().min(0),
        Joi.string()
        )
        .default(false), // FORCE FAIL-CLOSED BY DEFAULT,

    // Context Lengths Configuration
    MAX_DEVICE_ID_LENGTH: Joi.number().integer().positive().required().default(255),
    MAX_USER_AGENT_LENGTH: Joi.number().integer().positive().required().default(1000),
})