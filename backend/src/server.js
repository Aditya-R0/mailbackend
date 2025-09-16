require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const winston = require('winston');
const { body, validationResult, param } = require('express-validator');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken'); // 🔧 ADD: JWT support

class SecureEmailTracker {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.secretKey = process.env.API_SECRET_KEY || 'change-this-secret';
        this.setupLogger();
        this.setupDatabase();
        this.setupRateLimiting();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
    }

    setupLogger() {
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: { service: 'email-tracker' },
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    )
                })
            ]
        });

        // Add file logging in production
        if (process.env.NODE_ENV === 'production') {
            this.logger.add(new winston.transports.File({
                filename: process.env.LOG_FILE || './logs/app.log'
            }));
        }
    }

    setupDatabase() {
        const dbPath = process.env.DATABASE_PATH || './tracking.db';
        this.db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                this.logger.error('Database connection error:', err);
                throw err;
            }
            this.logger.info('Connected to SQLite database');
        });

        // Create tables
        this.createTables();
    }

    createTables() {
        const createOpenEventsTable = `
            CREATE TABLE IF NOT EXISTS open_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_hash TEXT,
                user_agent TEXT,
                country TEXT,
                is_bot BOOLEAN DEFAULT 0,
                referer TEXT,
                message_id TEXT,
                recipient_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `;

        const createTokensTable = `
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                message_id TEXT,
                recipient_hash TEXT,
                expires_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `;

        this.db.run(createOpenEventsTable, (err) => {
            if (err) this.logger.error('Error creating open_events table:', err);
        });

        this.db.run(createTokensTable, (err) => {
            if (err) this.logger.error('Error creating tokens table:', err);
        });
    }

    setupRateLimiting() {
        // General rate limiter
        this.rateLimiter = new RateLimiterMemory({
            keyBuilder: (req) => req.ip,
            points: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
            duration: parseInt(process.env.RATE_LIMIT_WINDOW_MS) / 1000 || 60,
        });

        // Aggressive rate limiter for pixel requests
        this.pixelRateLimiter = new RateLimiterMemory({
            keyBuilder: (req) => req.ip,
            points: 500, // Allow more requests for legitimate email clients
            duration: 60,
        });
    }

    setupMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:", "http:"], // 🔧 Allow http for localhost
                },
            },
            // 🔧 Disable CORP blocking for pixel images
            crossOriginResourcePolicy: false
        }));

        // CORS configuration - 🔧 More permissive for pixel loading
        const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
        this.app.use(cors({
            origin: true, // 🔧 Allow all origins for pixel loading
            credentials: false,
            methods: ['GET', 'POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
        }));

        // 🔧 Handle preflight requests for images
        this.app.options('*', cors());

        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Request logging
        this.app.use((req, res, next) => {
            this.logger.info(`${req.method} ${req.path}`, {
                ip: this.anonymizeIP(req.ip),
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });
            next();
        });
    }

    setupRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'OK',
                timestamp: new Date().toISOString(),
                version: '1.0.0'
            });
        });

        // 🔧 UPDATED: Pixel tracking endpoint with JWT support
        this.app.get('/pixel/:token.png',
            this.rateLimitMiddleware(this.pixelRateLimiter),
            // Remove base64 validation since JWT tokens have different format
            param('token').isLength({ min: 10, max: 1000 }),
            this.handlePixelRequest.bind(this)
        );

        // API endpoints for extension communication
        this.app.post('/api/generate-token',
            this.rateLimitMiddleware(this.rateLimiter),
            this.requireApiKey.bind(this),
            body('messageId').notEmpty(),
            body('recipient').isEmail(),
            body('timestamp').isNumeric(),
            this.handleTokenGeneration.bind(this)
        );

        this.app.post('/api/validate-token',
            this.rateLimitMiddleware(this.rateLimiter),
            this.requireApiKey.bind(this),
            body('token').isLength({ min: 10, max: 1000 }),
            this.handleTokenValidation.bind(this)
        );

        this.app.get('/api/stats/:messageId?',
            this.rateLimitMiddleware(this.rateLimiter),
            this.requireApiKey.bind(this),
            this.handleStatsRequest.bind(this)
        );

        // Admin endpoints (if enabled)
        if (process.env.ENABLE_ADMIN_ENDPOINTS === 'true') {
            this.app.delete('/admin/cleanup',
                this.rateLimitMiddleware(this.rateLimiter),
                this.requireAdminKey.bind(this),
                this.handleDataCleanup.bind(this)
            );
        }
    }

    rateLimitMiddleware(limiter) {
        return async (req, res, next) => {
            try {
                await limiter.consume(req.ip);
                next();
            } catch (rejRes) {
                const remainingPoints = rejRes.remainingPoints;
                const msBeforeNext = rejRes.msBeforeNext;
                res.set('Retry-After', Math.round(msBeforeNext / 1000) || 1);
                res.status(429).json({
                    error: 'Too Many Requests',
                    retryAfter: msBeforeNext
                });
            }
        };
    }

    requireApiKey(req, res, next) {
        const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
        if (!apiKey || apiKey !== this.secretKey) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        next();
    }

    requireAdminKey(req, res, next) {
        const adminKey = req.headers['x-admin-key'];
        if (!adminKey || adminKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ error: 'Invalid or missing admin key' });
        }
        next();
    }

    // 🔧 NEW: Token generation endpoint for extension
    async handleTokenGeneration(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { messageId, recipient, timestamp } = req.body;

            // Create JWT payload
            const payload = {
                mid: messageId,
                rec: recipient.substring(0, 6), // First 6 chars for privacy
                ts: timestamp,
                exp: timestamp + (24 * 60 * 60 * 1000), // 24h expiry
                nonce: crypto.randomBytes(16).toString('hex')
            };

            // Sign JWT token
            const token = jwt.sign(payload, this.secretKey);

            // 🔧 URL encode the token to handle = characters
            const encodedToken = encodeURIComponent(token);
            const pixelUrl = `${req.protocol}://${req.get('host')}/pixel/${encodedToken}.png`;

            // Store token hash in database
            const tokenHash = this.hashToken(token);
            this.storeToken(tokenHash, messageId, this.hashRecipient(recipient));

            this.logger.info('Token generated', {
                tokenHash,
                messageId: messageId.substring(0, 8) + '...'
            });

            res.json({
                success: true,
                token,
                pixelUrl,
                expiresAt: new Date(payload.exp).toISOString()
            });
        } catch (error) {
            this.logger.error('Token generation error:', error);
            res.status(500).json({
                success: false,
                error: 'Token generation failed'
            });
        }
    }

    // 🔧 UPDATED: Handle pixel requests with JWT validation
    async handlePixelRequest(req, res) {
        try {
            console.log('🔍 Raw token from URL:', req.params.token);
            
            // 🔧 URL decode the token first
            const decodedToken = decodeURIComponent(req.params.token);
            console.log('🔍 Decoded token:', decodedToken);

            let payload;
            try {
                // Validate JWT token
                payload = jwt.verify(decodedToken, this.secretKey);
                console.log('✅ Token verified successfully:', payload);
            } catch (jwtError) {
                console.log('❌ JWT verification failed:', jwtError.message);
                // Still return pixel for privacy (don't reveal invalid tokens)
                return this.sendPixel(res);
            }

            // Check if token is expired (double check)
            if (payload.exp && Date.now() > payload.exp) {
                this.logger.warn('Expired token used', {
                    tokenHash: this.hashToken(decodedToken),
                    expiredAt: new Date(payload.exp).toISOString()
                });
                return this.sendPixel(res);
            }

            // Detect if request is from a bot
            const isBot = this.detectBot(req.get('User-Agent') || '');
            const tokenHash = this.hashToken(decodedToken);
            const ipHash = this.anonymizeIP(req.ip);

            // Log the open event with enhanced data
            this.logOpenEvent({
                tokenHash,
                ipHash,
                userAgent: req.get('User-Agent') || '',
                referer: req.get('Referer') || '',
                messageId: payload.mid,
                recipientHash: this.hashRecipient(payload.rec),
                isBot
            });

            // Set no-cache headers
            res.set({
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma': 'no-cache',
                'Expires': 'Thu, 01 Jan 1970 00:00:00 GMT'
            });

            this.sendPixel(res);
        } catch (error) {
            console.error('❌ Pixel request error:', error);
            this.logger.error('Pixel request error:', error);
            this.sendPixel(res); // Always return pixel for privacy
        }
    }

    // Helper method to store tokens
    storeToken(tokenHash, messageId, recipientHash) {
        const query = `
            INSERT OR REPLACE INTO tokens (token_hash, message_id, recipient_hash, expires_at)
            VALUES (?, ?, ?, datetime('now', '+24 hours'))
        `;
        
        this.db.run(query, [tokenHash, messageId, recipientHash], (err) => {
            if (err) {
                this.logger.error('Error storing token:', err);
            }
        });
    }

    detectBot(userAgent) {
        const botPatterns = [
            /bot/i, /crawler/i, /spider/i, /scraper/i,
            /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i,
            /preview/i, /scanner/i, /validator/i, /googleimageproxy/i
        ];
        return botPatterns.some(pattern => pattern.test(userAgent));
    }

    // 🔧 UPDATED: Enhanced logging with message ID
    logOpenEvent(data) {
        const query = `
            INSERT INTO open_events (
                token_hash, ip_hash, user_agent, referer, message_id, 
                recipient_hash, is_bot
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        this.db.run(query, [
            data.tokenHash,
            data.ipHash,
            data.userAgent,
            data.referer,
            data.messageId,
            data.recipientHash,
            data.isBot ? 1 : 0
        ], (err) => {
            if (err) {
                this.logger.error('Error logging open event:', err);
            } else {
                this.logger.info('Open event logged successfully', {
                    tokenHash: data.tokenHash,
                    messageId: data.messageId?.substring(0, 8) + '...',
                    isBot: data.isBot
                });
            }
        });
    }

    sendPixel(res) {
        // 1x1 transparent PNG
        const pixel = Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
            'base64'
        );

        res.set({
            'Content-Type': 'image/png',
            'Content-Length': pixel.length,
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
            // 🔧 Add CORP headers for cross-origin image loading
            'Cross-Origin-Resource-Policy': 'cross-origin',
            'Cross-Origin-Embedder-Policy': 'unsafe-none',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET',
            'Access-Control-Allow-Headers': 'Content-Type'
        });

        res.end(pixel);
    }

    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    hashRecipient(recipient) {
        return crypto.createHash('sha256').update(recipient).digest('hex').substring(0, 16);
    }

    anonymizeIP(ip) {
        if (!ip || process.env.IP_ANONYMIZATION !== 'true') {
            return ip;
        }

        try {
            // IPv4: Keep first 3 octets, zero last octet
            if (ip.includes('.')) {
                const parts = ip.split('.');
                if (parts.length === 4) {
                    parts[3] = '0';
                    return parts.join('.');
                }
            }

            // IPv6: Keep first 64 bits, zero the rest
            if (ip.includes(':')) {
                const parts = ip.split(':');
                if (parts.length >= 4) {
                    return parts.slice(0, 4).join(':') + '::';
                }
            }
        } catch (error) {
            this.logger.warn('IP anonymization error:', error);
        }

        return crypto.createHash('sha256').update(ip).digest('hex').substring(0, 8);
    }

    async handleTokenValidation(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { token } = req.body;
            
            try {
                const payload = jwt.verify(token, this.secretKey);
                const isExpired = payload.exp && Date.now() > payload.exp;
                
                res.json({
                    valid: true,
                    expired: isExpired,
                    payload: payload
                });
            } catch (jwtError) {
                res.json({
                    valid: false,
                    expired: false,
                    error: jwtError.message
                });
            }
        } catch (error) {
            this.logger.error('Token validation error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleStatsRequest(req, res) {
        try {
            const messageId = req.params.messageId;
            
            let query = `
                SELECT 
                    COUNT(*) as total_opens,
                    COUNT(CASE WHEN is_bot = 0 THEN 1 END) as human_opens,
                    COUNT(CASE WHEN is_bot = 1 THEN 1 END) as bot_opens,
                    MIN(timestamp) as first_open,
                    MAX(timestamp) as last_open
                FROM open_events
            `;
            
            const params = [];
            if (messageId) {
                query += ' WHERE message_id = ?';
                params.push(messageId);
            }

            this.db.get(query, params, (err, row) => {
                if (err) {
                    this.logger.error('Stats query error:', err);
                    return res.status(500).json({ error: 'Database error' });
                }

                res.json({
                    ...row,
                    messageId: messageId || 'all'
                });
            });
        } catch (error) {
            this.logger.error('Stats request error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    async handleDataCleanup(req, res) {
        try {
            const retentionDays = parseInt(process.env.DATA_RETENTION_DAYS) || 90;
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

            const deleteQuery = `
                DELETE FROM open_events 
                WHERE created_at < datetime(?)
            `;

            this.db.run(deleteQuery, [cutoffDate.toISOString()], function (err) {
                if (err) {
                    this.logger.error('Data cleanup error:', err);
                    return res.status(500).json({ error: 'Cleanup failed' });
                }

                this.logger.info(`Cleaned up ${this.changes} old records`);
                res.json({
                    deleted: this.changes,
                    cutoffDate: cutoffDate.toISOString()
                });
            });
        } catch (error) {
            this.logger.error('Data cleanup error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }

    setupErrorHandling() {
        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({ error: 'Not found' });
        });

        // Global error handler
        this.app.use((err, req, res, next) => {
            this.logger.error('Unhandled error:', err);
            res.status(500).json({ error: 'Internal server error' });
        });

        // Graceful shutdown
        process.on('SIGTERM', this.gracefulShutdown.bind(this));
        process.on('SIGINT', this.gracefulShutdown.bind(this));
    }

    gracefulShutdown(signal) {
        this.logger.info(`Received ${signal}, shutting down gracefully`);
        this.db.close((err) => {
            if (err) {
                this.logger.error('Error closing database:', err);
            } else {
                this.logger.info('Database connection closed');
            }
            process.exit(0);
        });
    }

    start() {
        // 🔧 FIX: Listen on all interfaces (0.0.0.0) instead of localhost
        this.app.listen(this.port, '0.0.0.0', () => {
            this.logger.info(`Secure Email Tracker backend running on port ${this.port}`);
            this.logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
        });
    }
}

// Start the server
if (require.main === module) {
    new SecureEmailTracker().start();
}

module.exports = SecureEmailTracker;
