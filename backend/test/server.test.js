const request = require('supertest');
const SecureEmailTracker = require('../src/server');

describe('Secure Email Tracker API', () => {
    let app;
    let server;

    beforeAll(() => {
        // Set test environment
        process.env.NODE_ENV = 'test';
        process.env.API_SECRET_KEY = 'test-secret-key';
        process.env.DATABASE_PATH = ':memory:'; // Use in-memory database for testing

        server = new SecureEmailTracker();
        app = server.app;
    });

    afterAll((done) => {
        if (server.db) {
            server.db.close(done);
        } else {
            done();
        }
    });

    describe('Health Check', () => {
        it('should return 200 and status OK', async () => {
            const response = await request(app)
                .get('/health')
                .expect(200);

            expect(response.body.status).toBe('OK');
            expect(response.body.timestamp).toBeDefined();
        });
    });

    describe('Pixel Tracking', () => {
        it('should return a 1x1 PNG for valid token', async () => {
            // Create a test token (this is simplified for testing)
            const testToken = Buffer.from('test-token-data').toString('base64url');

            const response = await request(app)
                .get(`/pixel/${testToken}.png`)
                .expect(200);

            expect(response.headers['content-type']).toBe('image/png');
            expect(response.headers['cache-control']).toContain('no-cache');
        });

        it('should handle invalid tokens gracefully', async () => {
            const invalidToken = 'invalid-token';

            const response = await request(app)
                .get(`/pixel/${invalidToken}.png`)
                .expect(200); // Still returns pixel for privacy

            expect(response.headers['content-type']).toBe('image/png');
        });

        it('should rate limit excessive requests', async () => {
            const testToken = Buffer.from('rate-limit-test').toString('base64url');

            // Make many requests quickly
            const requests = Array(600).fill().map(() =>
                request(app).get(`/pixel/${testToken}.png`)
            );

            const responses = await Promise.allSettled(requests);

            // Some requests should be rate limited
            const rateLimited = responses.some(result =>
                result.value && result.value.status === 429
            );

            expect(rateLimited).toBe(true);
        }, 30000);
    });

    describe('API Authentication', () => {
        it('should reject requests without API key', async () => {
            await request(app)
                .post('/api/validate-token')
                .send({ token: 'test-token' })
                .expect(401);
        });

        it('should accept requests with valid API key', async () => {
            await request(app)
                .post('/api/validate-token')
                .set('X-API-Key', 'test-secret-key')
                .send({ token: Buffer.from('test').toString('base64') })
                .expect(200);
        });
    });

    describe('Token Validation', () => {
        it('should validate token format', async () => {
            const response = await request(app)
                .post('/api/validate-token')
                .set('X-API-Key', 'test-secret-key')
                .send({ token: 'invalid-base64!' })
                .expect(400);

            expect(response.body.errors).toBeDefined();
        });

        it('should return validation result for valid token format', async () => {
            const validToken = Buffer.from('valid-token-data').toString('base64');

            const response = await request(app)
                .post('/api/validate-token')
                .set('X-API-Key', 'test-secret-key')
                .send({ token: validToken })
                .expect(200);

            expect(response.body.valid).toBeDefined();
            expect(response.body.expired).toBeDefined();
        });
    });

    describe('Stats Endpoint', () => {
        it('should return stats with valid API key', async () => {
            const response = await request(app)
                .get('/api/stats')
                .set('X-API-Key', 'test-secret-key')
                .expect(200);

            expect(response.body.total_opens).toBeDefined();
            expect(response.body.human_opens).toBeDefined();
            expect(response.body.bot_opens).toBeDefined();
        });
    });
});
