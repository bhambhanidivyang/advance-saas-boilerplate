import type { Request } from 'express';
import { buildAuthContext } from './auth.util';

function fakeRequest(ip: string | undefined, headers: Record<string, string> = {}): Request {
    // 1. Lowercase all incoming test header keys to simulate native Node.js behavior
    const lowercasedHeaders = Object.keys(headers).reduce((acc, key) => {
        acc[key.toLowerCase()] = headers[key];
        return acc;
    }, {} as Record<string, string>);
    return {
        ip,
        // Fix A: Provide the raw headers object properties for direct object access
        headers: lowercasedHeaders,
        
        // Fix B: Provide the functional tracker method for method execution access
        get: (name: string) => lowercasedHeaders[name.toLowerCase()],
    } as unknown as Request;
}

describe('buildAuthContext', () => {
    it('drops a malformed ip instead of passing it through', () => {
        expect(buildAuthContext(fakeRequest('bogus')).ipAddress).toBeUndefined();
    });

    it('normalizes an ipv4-mapped ipv6 address', () => {
        expect(buildAuthContext(fakeRequest('::ffff:10.0.0.1')).ipAddress).toBe('10.0.0.1');
    });

    it('clamps a hostile device-id to the column limit', () => {
        const ctx = buildAuthContext(fakeRequest('127.0.0.1', { 'device-id': 'x'.repeat(400) }));
        expect(ctx.deviceId).toHaveLength(255);
    });

    it('clamps an oversized user-agent', () => {
        const ctx = buildAuthContext(fakeRequest('127.0.0.1', { 'user-agent': 'u'.repeat(2000) }));
        expect(ctx.userAgent).toHaveLength(1000);
    });

    it('returns undefined for absent headers rather than empty strings', () => {
        expect(buildAuthContext(fakeRequest('127.0.0.1'))).toEqual({
            ipAddress: '127.0.0.1',
            userAgent: undefined,
            deviceId: undefined,
        });
    });
});