import { normalizeIpAddress } from './ip.util';

describe('normalizeIpAddress', () => {
    it.each([
        [undefined, null],
        [null, null],
        ['', null],
        ['   ', null],
        ['127.0.0.1', '127.0.0.1'],
        ['  127.0.0.1  ', '127.0.0.1'],
        ['::1', '::1'],
        ['::ffff:10.0.0.1', '10.0.0.1'],
        ['::FFFF:10.0.0.1', '10.0.0.1'],
        ['1.2.3.4, 5.6.7.8', '1.2.3.4'],
        ['not-an-ip', null],
        ['999.999.999.999', null],
        ['<script>alert(1)</script>', null],
        ["'; DROP TABLE users; --", null],
    ])('normalizeIpAddress(%p) → %p', (input, expected) => {
        expect(normalizeIpAddress(input as string | null | undefined)).toBe(expected);
    });
});