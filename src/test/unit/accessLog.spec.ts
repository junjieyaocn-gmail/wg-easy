import { describe, expect, test, vi } from 'vitest';

import { accessLogTestExports } from '#server/utils/accessLog';

vi.mock('#server/utils/config', () => ({
  WG_ENV: {
    ACCESS_LOG_ENABLED: true,
    ACCESS_LOG_DIR: '/tmp/wgeasy-test-logs',
    ACCESS_LOG_TRAFFIC_INTERVAL_MINUTES: 5,
    ACCESS_LOG_MAX_SIZE_MB: 100,
    DISABLE_IPV6: true,
  },
}));

vi.mock('#server/utils/Database', () => ({
  default: {
    clients: { getAll: vi.fn().mockResolvedValue([]) },
    userConfigs: { get: vi.fn().mockResolvedValue({ defaultDns: [] }) },
  },
}));

const {
  parseDnsmasqQueryLine,
  formatAccessLogLine,
  formatTrafficLogLine,
} = accessLogTestExports;

describe('accessLog', () => {
  describe('parseDnsmasqQueryLine', () => {
    test('parses a standard A query line', () => {
      const line =
        'Oct  4 12:34:56 dnsmasq[7]: query[A] www.youtube.com from 10.8.0.2';
      expect(parseDnsmasqQueryLine(line)).toEqual({
        qtype: 'A',
        domain: 'www.youtube.com',
        srcIp: '10.8.0.2',
      });
    });

    test('parses AAAA and other query types', () => {
      const line =
        'Oct  4 12:34:56 dnsmasq[7]: query[AAAA] example.com from fd00::2';
      expect(parseDnsmasqQueryLine(line)).toEqual({
        qtype: 'AAAA',
        domain: 'example.com',
        srcIp: 'fd00::2',
      });
    });

    test('ignores non-query dnsmasq lines', () => {
      expect(
        parseDnsmasqQueryLine(
          'Oct  4 12:34:56 dnsmasq[7]: forwarded www.youtube.com to 1.1.1.1'
        )
      ).toBeNull();
      expect(
        parseDnsmasqQueryLine(
          'Oct  4 12:34:56 dnsmasq[7]: reply www.youtube.com is 142.250.1.1'
        )
      ).toBeNull();
      expect(parseDnsmasqQueryLine('')).toBeNull();
      expect(parseDnsmasqQueryLine('query[A] broken-line')).toBeNull();
    });
  });

  describe('formatAccessLogLine', () => {
    test('formats a website visit line', () => {
      const line = formatAccessLogLine(
        new Date('2026-10-04T04:00:00.000Z'),
        '我的手机',
        '10.8.0.2',
        { qtype: 'A', domain: 'www.youtube.com', srcIp: '10.8.0.2' }
      );
      expect(line).toBe(
        '2026-10-04T04:00:00.000Z access client="我的手机" ip=10.8.0.2 query=www.youtube.com type=A'
      );
    });

    test('strips quotes and newlines from client names', () => {
      const line = formatAccessLogLine(
        new Date('2026-10-04T04:00:00.000Z'),
        'evil"\nname',
        '10.8.0.2',
        { qtype: 'A', domain: 'example.com', srcIp: '10.8.0.2' }
      );
      expect(line).not.toContain('"\\n');
      expect(line).toContain('client="evilname"');
    });
  });

  describe('formatTrafficLogLine', () => {
    test('formats a traffic snapshot line', () => {
      const line = formatTrafficLogLine(
        new Date('2026-10-04T04:05:00.000Z'),
        '我的手机',
        '10.8.0.2',
        1048576,
        524288
      );
      expect(line).toBe(
        '2026-10-04T04:05:00.000Z traffic client="我的手机" ip=10.8.0.2 rx_bytes=1048576 tx_bytes=524288'
      );
    });
  });
});
