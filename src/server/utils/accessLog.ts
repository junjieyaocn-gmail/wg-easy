import childProcess from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';

import { parseCidr } from 'cidr-tools';
import { stringifyIp } from 'ip-bigint';
import { createDebug } from 'obug';

import Database from '#server/utils/Database';
import { exec } from '#server/utils/cmd';
import { WG_ENV } from '#server/utils/config';
import { wg } from '#server/utils/wgHelper';
import { setIntervalImmediately } from '#shared/utils/time';
import type { InterfaceType } from '#db/repositories/interface/types';

const AL_DEBUG = createDebug('AccessLog');

/**
 * Per-client access & traffic logging.
 *
 * - Website visits: a local dnsmasq resolver answers DNS for VPN clients and
 *   logs every query. Client DNS traffic (udp/tcp port 53) leaving the
 *   WireGuard interface is transparently redirected to it via NAT, so no
 *   client reconfiguration is needed. Queries are mapped from source IP to
 *   client name and appended to `access.log`.
 * - Traffic: `wg show dump` counters are snapshotted periodically and
 *   appended to `traffic.log`.
 *
 * Both logs live in WG_ENV.ACCESS_LOG_DIR (default /etc/wireguard, the
 * persisted config volume).
 *
 * Limitations: only domain names are visible (HTTPS encrypts everything
 * else). DNS-over-HTTPS / DNS-over-TLS bypass the local resolver and are
 * not logged.
 */

// dnsmasq --log-queries line, e.g.:
// "Oct  4 12:34:56 dnsmasq[7]: query[A] www.youtube.com from 10.8.0.2"
const DNSMASQ_QUERY_RE = /query\[([A-Za-z]+)\]\s+(\S+)\s+from\s+(\S+)/;

export type DnsQuery = {
  qtype: string;
  domain: string;
  srcIp: string;
};

export function parseDnsmasqQueryLine(line: string): DnsQuery | null {
  const match = DNSMASQ_QUERY_RE.exec(line);
  if (!match || !match[1] || !match[2] || !match[3]) {
    return null;
  }
  return { qtype: match[1], domain: match[2], srcIp: match[3] };
}

const sanitizeLogValue = (value: string): string =>
  value.replace(/["\\\r\n]/g, '');

export function formatAccessLogLine(
  now: Date,
  clientName: string,
  srcIp: string,
  query: DnsQuery
): string {
  return `${now.toISOString()} access client="${sanitizeLogValue(clientName)}" ip=${srcIp} query=${query.domain} type=${query.qtype}`;
}

export function formatTrafficLogLine(
  now: Date,
  clientName: string,
  ip: string,
  rxBytes: number,
  txBytes: number
): string {
  return `${now.toISOString()} traffic client="${sanitizeLogValue(clientName)}" ip=${ip} rx_bytes=${rxBytes} tx_bytes=${txBytes}`;
}

type AccessLogState = {
  running: boolean;
  dnsTailTimer?: ReturnType<typeof setInterval>;
  trafficTimer?: ReturnType<typeof setInterval>;
  clientMapTimer?: ReturnType<typeof setInterval>;
  dnsmasqProc?: childProcess.ChildProcess;
  dnsLogOffset: number;
  ipToName: Map<string, string>;
};

const state: AccessLogState = {
  running: false,
  dnsLogOffset: 0,
  ipToName: new Map(),
};

const logFile = (dir: string, name: string): string => path.join(dir, name);

async function appendLogLine(file: string, line: string): Promise<void> {
  const maxBytes = WG_ENV.ACCESS_LOG_MAX_SIZE_MB * 1024 * 1024;
  try {
    const stat = await fsp.stat(file);
    if (stat.size > maxBytes) {
      await fsp.rename(file, `${file}.1`).catch(() => {});
    }
  } catch {
    // file does not exist yet, nothing to rotate
  }
  await fsp.appendFile(file, `${line}\n`);
}

function serverTunnelIp(cidr: string): string {
  const parsed = parseCidr(cidr);
  return stringifyIp({ number: parsed.start + 1n, version: 4 });
}

function serverTunnelIp6(cidr: string): string {
  const parsed = parseCidr(cidr);
  return stringifyIp({ number: parsed.start + 1n, version: 6 });
}

async function refreshClientMap(): Promise<void> {
  try {
    const clients = await Database.clients.getAll();
    const map = new Map<string, string>();
    for (const client of clients) {
      if (client.enabled !== true) continue;
      map.set(client.ipv4Address, client.name);
      if (client.ipv6Address) {
        map.set(client.ipv6Address, client.name);
      }
    }
    state.ipToName = map;
  } catch (err) {
    AL_DEBUG('Failed to refresh client map:', err);
  }
}

async function resolveUpstreamDns(): Promise<string[]> {
  try {
    const userConfig = await Database.userConfigs.get();
    const configured = (userConfig.defaultDns ?? []).filter(
      (server) => server && server.trim().length > 0
    );
    if (configured.length > 0) {
      return configured;
    }
  } catch (err) {
    AL_DEBUG('Failed to read configured DNS:', err);
  }
  return ['1.1.1.1', '8.8.8.8'];
}

/**
 * Add/remove a NAT PREROUTING rule redirecting client DNS to the local resolver.
 */
async function manageDnsRedirectRule(
  bin: 'iptables' | 'ip6tables',
  interfaceName: string,
  proto: 'udp' | 'tcp',
  destination: string,
  action: 'A' | 'D'
): Promise<void> {
  const ruleSpec =
    `-t nat ${action} PREROUTING -i ${interfaceName} -p ${proto} --dport 53 ` +
    `-j DNAT --to-destination ${destination}`;
  if (action === 'A') {
    const checkSpec = ruleSpec.replace(' -A ', ' -C ');
    await exec(
      `${bin} ${checkSpec} 2>/dev/null || ${bin} ${ruleSpec} 2>/dev/null || true`
    );
  } else {
    await exec(`${bin} ${ruleSpec} 2>/dev/null || true`);
  }
}

async function startDnsmasq(
  listenAddresses: string[],
  upstreams: string[],
  dnsLogFile: string
): Promise<void> {
  try {
    await exec('command -v dnsmasq');
  } catch {
    console.warn(
      'WARNING: dnsmasq is not installed, DNS query logging is disabled. ' +
        'The website access log will stay empty.'
    );
    return;
  }

  state.dnsmasqProc?.kill();
  state.dnsmasqProc = undefined;

  const args = [
    ...listenAddresses.map((addr) => `--listen-address=${addr}`),
    '--bind-interfaces',
    '--port=53',
    '--no-resolv',
    ...upstreams.map((server) => `--server=${server}`),
    '--cache-size=1000',
    '--log-queries',
    `--log-facility=${dnsLogFile}`,
    '--keep-in-foreground',
  ];

  AL_DEBUG(`Starting dnsmasq: dnsmasq ${args.join(' ')}`);
  const proc = childProcess.spawn('dnsmasq', args, {
    detached: true,
    stdio: 'ignore',
  });
  proc.unref();
  proc.on('error', (err) => {
    AL_DEBUG('dnsmasq failed to start:', err);
    console.warn(`WARNING: dnsmasq failed to start: ${err.message}`);
  });
  state.dnsmasqProc = proc;
}

async function tailDnsLog(
  dnsLogFile: string,
  accessLogFile: string
): Promise<void> {
  let stat: fs.Stats;
  try {
    stat = await fsp.stat(dnsLogFile);
  } catch {
    return; // dnsmasq has not written anything yet
  }

  // log file was rotated/truncated
  if (stat.size < state.dnsLogOffset) {
    state.dnsLogOffset = 0;
  }
  if (stat.size === state.dnsLogOffset) {
    return;
  }

  const handle = await fsp.open(dnsLogFile, 'r');
  try {
    const length = stat.size - state.dnsLogOffset;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, state.dnsLogOffset);
    state.dnsLogOffset = stat.size;

    const now = new Date();
    for (const line of buffer.toString('utf8').split('\n')) {
      const query = parseDnsmasqQueryLine(line);
      if (!query) continue;

      let clientName = state.ipToName.get(query.srcIp);
      if (!clientName) {
        await refreshClientMap();
        clientName = state.ipToName.get(query.srcIp) ?? 'unknown';
      }

      await appendLogLine(
        accessLogFile,
        formatAccessLogLine(now, clientName, query.srcIp, query)
      );
    }
  } finally {
    await handle.close();
  }
}

async function snapshotTraffic(
  interfaceName: string,
  trafficLogFile: string
): Promise<void> {
  try {
    const clients = await Database.clients.getAll();
    const clientsByPublicKey = new Map(
      clients.map((client) => [client.publicKey, client])
    );

    const dump = await wg.dump(interfaceName);
    const now = new Date();

    for (const peer of dump) {
      const client = clientsByPublicKey.get(peer.publicKey);
      if (!client || client.enabled !== true) continue;

      await appendLogLine(
        trafficLogFile,
        formatTrafficLogLine(
          now,
          client.name,
          client.ipv4Address,
          peer.transferRx,
          peer.transferTx
        )
      );
    }
  } catch (err) {
    AL_DEBUG('Traffic snapshot failed:', err);
  }
}

export const accessLog = {
  async start(wgInterface: InterfaceType): Promise<void> {
    if (!WG_ENV.ACCESS_LOG_ENABLED) {
      AL_DEBUG('Access logging is disabled.');
      return;
    }
    if (state.running) {
      AL_DEBUG('Access logging already running.');
      return;
    }

    const dir = WG_ENV.ACCESS_LOG_DIR;
    await fsp.mkdir(dir, { recursive: true });

    const accessLogFile = logFile(dir, 'access.log');
    const trafficLogFile = logFile(dir, 'traffic.log');
    const dnsLogFile = logFile(dir, 'dnsmasq.log');

    const serverV4 = serverTunnelIp(wgInterface.ipv4Cidr);
    const enableIpv6 = !WG_ENV.DISABLE_IPV6;
    const serverV6 = enableIpv6
      ? serverTunnelIp6(wgInterface.ipv6Cidr)
      : null;

    await refreshClientMap();
    state.clientMapTimer = setIntervalImmediately(() => {
      void refreshClientMap();
    }, 60 * 1000);

    if (process.platform === 'linux') {
      const upstreams = await resolveUpstreamDns();
      const listenAddresses =
        serverV6 !== null ? [serverV4, serverV6] : [serverV4];
      await startDnsmasq(listenAddresses, upstreams, dnsLogFile);

      await manageDnsRedirectRule(
        'iptables',
        wgInterface.name,
        'udp',
        serverV4,
        'A'
      );
      await manageDnsRedirectRule(
        'iptables',
        wgInterface.name,
        'tcp',
        serverV4,
        'A'
      );
      if (serverV6 !== null) {
        await manageDnsRedirectRule(
          'ip6tables',
          wgInterface.name,
          'udp',
          serverV6,
          'A'
        );
        await manageDnsRedirectRule(
          'ip6tables',
          wgInterface.name,
          'tcp',
          serverV6,
          'A'
        );
      }
    }

    state.dnsTailTimer = setIntervalImmediately(() => {
      void tailDnsLog(dnsLogFile, accessLogFile).catch((err) =>
        AL_DEBUG('DNS tail failed:', err)
      );
    }, 2000);

    state.trafficTimer = setIntervalImmediately(
      () => {
        void snapshotTraffic(wgInterface.name, trafficLogFile).catch((err) =>
          AL_DEBUG('Traffic snapshot failed:', err)
        );
      },
      WG_ENV.ACCESS_LOG_TRAFFIC_INTERVAL_MINUTES * 60 * 1000
    );

    state.running = true;
    console.log(
      `Access logging enabled. Website visits -> ${accessLogFile}, traffic usage -> ${trafficLogFile}`
    );
  },

  async stop(wgInterface: InterfaceType): Promise<void> {
    for (const timer of [
      state.dnsTailTimer,
      state.trafficTimer,
      state.clientMapTimer,
    ]) {
      if (timer) clearInterval(timer);
    }
    state.dnsTailTimer = undefined;
    state.trafficTimer = undefined;
    state.clientMapTimer = undefined;

    state.dnsmasqProc?.kill();
    state.dnsmasqProc = undefined;
    state.dnsLogOffset = 0;

    if (process.platform === 'linux') {
      const serverV4 = serverTunnelIp(wgInterface.ipv4Cidr);
      await manageDnsRedirectRule(
        'iptables',
        wgInterface.name,
        'udp',
        serverV4,
        'D'
      );
      await manageDnsRedirectRule(
        'iptables',
        wgInterface.name,
        'tcp',
        serverV4,
        'D'
      );
      if (!WG_ENV.DISABLE_IPV6) {
        const serverV6 = serverTunnelIp6(wgInterface.ipv6Cidr);
        await manageDnsRedirectRule(
          'ip6tables',
          wgInterface.name,
          'udp',
          serverV6,
          'D'
        );
        await manageDnsRedirectRule(
          'ip6tables',
          wgInterface.name,
          'tcp',
          serverV6,
          'D'
        );
      }
    }

    state.running = false;
    AL_DEBUG('Access logging stopped.');
  },
};

export const accessLogTestExports = {
  parseDnsmasqQueryLine,
  formatAccessLogLine,
  formatTrafficLogLine,
};
