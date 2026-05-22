import net from 'node:net';
import tls from 'node:tls';
import { NextResponse } from 'next/server';
import { validateHost, isRateLimited, getClientIp, safeFetch } from '@/lib/ssrf-guard';

export const runtime = 'nodejs';

const SCANNER_URL = process.env.SCANNER_URL || '';
const SCANNER_KEY = process.env.SCANNER_KEY || '';

const ALLOWED_SCANS: Record<string, { endpoint: string; timeout: number }> = {
  quick: { endpoint: '/scan/quick', timeout: 15000 },
  ssl: { endpoint: '/scan/ssl', timeout: 10000 },
  headers: { endpoint: '/scan/headers', timeout: 10000 },
  rdns: { endpoint: '/scan/rdns', timeout: 8000 },
  subdomains: { endpoint: '/scan/subdomains', timeout: 15000 },
  tech: { endpoint: '/scan/tech', timeout: 15000 },
  whois: { endpoint: '/scan/whois', timeout: 10000 },
  geoloc: { endpoint: '/scan/geoloc', timeout: 8000 },
  vuln: { endpoint: '/scan/vuln', timeout: 90000 },
};

const LOCAL_SCANS = new Set(['quick', 'headers', 'ssl', 'tech', 'vuln']);
const COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443];
const SERVICE_NAMES: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  143: 'imap',
  443: 'https',
  465: 'smtps',
  587: 'submission',
  993: 'imaps',
  995: 'pop3s',
  3306: 'mysql',
  3389: 'rdp',
  5432: 'postgresql',
  6379: 'redis',
  8080: 'http-alt',
  8443: 'https-alt',
};

function normalizeTarget(rawTarget: string): { host: string; url: string } {
  const candidate = rawTarget.includes('://') ? rawTarget : `https://${rawTarget}`;
  try {
    const parsed = new URL(candidate);
    return { host: parsed.hostname, url: parsed.toString() };
  } catch {
    return { host: rawTarget, url: `https://${rawTarget}` };
  }
}

function scanPort(host: string, port: number): Promise<{ port: number; state: 'open' | 'closed'; service: string }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, timeout: 1200 });
    const finish = (state: 'open' | 'closed') => {
      socket.destroy();
      resolve({ port, state, service: SERVICE_NAMES[port] || 'unknown' });
    };
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('closed'));
    socket.once('error', () => finish('closed'));
  });
}

async function quickScan(host: string) {
  const started = Date.now();
  const scanned = await Promise.all(COMMON_PORTS.map((port) => scanPort(host, port)));
  const ports = scanned.filter((p) => p.state === 'open');
  return {
    target: host,
    scan_type: 'quick',
    ports,
    open_ports: ports,
    scanned_ports: COMMON_PORTS.length,
    duration: `${Date.now() - started}ms`,
    source: 'built-in',
  };
}

async function headerScan(url: string) {
  const res = await safeFetch(url, {
    method: 'HEAD',
    signal: AbortSignal.timeout(8000),
    maxRedirects: 3,
    headers: { 'User-Agent': 'Panoptes-Scanner/1.0' },
  });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => { headers[key] = value; });
  return {
    target: url,
    status: res.status,
    final_url: res.url,
    headers,
    source: 'built-in',
  };
}

async function sslScan(host: string) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve({
        target: host,
        issuer: cert.issuer?.O || cert.issuer?.CN,
        subject: cert.subject?.CN,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        fingerprint: cert.fingerprint256,
        source: 'built-in',
      });
    });
    socket.once('timeout', () => {
      socket.destroy();
      reject(new Error('TLS connection timed out'));
    });
    socket.once('error', reject);
  });
}

function detectTechnologies(headers: Record<string, string>, html: string) {
  const haystack = `${JSON.stringify(headers)}\n${html}`.toLowerCase();
  const technologies: string[] = [];
  const checks: Array<[string, RegExp]> = [
    ['Next.js', /x-nextjs|next-router|__next/],
    ['React', /react|__react/],
    ['Vue', /vue/],
    ['Angular', /ng-version|angular/],
    ['WordPress', /wp-content|wp-includes|x-powered-by.*wordpress/],
    ['Cloudflare', /cloudflare|cf-ray|cf-cache-status/],
    ['nginx', /server["']?:["']?nginx|nginx/],
    ['Apache', /server["']?:["']?apache|apache/],
    ['Express', /x-powered-by["']?:["']?express|express/],
    ['Vercel', /vercel|x-vercel/],
  ];
  for (const [name, pattern] of checks) {
    if (pattern.test(haystack) && !technologies.includes(name)) technologies.push(name);
  }
  return technologies;
}

async function techScan(url: string) {
  const res = await safeFetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(10000),
    maxRedirects: 3,
    headers: { 'User-Agent': 'Panoptes-Scanner/1.0' },
  });
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => { headers[key] = value; });
  const html = (await res.text()).slice(0, 250_000);
  return {
    target: url,
    status: res.status,
    final_url: res.url,
    technologies: detectTechnologies(headers, html),
    headers: {
      server: headers.server,
      'x-powered-by': headers['x-powered-by'],
      'cf-cache-status': headers['cf-cache-status'],
    },
    source: 'built-in',
  };
}

async function vulnScan(host: string, url: string) {
  const [ports, tech] = await Promise.allSettled([quickScan(host), techScan(url)]);
  const openPorts = ports.status === 'fulfilled' ? ports.value.ports : [];
  const technologies = tech.status === 'fulfilled' ? tech.value.technologies : [];
  const findings = [];
  if (openPorts.some((p) => p.port === 21)) findings.push({ id: 'FTP_EXPOSED', severity: 'MEDIUM', description: 'FTP is reachable on the public target.' });
  if (openPorts.some((p) => p.port === 3306 || p.port === 5432 || p.port === 6379)) findings.push({ id: 'DATABASE_PORT_EXPOSED', severity: 'HIGH', description: 'A common database service is reachable on the public target.' });
  if (openPorts.some((p) => p.port === 3389)) findings.push({ id: 'RDP_EXPOSED', severity: 'HIGH', description: 'Remote Desktop is reachable on the public target.' });
  return {
    target: host,
    risk_level: findings.some((f) => f.severity === 'HIGH') ? 'HIGH' : findings.length ? 'MEDIUM' : 'LOW',
    vulnerabilities: findings,
    open_ports: openPorts,
    technologies,
    note: 'Built-in assessment uses lightweight exposure checks. Configure SCANNER_URL and SCANNER_KEY for deeper CVE fingerprinting.',
    source: 'built-in',
  };
}

export async function GET(req: Request) {
  const clientIp = getClientIp(req);
  if (isRateLimited(clientIp, 10, 60_000)) {
    return NextResponse.json({ error: 'Rate limit exceeded', detail: 'Maximum 10 scans per minute.' }, { status: 429 });
  }

  const { searchParams } = new URL(req.url);
  const rawTarget = searchParams.get('target')?.trim();
  const scanType = searchParams.get('type') || 'quick';

  if (!rawTarget) return NextResponse.json({ error: 'Missing target parameter' }, { status: 400 });

  const scanConfig = ALLOWED_SCANS[scanType];
  if (!scanConfig) {
    return NextResponse.json({
      error: 'Scan type not available',
      detail: `"${scanType}" is restricted. Available: ${Object.keys(ALLOWED_SCANS).join(', ')}`,
      available_scans: Object.keys(ALLOWED_SCANS),
    }, { status: 403 });
  }

  const { host, url } = normalizeTarget(rawTarget);
  const guard = await validateHost(host);
  if (!guard.ok) {
    return NextResponse.json({ error: 'Target blocked', detail: `Target validation failed: ${guard.reason}` }, { status: 403 });
  }

  if (SCANNER_URL && SCANNER_KEY) {
    try {
      const params = new URLSearchParams({ key: SCANNER_KEY, target: rawTarget });
      const res = await fetch(`${SCANNER_URL}${scanConfig.endpoint}?${params.toString()}`, {
        signal: AbortSignal.timeout(scanConfig.timeout),
      });
      const data = await res.json();
      return NextResponse.json(data, { status: res.status });
    } catch {
      if (!LOCAL_SCANS.has(scanType)) {
        return NextResponse.json({ error: 'Scanner unreachable', detail: 'External scanner failed and no built-in fallback exists for this scan type.' }, { status: 502 });
      }
    }
  }

  if (!LOCAL_SCANS.has(scanType)) {
    return NextResponse.json({
      error: 'External scanner required',
      hint: 'Set SCANNER_URL and SCANNER_KEY in .env.local for this scan type.',
      built_in_scans: Array.from(LOCAL_SCANS),
    }, { status: 503 });
  }

  try {
    if (scanType === 'quick') return NextResponse.json(await quickScan(host));
    if (scanType === 'headers') return NextResponse.json(await headerScan(url));
    if (scanType === 'ssl') return NextResponse.json(await sslScan(host));
    if (scanType === 'tech') return NextResponse.json(await techScan(url));
    if (scanType === 'vuln') return NextResponse.json(await vulnScan(host, url));
  } catch (e: any) {
    return NextResponse.json({ error: 'Built-in scan failed', detail: e.message }, { status: 502 });
  }
}
