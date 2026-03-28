/**
 * useMockGadgetStream — simulates live Inspektor Gadget WebSocket telemetry.
 *
 * Addresses upstream issue #17: Security-focused UX Improvements for the
 * Inspektor Gadget Headlamp Plugin (github.com/inspektor-gadget/headlamp-plugin).
 *
 * This is the data engine for the eBPF Monitor (#15), Traffic Visualizer (#16),
 * and Install Wizard (#13) dashboards. All downstream components import their
 * interfaces from here.
 */

import { useEffect, useRef, useState } from 'react';

// ─── Exported interfaces ────────────────────────────────────────────────────

/** Schema matching the real bpfstats gadget output from Inspektor Gadget. */
export interface BPFProgramStats {
  /** BPF program ID (kernel assigned) */
  id: number;
  /** e.g. "kprobe__tcp_connect", "xdp_redirect" */
  name: string;
  /** e.g. "kprobe", "xdp", "tracepoint", "cgroup_skb" */
  type: string;
  /** 8-byte hex tag e.g. "a34f2c1e8b0d4567" */
  tag: string;
  /** Kubernetes node name */
  node: string;
  /** Kubernetes namespace */
  namespace: string;
  /** Pod name */
  pod: string;
  /** Container name */
  container: string;
  /** Number of times the program ran */
  runCount: number;
  /** Total runtime in nanoseconds */
  runTimeNs: number;
  /** Derived CPU usage % */
  cpuPercent: number;
  /** BPF map memory usage in bytes */
  memoryBytes: number;
  /** Average runtime per execution in nanoseconds */
  avgRunTimeNs: number;
}

/** A single HTTP request captured by the traffic sniffer. */
export interface HTTPRequest {
  timestamp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  statusCode: number;
  latencyMs: number;
  srcPod: string;
  dstPod: string;
}

/** A node in the cluster traffic graph. */
export interface TrafficNode {
  id: string;
  /** Pod/service display name */
  label: string;
  namespace: string;
  ip: string;
  port: number;
  kind: 'pod' | 'service' | 'external';
  /** SVG layout x position */
  x: number;
  /** SVG layout y position */
  y: number;
}

/** A directed traffic edge between two nodes. */
export interface TrafficEdge {
  id: string;
  /** Source node id */
  source: string;
  /** Target node id */
  target: string;
  protocol: 'HTTP' | 'TCP' | 'UDP' | 'DNS';
  bytesPerSec: number;
  packetsPerSec: number;
  droppedPackets: number;
  latencyMs: number;
  /** Last 5 captured requests on this edge */
  recentRequests: HTTPRequest[];
}

/** Full traffic graph snapshot. */
export interface TrafficGraph {
  nodes: TrafficNode[];
  edges: TrafficEdge[];
  captureStartTime: string;
  totalPackets: number;
  droppedPackets: number;
}

export type DNSRCode = 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'TIMEOUT';

export interface DNSQuery {
  id: string;
  timestamp: number;
  namespace: string;
  pod: string;
  container: string;
  domain: string;
  qtype: 'A' | 'AAAA' | 'CNAME';
  rcode: DNSRCode;
  latencyMs: number;
  retryCount: number;
  resolvedIP: string | null;
  isExternal: boolean;
  flagged: boolean;
  flagReason: string | null;
}

export interface DNSSnapshot {
  queries: DNSQuery[];
  totalQueries: number;
  failedQueries: number;
  retryStorms: { domain: string; pod: string; count: number }[];
  suspiciousDomains: string[];
  captureWindow: string;
}

// ─── Static base data ───────────────────────────────────────────────────────

interface ProgramBase {
  id: number;
  name: string;
  type: string;
  tag: string;
  node: string;
  namespace: string;
  pod: string;
  container: string;
  baseCpu: number;
  phase: number;
  avgRunTimeNs: number;
  baseMemoryBytes: number;
  baseRunCount: number;
}

const STATIC_PROGRAMS: readonly ProgramBase[] = [
  {
    id: 1,
    name: 'kprobe__tcp_connect',
    type: 'kprobe',
    tag: 'a34f2c1e8b0d4567',
    node: 'node-1',
    namespace: 'gadget',
    pod: 'gadget-node-1',
    container: 'gadget',
    baseCpu: 2.1,
    phase: 0.0,
    avgRunTimeNs: 4200,
    baseMemoryBytes: 32768,
    baseRunCount: 142000,
  },
  {
    id: 2,
    name: 'tracepoint__net__netif_receive_skb',
    type: 'tracepoint',
    tag: 'b72e1a3f9c048d21',
    node: 'node-2',
    namespace: 'gadget',
    pod: 'gadget-node-2',
    container: 'gadget',
    baseCpu: 3.4,
    phase: 0.7,
    avgRunTimeNs: 8900,
    baseMemoryBytes: 65536,
    baseRunCount: 98000,
  },
  {
    id: 3,
    name: 'xdp_redirect_map',
    type: 'xdp',
    tag: 'c81b5d2e7f3a9046',
    node: 'node-1',
    namespace: 'kube-system',
    pod: 'cilium-xxhj4',
    container: 'cilium-agent',
    baseCpu: 1.8,
    phase: 1.4,
    avgRunTimeNs: 1800,
    baseMemoryBytes: 16384,
    baseRunCount: 310000,
  },
  {
    id: 4,
    name: 'cgroup_skb__egress',
    type: 'cgroup_skb',
    tag: 'd94c6f1a2b8e3057',
    node: 'node-3',
    namespace: 'kube-system',
    pod: 'cilium-7mq9r',
    container: 'cilium-agent',
    baseCpu: 0.9,
    phase: 2.1,
    avgRunTimeNs: 2300,
    baseMemoryBytes: 8192,
    baseRunCount: 220000,
  },
  {
    id: 5,
    name: 'kprobe__sys_execve',
    type: 'kprobe',
    tag: 'e05d7a3b4c9f2168',
    node: 'node-1',
    namespace: 'default',
    pod: 'api-gateway-7b9d6f',
    container: 'api-gateway',
    baseCpu: 4.2,
    phase: 2.8,
    avgRunTimeNs: 12400,
    baseMemoryBytes: 49152,
    baseRunCount: 54000,
  },
  {
    id: 6,
    name: 'kretprobe__sys_open',
    type: 'kretprobe',
    tag: 'f16e8b4c5d0a3279',
    node: 'node-2',
    namespace: 'default',
    pod: 'auth-service-4c8f9b',
    container: 'auth-service',
    baseCpu: 1.5,
    phase: 3.5,
    avgRunTimeNs: 3100,
    baseMemoryBytes: 24576,
    baseRunCount: 187000,
  },
  {
    id: 7,
    name: 'tracepoint__syscalls__sys_enter_write',
    type: 'tracepoint',
    tag: '0a27f9c6e1b40d38',
    node: 'node-3',
    namespace: 'default',
    pod: 'frontend-8a2c1e',
    container: 'frontend',
    baseCpu: 6.1,
    phase: 0.3,
    avgRunTimeNs: 5700,
    baseMemoryBytes: 40960,
    baseRunCount: 426000,
  },
  {
    id: 8,
    name: 'xdp_pass',
    type: 'xdp',
    tag: '1b38aed7f2c50e49',
    node: 'node-2',
    namespace: 'kube-system',
    pod: 'cilium-k8n2p',
    container: 'cilium-agent',
    baseCpu: 0.4,
    phase: 1.1,
    avgRunTimeNs: 900,
    baseMemoryBytes: 4096,
    baseRunCount: 580000,
  },
  {
    id: 9,
    name: 'cgroup_skb__ingress',
    type: 'cgroup_skb',
    tag: '2c49bfe8a3d61f5a',
    node: 'node-1',
    namespace: 'kube-system',
    pod: 'cilium-xxhj4',
    container: 'cilium-agent',
    baseCpu: 2.7,
    phase: 4.2,
    avgRunTimeNs: 2100,
    baseMemoryBytes: 8192,
    baseRunCount: 195000,
  },
  {
    id: 10,
    name: 'kprobe__tcp_close',
    type: 'kprobe',
    tag: '3d5ac0f9b4e72a6b',
    node: 'node-3',
    namespace: 'default',
    pod: 'postgres-5d7f8c',
    container: 'postgres',
    baseCpu: 1.2,
    phase: 5.0,
    avgRunTimeNs: 3800,
    baseMemoryBytes: 20480,
    baseRunCount: 73000,
  },
];

/** Hardcoded SVG positions for the 6-node microservice topology. */
const STATIC_NODES: readonly TrafficNode[] = [
  {
    id: 'frontend',
    label: 'frontend',
    namespace: 'default',
    ip: '10.0.1.10',
    port: 3000,
    kind: 'pod',
    x: 80,
    y: 220,
  },
  {
    id: 'api-gateway',
    label: 'api-gateway',
    namespace: 'default',
    ip: '10.0.1.20',
    port: 8080,
    kind: 'service',
    x: 280,
    y: 220,
  },
  {
    id: 'auth-service',
    label: 'auth-service',
    namespace: 'default',
    ip: '10.0.1.30',
    port: 4000,
    kind: 'pod',
    x: 460,
    y: 100,
  },
  {
    id: 'postgres',
    label: 'postgres',
    namespace: 'default',
    ip: '10.0.1.40',
    port: 5432,
    kind: 'pod',
    x: 460,
    y: 280,
  },
  {
    id: 'redis',
    label: 'redis',
    namespace: 'default',
    ip: '10.0.1.50',
    port: 6379,
    kind: 'pod',
    x: 460,
    y: 380,
  },
  {
    id: 'external-dns',
    label: 'external-dns',
    namespace: 'kube-system',
    ip: '10.0.0.10',
    port: 53,
    kind: 'external',
    x: 660,
    y: 220,
  },
];

// ─── HTTP request generation helpers ────────────────────────────────────────

const HTTP_METHODS: ReadonlyArray<HTTPRequest['method']> = ['GET', 'POST', 'PUT', 'DELETE'];

const EDGE_PATHS: Readonly<Record<string, readonly string[]>> = {
  e1: ['/api/v1/products', '/api/v1/users', '/healthz', '/api/v1/cart', '/metrics'],
  e2: ['/auth/verify', '/auth/token', '/auth/refresh', '/auth/logout', '/auth/introspect'],
  e3: [
    '/query/users',
    '/query/sessions',
    '/query/orders',
    '/query/products',
    '/query/inventory',
  ],
  e4: ['/cache/session', '/cache/user', '/cache/rate-limit', '/cache/features', '/pub/events'],
  e5: ['/resolve/api-gateway', '/resolve/auth-service', '/resolve/postgres', '/resolve/redis'],
};

const STATUS_WEIGHTS: ReadonlyArray<{ code: number; weight: number }> = [
  { code: 200, weight: 70 },
  { code: 201, weight: 10 },
  { code: 304, weight: 5 },
  { code: 401, weight: 5 },
  { code: 404, weight: 5 },
  { code: 500, weight: 5 },
];

function weightedStatus(): number {
  const total = STATUS_WEIGHTS.reduce((s, w) => s + w.weight, 0);
  let r = Math.random() * total;
  for (const { code, weight } of STATUS_WEIGHTS) {
    r -= weight;
    if (r <= 0) return code;
  }
  return 200;
}

function makeRequest(edgeId: string, srcPod: string, dstPod: string): HTTPRequest {
  const paths = EDGE_PATHS[edgeId] ?? ['/'];
  return {
    timestamp: new Date().toISOString(),
    method: HTTP_METHODS[Math.floor(Math.random() * HTTP_METHODS.length)],
    path: paths[Math.floor(Math.random() * paths.length)],
    statusCode: weightedStatus(),
    latencyMs: Math.floor(Math.random() * 120 + 5),
    srcPod,
    dstPod,
  };
}

// ─── Per-tick generators ─────────────────────────────────────────────────────

/**
 * Generates a BPFProgramStats snapshot for all programs at the given tick.
 * CPU drifts via sine wave + noise; kprobe__sys_execve spikes above 15% every 15 ticks.
 */
function generateBPFStats(tick: number): BPFProgramStats[] {
  return STATIC_PROGRAMS.map(p => {
    let cpuPercent: number;

    if (p.name === 'kprobe__sys_execve' && tick % 15 < 2) {
      // Spike: deliberate security signal
      cpuPercent = 17 + Math.random() * 5;
    } else {
      const noise = (Math.random() - 0.5) * 0.8;
      cpuPercent = p.baseCpu + Math.sin(tick * 0.3 + p.phase) * (p.baseCpu * 0.4) + noise;
      cpuPercent = Math.max(0, cpuPercent);
    }

    const runCountDelta = Math.floor(Math.random() * 500 + 100);
    const runCount = p.baseRunCount + tick * runCountDelta;
    const runTimeNs = runCount * p.avgRunTimeNs;
    const memoryBytes = p.baseMemoryBytes + Math.floor(Math.random() * 4096);

    return {
      id: p.id,
      name: p.name,
      type: p.type,
      tag: p.tag,
      node: p.node,
      namespace: p.namespace,
      pod: p.pod,
      container: p.container,
      runCount,
      runTimeNs,
      cpuPercent: Math.round(cpuPercent * 100) / 100,
      memoryBytes,
      avgRunTimeNs: p.avgRunTimeNs,
    };
  });
}

/** Rolling request buffer — keyed by edge id, shared across ticks via module-level state. */
const recentRequestsCache: Record<string, HTTPRequest[]> = {};

interface EdgeBase {
  id: string;
  source: string;
  target: string;
  protocol: TrafficEdge['protocol'];
  baseBytesPerSec: number;
  basePacketsPerSec: number;
  baseLatencyMs: number;
  srcPodLabel: string;
  dstPodLabel: string;
}

const STATIC_EDGES: readonly EdgeBase[] = [
  {
    id: 'e1',
    source: 'frontend',
    target: 'api-gateway',
    protocol: 'HTTP',
    baseBytesPerSec: 24000,
    basePacketsPerSec: 180,
    baseLatencyMs: 8,
    srcPodLabel: 'frontend-8a2c1e',
    dstPodLabel: 'api-gateway-7b9d6f',
  },
  {
    id: 'e2',
    source: 'api-gateway',
    target: 'auth-service',
    protocol: 'HTTP',
    baseBytesPerSec: 9800,
    basePacketsPerSec: 70,
    baseLatencyMs: 14,
    srcPodLabel: 'api-gateway-7b9d6f',
    dstPodLabel: 'auth-service-4c8f9b',
  },
  {
    id: 'e3',
    source: 'api-gateway',
    target: 'postgres',
    protocol: 'TCP',
    baseBytesPerSec: 41000,
    basePacketsPerSec: 310,
    baseLatencyMs: 3,
    srcPodLabel: 'api-gateway-7b9d6f',
    dstPodLabel: 'postgres-5d7f8c',
  },
  {
    id: 'e4',
    source: 'api-gateway',
    target: 'redis',
    protocol: 'TCP',
    baseBytesPerSec: 18500,
    basePacketsPerSec: 140,
    baseLatencyMs: 1,
    srcPodLabel: 'api-gateway-7b9d6f',
    dstPodLabel: 'redis-3e6c2a',
  },
  {
    id: 'e5',
    source: 'auth-service',
    target: 'external-dns',
    protocol: 'DNS',
    baseBytesPerSec: 1200,
    basePacketsPerSec: 12,
    baseLatencyMs: 22,
    srcPodLabel: 'auth-service-4c8f9b',
    dstPodLabel: 'external-dns-coredns',
  },
];

let cumulativePackets = 0;
let cumulativeDropped = 0;
const CAPTURE_START = new Date().toISOString();

/**
 * Generates a TrafficGraph snapshot at the given tick.
 * Edge e2 (api-gateway→auth-service) carries intermittent packet drops as the security signal.
 */
function generateTrafficGraph(tick: number): TrafficGraph {
  const edges: TrafficEdge[] = STATIC_EDGES.map(e => {
    const jitter = (Math.random() - 0.5) * 0.2;
    const bytesPerSec = Math.floor(e.baseBytesPerSec * (1 + jitter));
    const packetsPerSec = Math.floor(e.basePacketsPerSec * (1 + jitter));
    const latencyMs = Math.round(e.baseLatencyMs * (1 + Math.abs(jitter)));

    // Security signal: intermittent drops on api-gateway→auth-service
    const droppedPackets =
      e.id === 'e2' && tick % 7 < 2 ? Math.floor(Math.random() * 15 + 5) : 0;

    // Rolling request buffer — prepend newest, cap at 5
    if (!recentRequestsCache[e.id]) {
      recentRequestsCache[e.id] = Array.from({ length: 5 }, () =>
        makeRequest(e.id, e.srcPodLabel, e.dstPodLabel)
      );
    } else {
      recentRequestsCache[e.id] = [
        makeRequest(e.id, e.srcPodLabel, e.dstPodLabel),
        ...recentRequestsCache[e.id].slice(0, 4),
      ];
    }

    return {
      id: e.id,
      source: e.source,
      target: e.target,
      protocol: e.protocol,
      bytesPerSec,
      packetsPerSec,
      droppedPackets,
      latencyMs,
      recentRequests: recentRequestsCache[e.id],
    };
  });

  const tickPackets = edges.reduce((s, e) => s + e.packetsPerSec * 3, 0);
  const tickDropped = edges.reduce((s, e) => s + e.droppedPackets, 0);
  cumulativePackets += Math.floor(tickPackets);
  cumulativeDropped += tickDropped;

  return {
    nodes: STATIC_NODES as TrafficNode[],
    edges,
    captureStartTime: CAPTURE_START,
    totalPackets: cumulativePackets,
    droppedPackets: cumulativeDropped,
  };
}

// ─── DNS mock data ────────────────────────────────────────────────────────────

const DNS_PODS = ['api-gateway-5c8b', 'auth-service-3d7a', 'frontend-9e2f', 'worker-4a1c'] as const;
const DNS_NAMESPACES = ['default', 'default', 'default', 'kube-system'] as const;
const DNS_INTERNAL = [
  'auth-service.default.svc.cluster.local',
  'postgres.default.svc.cluster.local',
  'redis.default.svc.cluster.local',
  'metrics-server.kube-system.svc.cluster.local',
] as const;
const DNS_EXTERNAL = [
  'api.github.com',
  'storage.googleapis.com',
  'registry-1.docker.io',
  'pastebin.com',
  'pypi.org',
  'c2.malicious-example.io',
] as const;
const SUSPICIOUS_DOMAINS = new Set(['pastebin.com', 'c2.malicious-example.io']);

const QTYPES: ReadonlyArray<DNSQuery['qtype']> = ['A', 'AAAA', 'CNAME'];
const RCODES: ReadonlyArray<DNSRCode> = ['NOERROR', 'NOERROR', 'NOERROR', 'NXDOMAIN', 'SERVFAIL', 'TIMEOUT'];

function makeDNSQuery(
  tick: number,
  i: number,
  forceFailure?: DNSRCode,
  forceExternal?: boolean
): DNSQuery {
  const podIdx = i % DNS_PODS.length;
  const pod = DNS_PODS[podIdx];
  const namespace = DNS_NAMESPACES[podIdx];
  const isExternal = forceExternal ?? Math.random() < 0.3;
  const domainPool = isExternal ? DNS_EXTERNAL : DNS_INTERNAL;
  const domain = domainPool[Math.floor(Math.random() * domainPool.length)];
  const rcode = forceFailure ?? RCODES[Math.floor(Math.random() * RCODES.length)];
  const isSuspicious = SUSPICIOUS_DOMAINS.has(domain);

  let latencyMs: number;
  if (rcode === 'TIMEOUT') {
    latencyMs = 5000 + Math.floor(Math.random() * 3000);
  } else if (rcode !== 'NOERROR') {
    latencyMs = Math.floor(Math.random() * 400 + 50);
  } else {
    latencyMs = Math.floor(Math.random() * 150 + 5);
  }

  let flagged = isSuspicious;
  let flagReason: string | null = null;
  if (rcode === 'NXDOMAIN') {
    flagged = true;
    flagReason = 'misconfiguration';
  } else if (rcode === 'TIMEOUT') {
    flagged = true;
    flagReason = 'resolver overload';
  } else if (isSuspicious) {
    flagReason = `Suspicious domain: ${domain}`;
  }

  return {
    id: `q-${tick}-${i}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: Date.now() - i * 1200 - Math.random() * 800,
    namespace,
    pod,
    container: pod.split('-').slice(0, -1).join('-'),
    domain,
    qtype: QTYPES[Math.floor(Math.random() * QTYPES.length)],
    rcode,
    latencyMs,
    retryCount: rcode !== 'NOERROR' ? Math.floor(Math.random() * 3) : 0,
    resolvedIP:
      rcode === 'NOERROR'
        ? `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
        : null,
    isExternal,
    flagged,
    flagReason,
  };
}

function makeDNSSnapshot(tick: number): DNSSnapshot {
  const queries: DNSQuery[] = [];

  for (let i = 0; i < 18; i++) {
    queries.push(makeDNSQuery(tick, i));
  }

  for (let i = 0; i < 7; i++) {
    const q = makeDNSQuery(tick, 100 + i, 'NXDOMAIN', false);
    queries.push({
      ...q,
      pod: 'api-gateway-5c8b',
      namespace: 'default',
      container: 'api-gateway',
      domain: 'auth-service.default.svc.cluster.local',
      retryCount: 2 + i,
      flagged: true,
      flagReason: 'Retry storm — 7 retries in 3s window',
    });
  }

  queries.push({
    id: `q-${tick}-c2-beacon`,
    timestamp: Date.now() - 200,
    namespace: 'kube-system',
    pod: 'worker-4a1c',
    container: 'worker',
    domain: 'c2.malicious-example.io',
    qtype: 'A',
    rcode: 'NOERROR',
    latencyMs: 42,
    retryCount: 0,
    resolvedIP: '185.220.101.47',
    isExternal: true,
    flagged: true,
    flagReason: 'Suspicious domain: c2.malicious-example.io',
  });

  queries.sort((a, b) => b.timestamp - a.timestamp);

  const stormMap: Record<string, { domain: string; pod: string; count: number }> = {};
  for (const q of queries) {
    const key = `${q.pod}::${q.domain}`;
    if (!stormMap[key]) stormMap[key] = { domain: q.domain, pod: q.pod, count: 0 };
    stormMap[key].count++;
  }
  const retryStorms = Object.values(stormMap).filter(s => s.count >= 5);

  const failedQueries = queries.filter(q => q.rcode !== 'NOERROR').length;
  const suspiciousDomains = [
    ...new Set(queries.filter(q => SUSPICIOUS_DOMAINS.has(q.domain)).map(q => q.domain)),
  ];

  return {
    queries,
    totalQueries: queries.length,
    failedQueries,
    retryStorms,
    suspiciousDomains,
    captureWindow: `Last ${Math.min(tick * 2 + 5, 60)}s`,
  };
}

export function getDNSQueriesForPod(snapshot: DNSSnapshot, podId: string): DNSQuery[] {
  return snapshot.queries.filter(q => q.pod.startsWith(podId));
}

// ─── Hook ────────────────────────────────────────────────────────────────────

/**
 * Simulates a live Inspektor Gadget WebSocket stream for eBPF program telemetry.
 * Updates every 2 seconds. Addresses upstream issues #15 and #17.
 * @param type - 'ebpftop' to receive BPF program stats
 */
export function useMockGadgetStream(type: 'ebpftop'): BPFProgramStats[];

/**
 * Simulates a live Inspektor Gadget WebSocket stream for cluster traffic.
 * Updates every 3 seconds. Addresses upstream issues #16 and #17.
 * @param type - 'traffic' to receive a traffic graph snapshot
 */
export function useMockGadgetStream(type: 'traffic'): TrafficGraph;

/**
 * Simulates a live Inspektor Gadget WebSocket stream for DNS query telemetry.
 * Updates every 2.5 seconds. Addresses upstream issues #17.
 * @param type - 'dns' to receive a DNS snapshot
 */
export function useMockGadgetStream(type: 'dns'): DNSSnapshot;

/**
 * Overload implementation — consumers should use the typed overloads above.
 */
export function useMockGadgetStream(
  type: 'ebpftop' | 'traffic' | 'dns'
): BPFProgramStats[] | TrafficGraph | DNSSnapshot {
  const intervalMs = type === 'ebpftop' ? 2000 : type === 'dns' ? 2500 : 3000;

  const tickRef = useRef<number>(0);
  const mountedRef = useRef<boolean>(true);

  const [data, setData] = useState<BPFProgramStats[] | TrafficGraph | DNSSnapshot>(() =>
    type === 'ebpftop' ? generateBPFStats(0) : type === 'dns' ? makeDNSSnapshot(0) : generateTrafficGraph(0)
  );

  // Track mount status — mirrors igSocket.tsx pattern
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Streaming interval — cleans up on unmount or type change
  useEffect(() => {
    tickRef.current = 0;

    const interval = setInterval(() => {
      tickRef.current += 1;
      if (!mountedRef.current) return;

      if (type === 'ebpftop') {
        setData(generateBPFStats(tickRef.current));
      } else if (type === 'dns') {
        setData(makeDNSSnapshot(tickRef.current));
      } else {
        setData(generateTrafficGraph(tickRef.current));
      }
    }, intervalMs);

    return () => clearInterval(interval);
  }, [type, intervalMs]);

  return data;
}
