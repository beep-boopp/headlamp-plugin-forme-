/**
 * TrafficVisualizer — live cluster service-to-service traffic map.
 *
 * Addresses upstream issue #16: [RFE] Capturing and Visualizing Kubernetes API Traffic
 * github.com/inspektor-gadget/headlamp-plugin/issues/16
 */

import { Icon } from '@iconify/react';
import {
  Alert,
  Box,
  Chip,
  Drawer,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Typography,
  useTheme,
} from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { HTTPRequest, TrafficEdge, TrafficNode, useMockGadgetStream } from '../common/useMockGadgetStream';
import { useMockGadgetStream as useDNSStream, getDNSQueriesForPod, DNSQuery } from '../common/useMockGadgetStream';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function edgeStrokeWidth(bytesPerSec: number): number {
  return Math.min(6, Math.max(1, Math.log(bytesPerSec) * 0.8));
}

function statusColor(
  code: number,
  theme: ReturnType<typeof useTheme>
): string {
  if (code >= 500) return theme.palette.error.main;
  if (code >= 400) return theme.palette.warning.main;
  return theme.palette.success.main;
}


// ─── Method chip ─────────────────────────────────────────────────────────────

function MethodChip({ method }: { method: HTTPRequest['method'] }) {
  const theme = useTheme();
  const colorMap: Record<HTTPRequest['method'], string> = {
    GET: theme.palette.info.main,
    POST: theme.palette.success.main,
    PUT: theme.palette.warning.main,
    DELETE: theme.palette.error.main,
  };
  return (
    <Chip
      label={method}
      size="small"
      sx={{ bgcolor: colorMap[method], color: '#fff', fontWeight: 'bold', fontSize: 10 }}
    />
  );
}

// ─── SVG edge ────────────────────────────────────────────────────────────────

interface SvgEdgeProps {
  edge: TrafficEdge;
  sourceNode: TrafficNode;
  targetNode: TrafficNode;
  theme: ReturnType<typeof useTheme>;
  /** index used to offset control point so parallel edges don't overlap */
  edgeIndex: number;
}

function SvgEdge({ edge, sourceNode, targetNode, theme, edgeIndex }: SvgEdgeProps) {
  const x1 = sourceNode.x;
  const y1 = sourceNode.y;
  const x2 = targetNode.x;
  const y2 = targetNode.y;

  const midX = (x1 + x2) / 2;
  const midY = (y1 + y2) / 2;
  // Slight vertical offset so parallel edges don't overlap
  const controlY = midY + edgeIndex * 18;

  const pathD = `M ${x1} ${y1} Q ${midX} ${controlY} ${x2} ${y2}`;
  const isDrop = edge.droppedPackets > 0;
  const strokeColor = isDrop ? theme.palette.error.main : theme.palette.primary.main;
  const strokeWidth = edgeStrokeWidth(edge.bytesPerSec);

  const animStyle: React.CSSProperties = isDrop
    ? {}
    : {
        animation: 'flowDash 1.5s linear infinite',
        strokeDasharray: '6 6',
      };

  return (
    <g>
      {/* Invisible wide hit area */}
      <path d={pathD} fill="none" stroke="transparent" strokeWidth={12} />
      {/* Visible edge */}
      <path
        d={pathD}
        fill="none"
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        strokeOpacity={isDrop ? 1 : 0.7}
        strokeDasharray={isDrop ? '8 4' : '6 6'}
        style={animStyle}
      />
      {/* Protocol label at midpoint */}
      <text
        x={midX}
        y={controlY - 6}
        textAnchor="middle"
        fontSize={10}
        fill={theme.palette.text.secondary}
        style={{ pointerEvents: 'none', userSelect: 'none' }}
      >
        {edge.protocol}
        {isDrop && ` ⚠ ${edge.droppedPackets} drops`}
      </text>
    </g>
  );
}

// ─── SVG node ────────────────────────────────────────────────────────────────

interface SvgNodeProps {
  node: TrafficNode;
  isHovered: boolean;
  isSelected: boolean;
  onClick: (node: TrafficNode) => void;
  onHover: (id: string | null) => void;
  theme: ReturnType<typeof useTheme>;
}

function SvgNode({ node, isHovered, isSelected, onClick, onHover, theme }: SvgNodeProps) {
  const colorMap: Record<TrafficNode['kind'], string> = {
    pod: theme.palette.primary.main,
    service: theme.palette.success.main,
    external: theme.palette.warning.main,
  };
  const fill = colorMap[node.kind];
  const r = isHovered || isSelected ? 31 : 28;

  return (
    <g
      style={{ cursor: 'pointer' }}
      onClick={() => onClick(node)}
      onMouseEnter={() => onHover(node.id)}
      onMouseLeave={() => onHover(null)}
    >
      {/* Glow ring when hovered */}
      {(isHovered || isSelected) && (
        <circle
          cx={node.x}
          cy={node.y}
          r={r + 6}
          fill="none"
          stroke={fill}
          strokeWidth={2}
          strokeOpacity={0.4}
          filter="url(#glow)"
        />
      )}
      <circle
        cx={node.x}
        cy={node.y}
        r={r}
        fill={fill}
        stroke={theme.palette.background.default}
        strokeWidth={2}
        filter={isHovered || isSelected ? 'url(#glow)' : undefined}
      />
      {/* Kind icon abbreviation */}
      <text
        x={node.x}
        y={node.y + 5}
        textAnchor="middle"
        fontSize={11}
        fontWeight="bold"
        fill={theme.palette.getContrastText(fill)}
        style={{ pointerEvents: 'none', userSelect: 'none' }}
      >
        {node.kind === 'pod' ? 'POD' : node.kind === 'service' ? 'SVC' : 'EXT'}
      </text>
      {/* Node label below */}
      <text
        x={node.x}
        y={node.y + r + 16}
        textAnchor="middle"
        fontSize={11}
        fill={theme.palette.text.primary}
        style={{ pointerEvents: 'none', userSelect: 'none' }}
      >
        {node.label}
      </text>
    </g>
  );
}

// ─── Node detail drawer ───────────────────────────────────────────────────────

interface NodeDrawerProps {
  node: TrafficNode | null;
  open: boolean;
  onClose: () => void;
  edges: TrafficEdge[];
  theme: ReturnType<typeof useTheme>;
  drawerTab: number;
  setDrawerTab: (v: number) => void;
  dnsQueries: DNSQuery[];
}

function NodeDrawer({ node, open, onClose, edges, theme, drawerTab, setDrawerTab, dnsQueries }: NodeDrawerProps) {
  const connectedRequests = useMemo<HTTPRequest[]>(() => {
    if (!node) return [];
    return edges
      .filter(e => e.source === node.id || e.target === node.id)
      .flatMap(e => e.recentRequests)
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, 20);
  }, [node, edges]);

  const failedDns = dnsQueries.filter(q => q.rcode !== 'NOERROR');
  const flaggedDns = dnsQueries.filter(q => q.flagged);
  const flaggedCount = flaggedDns.length;
  const shownDnsQueries = dnsQueries.slice(0, 10);

  const kindColorMap: Record<TrafficNode['kind'], 'primary' | 'success' | 'warning'> = {
    pod: 'primary',
    service: 'success',
    external: 'warning',
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{ sx: { width: 420, p: 0 } }}
    >
      {node && (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
          {/* Header */}
          <Box
            sx={{
              p: 2,
              bgcolor: theme.palette.action.hover,
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
            }}
          >
            <Box>
              <Box display="flex" alignItems="center" gap={1}>
                <Typography variant="h6" fontWeight="bold">
                  {node.label}
                </Typography>
                <Chip label={node.kind} color={kindColorMap[node.kind]} size="small" />
              </Box>
              <Typography variant="body2" color="text.secondary">
                {node.namespace}
              </Typography>
              <Typography variant="body2" fontFamily="monospace" color="text.secondary">
                {node.ip}:{node.port}
              </Typography>
            </Box>
            <IconButton size="small" onClick={onClose}>
              <Icon icon="mdi:close" width={20} />
            </IconButton>
          </Box>

          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <Tabs
              value={drawerTab}
              onChange={(_, v) => setDrawerTab(v)}
              sx={{ borderBottom: 1, borderColor: 'divider', px: 2, flexShrink: 0 }}
            >
              <Tab label="HTTP Traffic" />
              <Tab
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    DNS Activity
                    {flaggedCount > 0 && (
                      <Chip label={flaggedCount} size="small" color="error" />
                    )}
                  </Box>
                }
              />
            </Tabs>

            <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
              {drawerTab === 0 && (
                <Box>
                  <Typography variant="subtitle2" fontWeight="bold" gutterBottom>
                    Recent Requests
                  </Typography>
                  {connectedRequests.length === 0 ? (
                    <Typography variant="body2" color="text.secondary">
                      No recent requests
                    </Typography>
                  ) : (
                    <TableContainer component={Paper} variant="outlined">
                      <Table size="small">
                        <TableHead>
                          <TableRow sx={{ bgcolor: theme.palette.action.hover }}>
                            <TableCell sx={{ py: 0.5 }}>Time</TableCell>
                            <TableCell sx={{ py: 0.5 }}>Method</TableCell>
                            <TableCell sx={{ py: 0.5 }}>Path</TableCell>
                            <TableCell sx={{ py: 0.5 }}>Status</TableCell>
                            <TableCell sx={{ py: 0.5 }}>Latency</TableCell>
                            <TableCell sx={{ py: 0.5 }}>Flow</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {connectedRequests.map((req, i) => (
                            <TableRow key={i}>
                              <TableCell sx={{ py: 0.5 }}>
                                <Typography variant="caption" fontFamily="monospace">
                                  {new Date(req.timestamp).toLocaleTimeString()}
                                </Typography>
                              </TableCell>
                              <TableCell sx={{ py: 0.5 }}>
                                <MethodChip method={req.method} />
                              </TableCell>
                              <TableCell sx={{ py: 0.5 }}>
                                <Typography
                                  variant="caption"
                                  fontFamily="monospace"
                                  noWrap
                                  title={req.path}
                                  sx={{ maxWidth: 90, display: 'block' }}
                                >
                                  {req.path}
                                </Typography>
                              </TableCell>
                              <TableCell sx={{ py: 0.5 }}>
                                <Typography
                                  variant="caption"
                                  fontWeight="bold"
                                  color={statusColor(req.statusCode, theme)}
                                >
                                  {req.statusCode}
                                </Typography>
                              </TableCell>
                              <TableCell sx={{ py: 0.5 }}>
                                <Typography variant="caption">{req.latencyMs}ms</Typography>
                              </TableCell>
                              <TableCell sx={{ py: 0.5 }}>
                                <Typography variant="caption" fontFamily="monospace" noWrap>
                                  {req.srcPod.split('-')[0]}→{req.dstPod.split('-')[0]}
                                </Typography>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </Box>
              )}

              {drawerTab === 1 && (
                <Box display="flex" flexDirection="column" gap={2}>
                  {dnsQueries.length === 0 ? (
                    <Typography variant="body2" color="text.secondary">
                      No DNS queries recorded for this workload in the current window.
                    </Typography>
                  ) : (
                    <>
                      <Box display="flex" gap={1} flexWrap="wrap">
                        <Chip label={`${dnsQueries.length} total`} size="small" />
                        {failedDns.length > 0 && (
                          <Chip label={`${failedDns.length} failed`} size="small" color="error" />
                        )}
                        {flaggedDns.length > 0 && (
                          <Chip label={`${flaggedDns.length} flagged`} size="small" color="warning" />
                        )}
                      </Box>

                      {flaggedDns.length > 0 &&
                        flaggedDns.slice(0, 2).map((q, i) => (
                          <Alert key={i} severity="warning">
                            <strong>{q.domain}</strong>
                            {q.flagReason ? ` — ${q.flagReason}` : ''}
                          </Alert>
                        ))}

                      <TableContainer component={Paper} variant="outlined">
                        <Table size="small">
                          <TableHead>
                            <TableRow sx={{ bgcolor: theme.palette.action.hover }}>
                              <TableCell>Domain</TableCell>
                              <TableCell>RCode</TableCell>
                              <TableCell>Latency</TableCell>
                              <TableCell>Retries</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {shownDnsQueries.map(q => {
                              const latText =
                                q.latencyMs >= 1000
                                  ? `${(q.latencyMs / 1000).toFixed(1)}s`
                                  : `${q.latencyMs}ms`;
                              const latColor =
                                q.latencyMs >= 1000
                                  ? theme.palette.error.main
                                  : q.latencyMs >= 200
                                  ? theme.palette.warning.main
                                  : 'inherit';
                              const rcodeChipColor: 'success' | 'error' | 'warning' =
                                q.rcode === 'NOERROR'
                                  ? 'success'
                                  : q.rcode === 'NXDOMAIN'
                                  ? 'error'
                                  : 'warning';
                              return (
                                <TableRow
                                  key={q.id}
                                  sx={{
                                    backgroundColor: q.flagged
                                      ? 'rgba(211,47,47,0.08)'
                                      : undefined,
                                  }}
                                >
                                  <TableCell>
                                    <Typography
                                      variant="caption"
                                      fontFamily="monospace"
                                      sx={{ wordBreak: 'break-all' }}
                                    >
                                      {q.domain}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Chip
                                      label={q.rcode}
                                      size="small"
                                      color={rcodeChipColor}
                                      variant="outlined"
                                    />
                                  </TableCell>
                                  <TableCell>
                                    <Typography variant="caption" sx={{ color: latColor }}>
                                      {latText}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>{q.retryCount}</TableCell>
                                </TableRow>
                              );
                            })}
                          </TableBody>
                        </Table>
                      </TableContainer>

                      <Typography variant="caption" color="text.secondary">
                        Showing {Math.min(dnsQueries.length, 10)} of {dnsQueries.length} queries
                      </Typography>
                    </>
                  )}
                </Box>
              )}
            </Box>
          </Box>
        </Box>
      )}
    </Drawer>
  );
}

// ─── Traffic security banner ──────────────────────────────────────────────────

function TrafficSecurityBanner({ droppedPackets, edges }: { droppedPackets: number; edges: TrafficEdge[] }) {
  const externalDnsEdges = edges.filter(e => e.target === 'external-dns');
  const topDropEdge = edges.reduce<TrafficEdge | null>(
    (max, e) => (e.droppedPackets > (max?.droppedPackets ?? 0) ? e : max),
    null
  );

  if (droppedPackets === 0 && externalDnsEdges.length < 2) return null;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 2 }}>
      {droppedPackets > 0 && topDropEdge && (
        <Alert severity="error">
          {droppedPackets} dropped packets detected — highest on {topDropEdge.source} → {topDropEdge.target}. Possible network policy conflict.
        </Alert>
      )}
      {externalDnsEdges.length >= 2 && (
        <Alert severity="warning">
          {externalDnsEdges.length} services resolving to external-dns — verify no unexpected data egress.
        </Alert>
      )}
    </Box>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

/**
 * Full-page live cluster traffic visualization with SVG canvas and node detail drawer.
 * Addresses upstream issue #16.
 */
export function TrafficVisualizer() {
  const theme = useTheme();
  const graph = useMockGadgetStream('traffic');
  const dnsSnapshot = useDNSStream('dns');

  const [selectedNode, setSelectedNode] = useState<TrafficNode | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [namespace, setNamespace] = useState<string>('default');
  const [captureDuration, setCaptureDuration] = useState(0);
  const [drawerTab, setDrawerTab] = useState(0);

  // Ticking capture duration counter
  useEffect(() => {
    const t = setInterval(() => setCaptureDuration(d => d + 1), 1000);
    return () => clearInterval(t);
  }, []);

  function handleNodeClick(node: TrafficNode) {
    setSelectedNode(node);
    setDrawerOpen(true);
    setDrawerTab(0);
  }

  return (
    <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* ── Section 1: Header ─────────────────────────────────────────── */}
      <Box>
        <Box
          display="flex"
          alignItems="center"
          justifyContent="space-between"
          flexWrap="wrap"
          gap={2}
        >
          <Box display="flex" alignItems="center" gap={1}>
            <Icon icon="mdi:graph-outline" width={28} color={theme.palette.primary.main} />
            <Typography variant="h5" fontWeight="bold">
              Cluster Traffic Map
            </Typography>
          </Box>

          <Box display="flex" alignItems="center" gap={2} flexWrap="wrap">
            {/* Namespace selector */}
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel id="ns-select-label">Namespace</InputLabel>
              <Select
                labelId="ns-select-label"
                value={namespace}
                label="Namespace"
                onChange={(e: SelectChangeEvent) => setNamespace(e.target.value)}
              >
                <MenuItem value="default">default</MenuItem>
                <MenuItem value="kube-system">kube-system</MenuItem>
                <MenuItem value="monitoring">monitoring</MenuItem>
              </Select>
            </FormControl>

            {/* Capture stats */}
            <Box display="flex" alignItems="center" gap={1}>
              <Typography variant="caption" color="text.secondary">
                {graph.totalPackets.toLocaleString()} pkts
              </Typography>
              <Chip
                label={`${graph.droppedPackets} drops`}
                size="small"
                color={graph.droppedPackets > 0 ? 'error' : 'success'}
                icon={
                  <Icon
                    icon={graph.droppedPackets > 0 ? 'mdi:alert' : 'mdi:check'}
                    width={14}
                  />
                }
              />
              <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                {formatDuration(captureDuration)}
              </Typography>
            </Box>

            {/* CAPTURING badge */}
            <Box display="flex" alignItems="center" gap={0.5}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: 'error.main',
                  animation: 'capturePulse 1.2s ease-in-out infinite',
                  '@keyframes capturePulse': {
                    '0%, 100%': { opacity: 1 },
                    '50%': { opacity: 0.3 },
                  },
                }}
              />
              <Typography variant="caption" color="error.main" fontWeight="bold">
                CAPTURING
              </Typography>
            </Box>
          </Box>
        </Box>

        <Typography variant="body2" color="text.secondary" mt={0.5}>
          Live service-to-service traffic capture · Issue #16
        </Typography>
      </Box>

      <TrafficSecurityBanner droppedPackets={graph.droppedPackets} edges={graph.edges} />

      {/* ── Section 2: SVG canvas ──────────────────────────────────────── */}
      <Paper
        variant="outlined"
        sx={{ overflow: 'hidden', bgcolor: theme.palette.background.paper }}
      >
        <svg
          viewBox="0 0 800 480"
          width="100%"
          style={{ display: 'block' }}
        >
          <defs>
            {/* Flow animation */}
            <style>{`
              @keyframes flowDash {
                to { stroke-dashoffset: -24; }
              }
            `}</style>
            {/* Glow filter */}
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Edges (rendered first, underneath nodes) */}
          {graph.edges.map((edge, i) => {
            const src = graph.nodes.find(n => n.id === edge.source);
            const tgt = graph.nodes.find(n => n.id === edge.target);
            if (!src || !tgt) return null;
            return (
              <SvgEdge
                key={edge.id}
                edge={edge}
                sourceNode={src}
                targetNode={tgt}
                theme={theme}
                edgeIndex={i}
              />
            );
          })}

          {/* Nodes (rendered on top) */}
          {graph.nodes.map(node => (
            <SvgNode
              key={node.id}
              node={node}
              isHovered={hoveredNode === node.id}
              isSelected={selectedNode?.id === node.id}
              onClick={handleNodeClick}
              onHover={setHoveredNode}
              theme={theme}
            />
          ))}
        </svg>

        {/* Legend */}
        <Box
          sx={{
            px: 2,
            py: 1,
            borderTop: `1px solid ${theme.palette.divider}`,
            display: 'flex',
            gap: 3,
            flexWrap: 'wrap',
          }}
        >
          {(
            [
              { kind: 'pod', label: 'Pod', color: theme.palette.primary.main },
              { kind: 'service', label: 'Service', color: theme.palette.success.main },
              { kind: 'external', label: 'External', color: theme.palette.warning.main },
            ] as { kind: string; label: string; color: string }[]
          ).map(({ kind, label, color }) => (
            <Box key={kind} display="flex" alignItems="center" gap={0.5}>
              <Box
                sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: color }}
              />
              <Typography variant="caption" color="text.secondary">
                {label}
              </Typography>
            </Box>
          ))}
          <Box display="flex" alignItems="center" gap={0.5}>
            <Box
              sx={{
                width: 24,
                height: 2,
                background: `repeating-linear-gradient(90deg, ${theme.palette.error.main} 0 8px, transparent 8px 12px)`,
              }}
            />
            <Typography variant="caption" color="text.secondary">
              Packet drops
            </Typography>
          </Box>
          <Box display="flex" alignItems="center" gap={0.5}>
            <Box
              sx={{
                width: 24,
                height: 2,
                background: `repeating-linear-gradient(90deg, ${theme.palette.primary.main} 0 6px, transparent 6px 12px)`,
              }}
            />
            <Typography variant="caption" color="text.secondary">
              Active flow
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* ── Section 3: Node detail drawer ─────────────────────────────── */}
      <NodeDrawer
        node={selectedNode}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        edges={graph.edges}
        theme={theme}
        drawerTab={drawerTab}
        setDrawerTab={setDrawerTab}
        dnsQueries={selectedNode ? getDNSQueriesForPod(dnsSnapshot, selectedNode.id) : []}
      />
    </Box>
  );
}
