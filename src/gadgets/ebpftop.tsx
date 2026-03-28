/**
 * EBPFTopDashboard — live eBPF program resource monitor.
 *
 * Addresses upstream issue #15: [RFE] Monitoring Resource Usage of eBPF Programs
 * github.com/inspektor-gadget/headlamp-plugin/issues/15
 */

import { Icon } from '@iconify/react';
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Collapse,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  SelectChangeEvent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Typography,
  useTheme,
} from '@mui/material';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { BPFProgramStats, useMockGadgetStream } from '../common/useMockGadgetStream';

// ─── Types ───────────────────────────────────────────────────────────────────

type SortKey = 'cpuPercent' | 'memoryBytes' | 'runCount';
type SortDir = 'asc' | 'desc';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function cpuStatus(cpu: number): 'error' | 'warning' | 'success' {
  if (cpu > 15) return 'error';
  if (cpu > 5) return 'warning';
  return 'success';
}

function cpuLabel(cpu: number): string {
  if (cpu > 15) return 'ALERT';
  if (cpu > 5) return 'WARN';
  return 'OK';
}

// ─── Summary card ─────────────────────────────────────────────────────────────

interface SummaryCardProps {
  title: string;
  value: string;
  sub?: string;
  icon: string;
  accent?: 'error' | 'warning' | 'success' | 'primary';
}

function SummaryCard({ title, value, sub, icon, accent = 'primary' }: SummaryCardProps) {
  const theme = useTheme();
  const accentColor = theme.palette[accent].main;

  return (
    <Card sx={{ flex: 1, minWidth: 160 }}>
      <CardContent>
        <Box display="flex" alignItems="center" gap={1} mb={0.5}>
          <Icon icon={icon} width={18} color={accentColor} />
          <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 0.5 }}>
            {title}
          </Typography>
        </Box>
        <Typography variant="h5" fontWeight="bold" color={accentColor}>
          {value}
        </Typography>
        {sub && (
          <Typography variant="caption" color="text.secondary" noWrap title={sub}>
            {sub}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Chart data point ─────────────────────────────────────────────────────────

interface ChartPoint {
  tick: number;
  [programName: string]: number;
}

// ─── Security insight banner ──────────────────────────────────────────────────

function SecurityInsightBanner({ programs }: { programs: BPFProgramStats[] }) {
  const highCpu = programs.find(p => p.cpuPercent > 15);
  const lsm = programs.find(p => p.type === 'lsm');
  const bigMap = programs.find(p => p.memoryBytes / 1024 > 600);

  if (!highCpu && !lsm && !bigMap) return null;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 2 }}>
      {highCpu && (
        <Alert severity="error">
          High syscall tracing overhead — {highCpu.name} at {highCpu.cpuPercent.toFixed(1)}% CPU. Consider rate-limiting.
        </Alert>
      )}
      {lsm && (
        <Alert severity="warning">
          LSM hook active ({lsm.name}) — enforcing policy on socket_connect. Verify intent.
        </Alert>
      )}
      {bigMap && (
        <Alert severity="warning">
          {bigMap.name} using {Math.round(bigMap.memoryBytes / 1024)}KB — unusually large eBPF map footprint.
        </Alert>
      )}
    </Box>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

/**
 * Full-page eBPF program resource monitor dashboard.
 * Consumes useMockGadgetStream('ebpftop') for live telemetry.
 * Addresses upstream issue #15.
 */
export function EBPFTopDashboard() {
  const theme = useTheme();
  const programs: BPFProgramStats[] = useMockGadgetStream('ebpftop');

  const [selectedNode, setSelectedNode] = useState<string>('all');
  const [sortBy, setSortBy] = useState<SortKey>('cpuPercent');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  /** CPU history per program — kept in ref to avoid extra renders */
  const historyRef = useRef<Record<string, number[]>>({});
  /** Tick counter for chart x-axis */
  const tickRef = useRef<number>(0);

  // Update history and timestamp on each data tick
  useEffect(() => {
    tickRef.current += 1;
    programs.forEach(p => {
      if (!historyRef.current[p.name]) {
        historyRef.current[p.name] = [];
      }
      historyRef.current[p.name] = [
        ...historyRef.current[p.name].slice(-29),
        p.cpuPercent,
      ];
    });
    setLastUpdated(new Date());
  }, [programs]);

  // Filtered + sorted table rows
  const displayed = useMemo<BPFProgramStats[]>(() => {
    const filtered =
      selectedNode === 'all' ? programs : programs.filter(p => p.node === selectedNode);
    const mul = sortDir === 'desc' ? -1 : 1;
    return [...filtered].sort((a, b) => (a[sortBy] - b[sortBy]) * mul);
  }, [programs, selectedNode, sortBy, sortDir]);

  // Top 3 programs by current CPU for the chart
  const top3 = useMemo<BPFProgramStats[]>(
    () => [...programs].sort((a, b) => b.cpuPercent - a.cpuPercent).slice(0, 3),
    [programs]
  );

  // Build 30-point chart data from history
  const chartData = useMemo<ChartPoint[]>(() => {
    const maxLen = Math.max(...top3.map(p => (historyRef.current[p.name] ?? []).length), 1);
    return Array.from({ length: Math.min(maxLen, 30) }, (_, i) => {
      const point: ChartPoint = { tick: tickRef.current - (maxLen - 1 - i) };
      top3.forEach(p => {
        const hist = historyRef.current[p.name] ?? [];
        const offset = hist.length - maxLen;
        point[p.name] = hist[offset + i] ?? 0;
      });
      return point;
    });
  }, [top3]);

  // Summary aggregates
  const totalCpu = useMemo(
    () => programs.reduce((s, p) => s + p.cpuPercent, 0),
    [programs]
  );
  const totalMemory = useMemo(
    () => programs.reduce((s, p) => s + p.memoryBytes, 0),
    [programs]
  );
  const highestCpu = useMemo<BPFProgramStats | null>(
    () =>
      programs.length > 0
        ? programs.reduce((max, p) => (p.cpuPercent > max.cpuPercent ? p : max), programs[0])
        : null,
    [programs]
  );

  const chartColors = [
    theme.palette.primary.main,
    theme.palette.secondary.main,
    theme.palette.warning.main,
  ];

  function handleSortClick(key: SortKey) {
    if (sortBy === key) {
      setSortDir(prev => (prev === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortBy(key);
      setSortDir('desc');
    }
  }

  function handleRowClick(id: number) {
    setExpandedRow(prev => (prev === id ? null : id));
  }

  return (
    <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* ── Section 1: Header ─────────────────────────────────────────── */}
      <Box>
        <Box display="flex" alignItems="center" justifyContent="space-between" flexWrap="wrap" gap={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <Icon icon="mdi:chip" width={28} color={theme.palette.primary.main} />
            <Typography variant="h5" fontWeight="bold">
              eBPF Resource Monitor
            </Typography>
          </Box>

          <Box display="flex" alignItems="center" gap={2} flexWrap="wrap">
            {/* Node selector */}
            <FormControl size="small" sx={{ minWidth: 130 }}>
              <InputLabel id="node-select-label">Node</InputLabel>
              <Select
                labelId="node-select-label"
                value={selectedNode}
                label="Node"
                onChange={(e: SelectChangeEvent) => setSelectedNode(e.target.value)}
              >
                <MenuItem value="all">All Nodes</MenuItem>
                <MenuItem value="node-1">node-1</MenuItem>
                <MenuItem value="node-2">node-2</MenuItem>
                <MenuItem value="node-3">node-3</MenuItem>
              </Select>
            </FormControl>

            {/* LIVE badge */}
            <Box display="flex" alignItems="center" gap={0.5}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: 'success.main',
                  animation: 'livePulse 1.5s ease-in-out infinite',
                  '@keyframes livePulse': {
                    '0%, 100%': { opacity: 1 },
                    '50%': { opacity: 0.3 },
                  },
                }}
              />
              <Typography variant="caption" color="success.main" fontWeight="bold">
                LIVE
              </Typography>
            </Box>

            <Typography variant="caption" color="text.secondary">
              Updated {lastUpdated.toLocaleTimeString()}
            </Typography>
          </Box>
        </Box>

        <Typography variant="body2" color="text.secondary" mt={0.5}>
          Live resource usage of eBPF programs · Issue #15
        </Typography>
      </Box>

      <SecurityInsightBanner programs={programs} />

      {/* ── Section 2: Summary cards ───────────────────────────────────── */}
      <Box display="flex" gap={2} flexWrap="wrap">
        <SummaryCard
          title="Active Programs"
          value={String(programs.length)}
          icon="mdi:code-braces"
          accent="primary"
        />
        <SummaryCard
          title="Total CPU %"
          value={`${totalCpu.toFixed(2)}%`}
          icon="mdi:cpu-64-bit"
          accent={totalCpu > 50 ? 'error' : totalCpu > 20 ? 'warning' : 'success'}
        />
        <SummaryCard
          title="Total Memory"
          value={formatBytes(totalMemory)}
          icon="mdi:memory"
          accent="primary"
        />
        <SummaryCard
          title="Highest CPU"
          value={highestCpu ? `${highestCpu.cpuPercent.toFixed(2)}%` : '—'}
          sub={highestCpu?.name}
          icon="mdi:alert-circle-outline"
          accent={
            highestCpu
              ? highestCpu.cpuPercent > 15
                ? 'error'
                : highestCpu.cpuPercent > 5
                ? 'warning'
                : 'success'
              : 'primary'
          }
        />
      </Box>

      {/* ── Section 3: Sortable table ──────────────────────────────────── */}
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow sx={{ bgcolor: theme.palette.action.hover }}>
              <TableCell>Program Name</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Node</TableCell>
              <TableCell>Pod</TableCell>
              <TableCell sortDirection={sortBy === 'cpuPercent' ? sortDir : false}>
                <TableSortLabel
                  active={sortBy === 'cpuPercent'}
                  direction={sortBy === 'cpuPercent' ? sortDir : 'desc'}
                  onClick={() => handleSortClick('cpuPercent')}
                >
                  CPU %
                </TableSortLabel>
              </TableCell>
              <TableCell sortDirection={sortBy === 'runCount' ? sortDir : false}>
                <TableSortLabel
                  active={sortBy === 'runCount'}
                  direction={sortBy === 'runCount' ? sortDir : 'desc'}
                  onClick={() => handleSortClick('runCount')}
                >
                  Avg Runtime (ns)
                </TableSortLabel>
              </TableCell>
              <TableCell sortDirection={sortBy === 'runCount' ? sortDir : false}>
                <TableSortLabel
                  active={sortBy === 'runCount'}
                  direction={sortBy === 'runCount' ? sortDir : 'desc'}
                  onClick={() => handleSortClick('runCount')}
                >
                  Run Count
                </TableSortLabel>
              </TableCell>
              <TableCell sortDirection={sortBy === 'memoryBytes' ? sortDir : false}>
                <TableSortLabel
                  active={sortBy === 'memoryBytes'}
                  direction={sortBy === 'memoryBytes' ? sortDir : 'desc'}
                  onClick={() => handleSortClick('memoryBytes')}
                >
                  Memory
                </TableSortLabel>
              </TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>

          <TableBody>
            {displayed.map(p => {
              const isExpanded = expandedRow === p.id;
              const status = cpuStatus(p.cpuPercent);
              const rowSx =
                p.cpuPercent > 15
                  ? {
                      bgcolor: theme.palette.error.dark,
                      cursor: 'pointer',
                      animation: 'alertPulse 1s ease-in-out infinite',
                      '@keyframes alertPulse': {
                        '0%, 100%': { opacity: 1 },
                        '50%': { opacity: 0.85 },
                      },
                    }
                  : p.cpuPercent > 5
                  ? { bgcolor: theme.palette.warning.dark, cursor: 'pointer' }
                  : { cursor: 'pointer', '&:hover': { bgcolor: theme.palette.action.hover } };

              return (
                <>
                  <TableRow
                    key={`row-${p.id}`}
                    sx={rowSx}
                    onClick={() => handleRowClick(p.id)}
                    selected={isExpanded}
                  >
                    <TableCell>
                      <Box display="flex" alignItems="center" gap={0.5}>
                        {p.cpuPercent > 15 && (
                          <Icon icon="mdi:alert" width={16} color={theme.palette.error.contrastText} />
                        )}
                        <Typography
                          variant="body2"
                          fontFamily="monospace"
                          sx={{ color: p.cpuPercent > 15 ? theme.palette.error.contrastText : 'inherit' }}
                        >
                          {p.name}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip label={p.type} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{p.node}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" noWrap>
                        {p.pod}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontWeight="bold"
                        color={
                          p.cpuPercent > 15
                            ? theme.palette.error.contrastText
                            : p.cpuPercent > 5
                            ? theme.palette.warning.contrastText
                            : 'inherit'
                        }
                      >
                        {p.cpuPercent.toFixed(2)}%
                      </Typography>
                    </TableCell>
                    <TableCell>{p.avgRunTimeNs.toLocaleString()}</TableCell>
                    <TableCell>{p.runCount.toLocaleString()}</TableCell>
                    <TableCell>{formatBytes(p.memoryBytes)}</TableCell>
                    <TableCell>
                      <Chip
                        label={cpuLabel(p.cpuPercent)}
                        color={status}
                        size="small"
                      />
                    </TableCell>
                  </TableRow>

                  {/* Inline expand row */}
                  <TableRow key={`expand-${p.id}`}>
                    <TableCell colSpan={9} sx={{ py: 0, border: isExpanded ? undefined : 'none' }}>
                      <Collapse in={isExpanded} unmountOnExit>
                        <Box sx={{ p: 2, bgcolor: theme.palette.action.selected, borderRadius: 1, my: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>
                            Program Details
                          </Typography>
                          <Box
                            display="grid"
                            gridTemplateColumns="repeat(auto-fill, minmax(220px, 1fr))"
                            gap={1}
                          >
                            {(
                              [
                                ['ID', String(p.id)],
                                ['Tag', p.tag],
                                ['Namespace', p.namespace],
                                ['Container', p.container],
                                ['Total Runtime (ns)', p.runTimeNs.toLocaleString()],
                                ['Avg Runtime (ns)', p.avgRunTimeNs.toLocaleString()],
                                ['Memory', formatBytes(p.memoryBytes)],
                              ] as [string, string][]
                            ).map(([label, val]) => (
                              <Box key={label}>
                                <Typography variant="caption" color="text.secondary">
                                  {label}
                                </Typography>
                                <Typography variant="body2" fontFamily="monospace">
                                  {val}
                                </Typography>
                              </Box>
                            ))}
                          </Box>
                        </Box>
                      </Collapse>
                    </TableCell>
                  </TableRow>
                </>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      {/* ── Section 4: CPU history chart ──────────────────────────────── */}
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
          CPU % History — Top 3 Programs
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block" mb={2}>
          Last 30 data points (2s interval)
        </Typography>
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={chartData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
            <defs>
              {top3.map((p, i) => (
                <linearGradient key={p.name} id={`grad-${i}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={chartColors[i]} stopOpacity={0.4} />
                  <stop offset="95%" stopColor={chartColors[i]} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
            <XAxis
              dataKey="tick"
              tick={{ fontSize: 11, fill: theme.palette.text.secondary }}
              stroke={theme.palette.divider}
            />
            <YAxis
              unit="%"
              tick={{ fontSize: 11, fill: theme.palette.text.secondary }}
              stroke={theme.palette.divider}
            />
            <Tooltip
              contentStyle={{
                background: theme.palette.background.paper,
                border: `1px solid ${theme.palette.divider}`,
                borderRadius: 4,
              }}
              formatter={(value: number) => [`${value.toFixed(2)}%`, '']}
            />
            <Legend />
            <ReferenceLine
              y={10}
              label={{ value: 'Alert Threshold', fill: theme.palette.error.main, fontSize: 11 }}
              stroke={theme.palette.error.main}
              strokeDasharray="4 4"
            />
            {top3.map((p, i) => (
              <Area
                key={p.name}
                type="monotone"
                dataKey={p.name}
                name={p.name}
                stroke={chartColors[i]}
                fill={`url(#grad-${i})`}
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </Paper>
    </Box>
  );
}
