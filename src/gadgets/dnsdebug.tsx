/**
 * DNSDebugPanel — live DNS query analysis dashboard.
 *
 * Addresses upstream issue #17: Security-focused UX Improvements for the
 * Inspektor Gadget Headlamp Plugin (github.com/inspektor-gadget/headlamp-plugin).
 */

import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Collapse,
  FormControl,
  IconButton,
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
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { Icon } from '@iconify/react';
import { useMemo, useState } from 'react';
import { DNSSnapshot, useMockGadgetStream } from '../common/useMockGadgetStream';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatLatency(ms: number, errorColor: string, warnColor: string): { text: string; color: string } {
  if (ms >= 1000) return { text: `${(ms / 1000).toFixed(1)}s`, color: errorColor };
  if (ms >= 200) return { text: `${ms}ms`, color: warnColor };
  return { text: `${ms}ms`, color: 'inherit' };
}

function rcodeColor(rcode: string): 'success' | 'error' | 'warning' | 'default' {
  if (rcode === 'NOERROR') return 'success';
  if (rcode === 'NXDOMAIN') return 'error';
  return 'warning';
}

// ─── Summary card ─────────────────────────────────────────────────────────────

function SummaryCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  const theme = useTheme();
  return (
    <Card variant="outlined" sx={{ flex: '1 1 0', minWidth: 120 }}>
      <CardContent sx={{ pb: '12px !important', pt: 1.5, px: 2 }}>
        <Typography variant="caption" color="text.secondary" display="block">
          {label}
        </Typography>
        <Typography
          variant="h5"
          fontWeight="bold"
          sx={{ color: color ?? theme.palette.text.primary }}
        >
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function DNSDebugPanel() {
  const snapshot: DNSSnapshot = useMockGadgetStream('dns');
  const theme = useTheme();

  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [nsFilter, setNsFilter] = useState('all');
  const [podFilter, setPodFilter] = useState('all');
  const [showFilter, setShowFilter] = useState<'all' | 'failed' | 'flagged'>('all');

  const filtered = useMemo(() => {
    return snapshot.queries.filter(q => {
      if (nsFilter !== 'all' && q.namespace !== nsFilter) return false;
      if (podFilter !== 'all' && !q.pod.startsWith(podFilter)) return false;
      if (showFilter === 'failed' && q.rcode === 'NOERROR') return false;
      if (showFilter === 'flagged' && !q.flagged) return false;
      return true;
    });
  }, [snapshot.queries, nsFilter, podFilter, showFilter]);

  const failureRate =
    snapshot.totalQueries > 0
      ? Math.round((snapshot.failedQueries / snapshot.totalQueries) * 100)
      : 0;

  const errorColor = theme.palette.error.main;
  const warnColor = theme.palette.warning.main;

  return (
    <Box sx={{ p: 2 }}>
      {/* ── Section 1: Header ── */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
        <Icon icon="mdi:dns" width={24} color={theme.palette.primary.main} />
        <Typography variant="h5" fontWeight="bold">
          DNS Debug
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>
          DNS query analysis · Issue #17
        </Typography>
        <Chip
          label="LIVE"
          size="small"
          color="success"
          sx={{
            animation: 'pulse 1.5s ease-in-out infinite',
            '@keyframes pulse': {
              '0%, 100%': { opacity: 1 },
              '50%': { opacity: 0.5 },
            },
          }}
        />
        <Typography variant="caption" color="text.secondary">
          {snapshot.captureWindow}
        </Typography>
      </Box>

      {/* ── Section 2: Security alerts ── */}
      {(snapshot.suspiciousDomains.length > 0 ||
        snapshot.retryStorms.length > 0 ||
        snapshot.failedQueries >= 5) && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, mb: 2 }}>
          {snapshot.suspiciousDomains.length > 0 && (
            <Alert severity="error">
              Suspicious domains detected:{' '}
              <strong>{snapshot.suspiciousDomains.join(', ')}</strong>
            </Alert>
          )}
          {snapshot.retryStorms.length > 0 && (
            <Alert severity="warning">
              Retry storm on pod{' '}
              <strong>{snapshot.retryStorms[0].pod}</strong> →{' '}
              <strong>{snapshot.retryStorms[0].domain}</strong> (
              {snapshot.retryStorms[0].count} retries)
            </Alert>
          )}
          {snapshot.failedQueries >= 5 && (
            <Alert severity="warning">
              {snapshot.failedQueries} failed DNS lookups in capture window
            </Alert>
          )}
        </Box>
      )}

      {/* ── Section 3: Summary cards ── */}
      <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
        <SummaryCard label="Total Queries" value={snapshot.totalQueries} />
        <SummaryCard
          label="Failed Lookups"
          value={snapshot.failedQueries}
          color={snapshot.failedQueries > 0 ? errorColor : undefined}
        />
        <SummaryCard
          label="Failure Rate"
          value={`${failureRate}%`}
          color={failureRate >= 20 ? errorColor : failureRate >= 5 ? warnColor : undefined}
        />
        <SummaryCard
          label="Retry Storms"
          value={snapshot.retryStorms.length}
          color={snapshot.retryStorms.length > 0 ? warnColor : undefined}
        />
        <SummaryCard
          label="Suspicious Domains"
          value={snapshot.suspiciousDomains.length}
          color={snapshot.suspiciousDomains.length > 0 ? errorColor : undefined}
        />
      </Box>

      {/* ── Section 4: Filters ── */}
      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2, flexWrap: 'wrap' }}>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel>Namespace</InputLabel>
          <Select
            label="Namespace"
            value={nsFilter}
            onChange={(e: SelectChangeEvent) => setNsFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="default">default</MenuItem>
            <MenuItem value="kube-system">kube-system</MenuItem>
            <MenuItem value="monitoring">monitoring</MenuItem>
            <MenuItem value="ingress-nginx">ingress-nginx</MenuItem>
          </Select>
        </FormControl>

        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Pod</InputLabel>
          <Select
            label="Pod"
            value={podFilter}
            onChange={(e: SelectChangeEvent) => setPodFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="api-gateway-5c8b">api-gateway-5c8b</MenuItem>
            <MenuItem value="auth-service-3d7a">auth-service-3d7a</MenuItem>
            <MenuItem value="frontend-9e2f">frontend-9e2f</MenuItem>
            <MenuItem value="worker-4a1c">worker-4a1c</MenuItem>
          </Select>
        </FormControl>

        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Show</InputLabel>
          <Select
            label="Show"
            value={showFilter}
            onChange={(e: SelectChangeEvent) =>
              setShowFilter(e.target.value as 'all' | 'failed' | 'flagged')
            }
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="failed">Failed only</MenuItem>
            <MenuItem value="flagged">Flagged only</MenuItem>
          </Select>
        </FormControl>

        <Chip label={`${filtered.length} queries`} size="small" variant="outlined" />
      </Box>

      {/* ── Section 5: Table ── */}
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox" />
              <TableCell>Time</TableCell>
              <TableCell>Namespace</TableCell>
              <TableCell>Pod</TableCell>
              <TableCell>Domain</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>RCode</TableCell>
              <TableCell>Latency</TableCell>
              <TableCell>Retries</TableCell>
              <TableCell>Flag</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.map(q => {
              const isExpanded = expandedRow === q.id;
              const latency = formatLatency(q.latencyMs, errorColor, warnColor);
              const rowBg =
                q.flagged && q.rcode !== 'NOERROR'
                  ? 'rgba(211,47,47,0.08)'
                  : q.flagged
                  ? 'rgba(237,108,2,0.08)'
                  : undefined;

              return (
                <>
                  <TableRow
                    key={q.id}
                    hover
                    sx={{ backgroundColor: rowBg, cursor: 'pointer' }}
                    onClick={() => setExpandedRow(isExpanded ? null : q.id)}
                  >
                    <TableCell padding="checkbox">
                      <IconButton size="small">
                        {isExpanded ? <Icon icon="mdi:chevron-up" width={20} /> : <Icon icon="mdi:chevron-down" width={20} />}
                      </IconButton>
                    </TableCell>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>
                      <Typography variant="caption">
                        {new Date(q.timestamp).toLocaleTimeString()}
                      </Typography>
                    </TableCell>
                    <TableCell>{q.namespace}</TableCell>
                    <TableCell>{q.pod}</TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {q.isExternal && (
                          <Icon
                            icon="mdi:wifi-alert"
                            width={16}
                            color={warnColor}
                            style={{ flexShrink: 0 }}
                          />
                        )}
                        <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                          {q.domain}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>{q.qtype}</TableCell>
                    <TableCell>
                      <Chip
                        label={q.rcode}
                        size="small"
                        color={rcodeColor(q.rcode)}
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ color: latency.color }}>
                        {latency.text}
                      </Typography>
                    </TableCell>
                    <TableCell>{q.retryCount}</TableCell>
                    <TableCell>
                      {q.flagged && q.flagReason && (
                        <Tooltip title={q.flagReason}>
                          <span>
                            <Icon
                              icon="mdi:alert"
                              width={16}
                              color={q.rcode !== 'NOERROR' ? errorColor : warnColor}
                            />
                          </span>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                  <TableRow key={`${q.id}-detail`}>
                    <TableCell colSpan={10} sx={{ py: 0 }}>
                      <Collapse in={isExpanded} unmountOnExit>
                        <Box sx={{ py: 1, px: 2, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          <Box>
                            <Typography variant="caption" color="text.secondary">
                              Resolved IP
                            </Typography>
                            <Typography variant="body2">
                              {q.resolvedIP ?? '—'}
                            </Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="text.secondary">
                              Container
                            </Typography>
                            <Typography variant="body2">{q.container}</Typography>
                          </Box>
                          <Box>
                            <Typography variant="caption" color="text.secondary">
                              Retry Count
                            </Typography>
                            <Typography variant="body2">{q.retryCount}</Typography>
                          </Box>
                          {q.flagReason && (
                            <Box>
                              <Typography variant="caption" color="text.secondary">
                                Flag Reason
                              </Typography>
                              <Typography
                                variant="body2"
                                sx={{
                                  color:
                                    q.rcode !== 'NOERROR' ? errorColor : warnColor,
                                }}
                              >
                                {q.flagReason}
                              </Typography>
                            </Box>
                          )}
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
    </Box>
  );
}
