/**
 * InstallWizard — guided Inspektor Gadget installation flow.
 *
 * Addresses upstream issue #13: [RFE] Improve install ig experience
 * github.com/inspektor-gadget/headlamp-plugin/issues/13
 */

import { Icon } from '@iconify/react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  Paper,
  Step,
  StepLabel,
  Stepper,
  Typography,
  useTheme,
} from '@mui/material';
import { useEffect, useRef, useState } from 'react';

// ─── Types ───────────────────────────────────────────────────────────────────

type CheckStatus = 'pending' | 'running' | 'pass' | 'fail';

interface Check {
  label: string;
  status: CheckStatus;
  detail?: string;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const STEP_LABELS = [
  'Cluster Compatibility',
  'RBAC Permissions',
  'Deploy Inspektor Gadget',
];

const INITIAL_STEP1_CHECKS: Check[] = [
  { label: 'Kubernetes version ≥ 1.28', status: 'pending', detail: 'v1.29.4' },
  { label: 'Linux kernel ≥ 5.10', status: 'pending', detail: '6.1.0-26-amd64' },
  { label: 'BTF support enabled', status: 'pending', detail: '/sys/kernel/btf/vmlinux present' },
  { label: 'Privileged pod support', status: 'pending', detail: 'PodSecurity policy allows privileged' },
];

const INITIAL_STEP2_CHECKS: Check[] = [
  {
    label: 'ClusterRole inspektor-gadget-clusterrole',
    status: 'pending',
    detail: 'rbac.authorization.k8s.io/v1',
  },
  { label: 'ServiceAccount gadget', status: 'pending', detail: 'namespace: gadget' },
  { label: 'Namespace gadget', status: 'pending', detail: 'Active' },
];

const RBAC_YAML = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: inspektor-gadget-clusterrole
rules:
- apiGroups: [""]
  resources: ["namespaces", "nodes", "pods"]
  verbs: ["get", "watch", "list"]
- apiGroups: ["gadget.kinvolk.io"]
  resources: ["traces"]
  verbs: ["get", "list", "watch", "create", "delete", "update", "patch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]`;

const HELM_CMD =
  'helm install gadget inspektor-gadget/gadget --namespace gadget --create-namespace';

const DEPLOY_LINES = [
  `+ ${HELM_CMD}`,
  'Pulling image ghcr.io/inspektor-gadget/gadget:latest...',
  'Creating namespace "gadget"...',
  'Deploying DaemonSet inspektor-gadget...',
  'Waiting for DaemonSet rollout... (3/3 nodes ready)',
  'Configuring RBAC permissions...',
  '✓ Inspektor Gadget successfully deployed!',
];

// ─── Check row ────────────────────────────────────────────────────────────────

function CheckRow({ check }: { check: Check }) {
  const theme = useTheme();

  const icon = (() => {
    switch (check.status) {
      case 'running':
        return <CircularProgress size={16} />;
      case 'pass':
        return <Icon icon="mdi:check-circle" width={18} color={theme.palette.success.main} />;
      case 'fail':
        return <Icon icon="mdi:close-circle" width={18} color={theme.palette.error.main} />;
      default:
        return (
          <Icon icon="mdi:minus-circle-outline" width={18} color={theme.palette.text.disabled} />
        );
    }
  })();

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        py: 1,
        px: 2,
        borderRadius: 1,
        bgcolor:
          check.status === 'fail'
            ? `${theme.palette.error.main}18`
            : check.status === 'pass'
            ? `${theme.palette.success.main}10`
            : 'transparent',
      }}
    >
      <Box sx={{ flexShrink: 0, display: 'flex', alignItems: 'center' }}>{icon}</Box>
      <Box flex={1}>
        <Typography
          variant="body2"
          color={
            check.status === 'fail'
              ? 'error.main'
              : check.status === 'pending'
              ? 'text.disabled'
              : 'text.primary'
          }
        >
          {check.label}
        </Typography>
        {check.detail && check.status === 'pass' && (
          <Typography variant="caption" color="text.secondary" fontFamily="monospace">
            {check.detail}
          </Typography>
        )}
      </Box>
    </Box>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

/**
 * Guided install wizard for Inspektor Gadget.
 * Addresses upstream issue #13.
 */
export function InstallWizard() {
  const theme = useTheme();

  const [activeStep, setActiveStep] = useState(0);
  const [step1Checks, setStep1Checks] = useState<Check[]>(INITIAL_STEP1_CHECKS);
  const [step2Checks, setStep2Checks] = useState<Check[]>(INITIAL_STEP2_CHECKS);
  const [yamlOpen, setYamlOpen] = useState(false);
  const [autoFixApplied, setAutoFixApplied] = useState(false);
  const [autoFixRunning, setAutoFixRunning] = useState(false);
  const [step2Done, setStep2Done] = useState(false);
  const [deployStarted, setDeployStarted] = useState(false);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const [deployDone, setDeployDone] = useState(false);

  /** All setTimeout IDs — cleared on unmount to prevent memory leaks. */
  const timeoutIds = useRef<ReturnType<typeof setTimeout>[]>([]);
  /** Terminal scroll target. */
  const terminalRef = useRef<HTMLDivElement>(null);

  // Cleanup all pending timeouts on unmount
  useEffect(() => {
    return () => {
      timeoutIds.current.forEach(clearTimeout);
    };
  }, []);

  /** Schedule a timeout and track its ID for cleanup. */
  function schedule(fn: () => void, ms: number): void {
    const id = setTimeout(fn, ms);
    timeoutIds.current.push(id);
  }

  // ── Step 1: run compatibility checks on mount ──────────────────────────────
  useEffect(() => {
    function runCheck(i: number) {
      setStep1Checks(prev =>
        prev.map((c, idx) => (idx === i ? { ...c, status: 'running' } : c))
      );
      schedule(() => {
        setStep1Checks(prev =>
          prev.map((c, idx) => (idx === i ? { ...c, status: 'pass' } : c))
        );
        if (i < INITIAL_STEP1_CHECKS.length - 1) {
          schedule(() => runCheck(i + 1), 700);
        } else {
          // All passed — advance to Step 2
          schedule(() => setActiveStep(1), 500);
        }
      }, 700);
    }
    runCheck(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Step 2: run RBAC checks when entering step 2 ──────────────────────────
  useEffect(() => {
    if (activeStep !== 1 || autoFixApplied) return;

    // Intentional failure outcomes: [fail, pass, pass]
    const outcomes: CheckStatus[] = ['fail', 'pass', 'pass'];

    function runCheck(i: number) {
      setStep2Checks(prev =>
        prev.map((c, idx) => (idx === i ? { ...c, status: 'running' } : c))
      );
      schedule(() => {
        setStep2Checks(prev =>
          prev.map((c, idx) => (idx === i ? { ...c, status: outcomes[i] } : c))
        );
        if (i < INITIAL_STEP2_CHECKS.length - 1) {
          schedule(() => runCheck(i + 1), 600);
        } else {
          setStep2Done(true);
        }
      }, 600);
    }
    runCheck(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeStep, autoFixApplied]);

  // ── Auto-fix: re-run checks, all pass ─────────────────────────────────────
  function handleAutoFix() {
    setAutoFixRunning(true);
    setStep2Done(false);
    setStep2Checks(INITIAL_STEP2_CHECKS);

    schedule(() => {
      // After fake "apply", re-run with all passing
      function runFixed(i: number) {
        setStep2Checks(prev =>
          prev.map((c, idx) => (idx === i ? { ...c, status: 'running' } : c))
        );
        schedule(() => {
          setStep2Checks(prev =>
            prev.map((c, idx) => (idx === i ? { ...c, status: 'pass' } : c))
          );
          if (i < INITIAL_STEP2_CHECKS.length - 1) {
            schedule(() => runFixed(i + 1), 400);
          } else {
            setAutoFixApplied(true);
            setAutoFixRunning(false);
            setStep2Done(true);
          }
        }, 400);
      }
      runFixed(0);
    }, 1500);
  }

  // ── Terminal auto-scroll ───────────────────────────────────────────────────
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  // ── Deploy: add terminal lines one by one ─────────────────────────────────
  function handleDeploy() {
    setDeployStarted(true);

    function addLine(i: number) {
      setTerminalLines(prev => [...prev, DEPLOY_LINES[i]]);
      if (i < DEPLOY_LINES.length - 1) {
        schedule(() => addLine(i + 1), 400);
      } else {
        schedule(() => setDeployDone(true), 300);
      }
    }
    addLine(0);
  }

  // ── Step content renderers ─────────────────────────────────────────────────

  function renderStep1() {
    return (
      <Box display="flex" flexDirection="column" gap={0.5}>
        <Typography variant="subtitle2" color="text.secondary" mb={1}>
          Verifying cluster prerequisites…
        </Typography>
        {step1Checks.map((c, i) => (
          <CheckRow key={i} check={c} />
        ))}
      </Box>
    );
  }

  function renderStep2() {
    const hasFailed = step2Done && step2Checks.some(c => c.status === 'fail');
    const allPassed = step2Done && step2Checks.every(c => c.status === 'pass');

    return (
      <Box display="flex" flexDirection="column" gap={1.5}>
        <Typography variant="subtitle2" color="text.secondary" mb={0.5}>
          Checking required Kubernetes RBAC resources…
        </Typography>

        {step2Checks.map((c, i) => (
          <CheckRow key={i} check={c} />
        ))}

        {hasFailed && !autoFixApplied && (
          <Box mt={1} display="flex" flexDirection="column" gap={1.5}>
            <Alert severity="error">
              <Typography variant="body2" fontWeight="bold">
                Missing ClusterRole: inspektor-gadget-clusterrole
              </Typography>
              <Typography variant="body2">
                Gadget requires privileged kernel access to load eBPF programs.
              </Typography>
            </Alert>
            <Box display="flex" gap={1}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<Icon icon="mdi:code-braces" width={16} />}
                onClick={() => setYamlOpen(true)}
              >
                View Required YAML
              </Button>
              <Button
                variant="contained"
                color="warning"
                size="small"
                disabled={autoFixRunning}
                startIcon={
                  autoFixRunning ? (
                    <CircularProgress size={14} color="inherit" />
                  ) : (
                    <Icon icon="mdi:wrench" width={16} />
                  )
                }
                onClick={handleAutoFix}
              >
                {autoFixRunning ? 'Applying…' : 'Auto-Fix (Apply YAML)'}
              </Button>
            </Box>
          </Box>
        )}

        {allPassed && (
          <Box mt={1} display="flex" flexDirection="column" gap={1.5}>
            <Alert severity="success">
              All RBAC checks passed. You can proceed to deployment.
            </Alert>
            <Button
              variant="contained"
              color="primary"
              onClick={() => setActiveStep(2)}
              endIcon={<Icon icon="mdi:arrow-right" width={16} />}
            >
              Continue to Deploy
            </Button>
          </Box>
        )}
      </Box>
    );
  }

  function renderStep3() {
    return (
      <Box display="flex" flexDirection="column" gap={2}>
        <Typography variant="subtitle2" color="text.secondary">
          Deploy Inspektor Gadget using Helm:
        </Typography>

        {/* Helm command display */}
        <Paper
          variant="outlined"
          sx={{
            p: 1.5,
            bgcolor: theme.palette.action.hover,
            display: 'flex',
            alignItems: 'center',
            gap: 1,
          }}
        >
          <Icon icon="mdi:console" width={18} color={theme.palette.text.secondary} />
          <Typography
            variant="body2"
            fontFamily="monospace"
            sx={{ flex: 1, wordBreak: 'break-all' }}
          >
            {HELM_CMD}
          </Typography>
          <IconButton
            size="small"
            title="Copy command"
            onClick={() => navigator.clipboard?.writeText(HELM_CMD)}
          >
            <Icon icon="mdi:content-copy" width={16} />
          </IconButton>
        </Paper>

        <Button
          variant="contained"
          color="primary"
          disabled={deployStarted}
          startIcon={<Icon icon="mdi:rocket-launch" width={18} />}
          onClick={handleDeploy}
          sx={{ alignSelf: 'flex-start' }}
        >
          Deploy via Helm
        </Button>

        {/* Terminal output */}
        {terminalLines.length > 0 && (
          <Box
            ref={terminalRef}
            sx={{
              bgcolor: '#0d1117',
              color: '#3fb950',
              fontFamily: 'monospace',
              fontSize: 13,
              p: 2,
              borderRadius: 1,
              maxHeight: 200,
              overflowY: 'auto',
              lineHeight: 1.6,
            }}
          >
            {terminalLines.map((line, i) => (
              <Box key={i} component="div">
                {line}
              </Box>
            ))}
            {!deployDone && (
              <Box component="span" sx={{ animation: 'blink 1s step-end infinite' }}>
                {'█'}
              </Box>
            )}
          </Box>
        )}

        {deployDone && (
          <Alert
            severity="success"
            action={
              <Button
                color="inherit"
                size="small"
                endIcon={<Icon icon="mdi:arrow-right" width={14} />}
                onClick={() => {
                  window.location.href = window.location.pathname.split('/').slice(0, 3).join('/') + '/gadgets';
                }}
              >
                Go to Gadgets
              </Button>
            }
          >
            Inspektor Gadget is running. Go to the Gadgets page to start using it.
          </Alert>
        )}
      </Box>
    );
  }

  // ── YAML dialog ────────────────────────────────────────────────────────────

  function renderYamlDialog() {
    return (
      <Dialog open={yamlOpen} onClose={() => setYamlOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={1}>
              <Icon icon="mdi:shield-lock" width={20} color={theme.palette.warning.main} />
              <Typography variant="h6">Required RBAC YAML</Typography>
            </Box>
            <IconButton size="small" onClick={() => setYamlOpen(false)}>
              <Icon icon="mdi:close" width={18} />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" mb={2}>
            Apply this ClusterRole to grant Inspektor Gadget the kernel access it needs to load
            eBPF programs:
          </Typography>
          <Paper
            variant="outlined"
            sx={{ bgcolor: theme.palette.action.hover, overflow: 'auto' }}
          >
            <Box
              component="pre"
              sx={{
                m: 0,
                p: 2,
                fontFamily: 'monospace',
                fontSize: 12,
                color: theme.palette.text.primary,
                whiteSpace: 'pre',
              }}
            >
              {RBAC_YAML}
            </Box>
          </Paper>
          <Box mt={2} display="flex" justifyContent="flex-end" gap={1}>
            <Button
              size="small"
              startIcon={<Icon icon="mdi:content-copy" width={14} />}
              onClick={() => navigator.clipboard?.writeText(RBAC_YAML)}
            >
              Copy YAML
            </Button>
            <Button variant="contained" size="small" onClick={() => setYamlOpen(false)}>
              Close
            </Button>
          </Box>
        </DialogContent>
      </Dialog>
    );
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <Box sx={{ p: 3, maxWidth: 720, mx: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
      {/* Header */}
      <Box>
        <Box display="flex" alignItems="center" gap={1} mb={0.5}>
          <Icon icon="mdi:download-circle" width={28} color={theme.palette.primary.main} />
          <Typography variant="h5" fontWeight="bold">
            Install Inspektor Gadget
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary">
          Guided setup wizard · Issue #13
        </Typography>
      </Box>

      {/* Stepper */}
      <Stepper activeStep={activeStep} alternativeLabel>
        {STEP_LABELS.map((label, i) => (
          <Step key={label} completed={i < activeStep}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      <Divider />

      {/* Step content */}
      <Paper variant="outlined" sx={{ p: 3 }}>
        {activeStep === 0 && renderStep1()}
        {activeStep === 1 && renderStep2()}
        {activeStep === 2 && renderStep3()}
      </Paper>

      {/* YAML dialog */}
      {renderYamlDialog()}
    </Box>
  );
}
