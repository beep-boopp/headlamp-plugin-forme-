# Security UX MVP

> Companion to the GSoC 2025 proposal — demonstrates four security-focused 
> gadget UIs running inside real Headlamp with dynamic mock data aligned to 
> Inspektor Gadget output schemas.

## What's included

| Gadget | Issue | Description |
|--------|-------|-------------|
| eBPF Monitor | #15 | Live resource usage table for active eBPF programs with threshold-based alerting |
| Traffic Visualizer | #16 | Interactive SVG topology of service-to-service traffic with packet drop detection |
| DNS Debug | #17 | Live DNS query panel with retry storm detection and suspicious domain flagging |
| Install Wizard | #13 | Guided three-step setup flow with prerequisite checks and RBAC validation |

## How to run

### Prerequisites

- Node.js 20+ (via nvm)
- Docker Desktop running on Windows
- Minikube

### Steps
```bash
# Step 1 — wake up the environment
nvm use node
minikube start

# Step 2 — forge the kubeconfig
kubectl config view --flatten > ~/.kube/config-headlamp

# Step 3 — build the plugin
cd ~/headlamp-plugin-forme-
npm run build && cp package.json dist/

# Step 4 — launch Headlamp
docker run --rm -u root --network host \
  -v ~/.kube/config-headlamp:/root/.kube/config \
  -v ~/.minikube:/root/.minikube \
  -v $(pwd)/dist:/headlamp/plugins/inspektor-gadget \
  ghcr.io/headlamp-k8s/headlamp:latest
```

Open `http://localhost:4466` in your browser, click into the Minikube 
cluster, and look for **IG Security** in the sidebar.

## Mock data

All panels run on `useMockGadgetStream` — a drop-in hook that produces 
dynamic snapshots every 2–3 seconds with data structures aligned to real 
Inspektor Gadget stream output (`ig-top-ebpf`, `ig-trace-dns`, 
`ig-trace-network`). No live Inspektor Gadget installation required to 
explore the UI.

Replacing mock data with live streams is a targeted swap at the hook 
interface — no UI redesign required.

## Notes

- The `package-lock.json` diff is large due to the SDK upgrade from 
  `@kinvolk/headlamp-plugin@0.11.4` to `0.13.1` — not new feature deps
- All components use named exports and follow existing plugin conventions
- Routes use `/ig-security/*` prefix to avoid conflicts with existing gadget routes