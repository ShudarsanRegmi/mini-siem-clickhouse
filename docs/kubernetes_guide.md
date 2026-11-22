# Hands-On Kubernetes Guide: Architecture, Operations & SIEM Telemetry

This guide is designed for engineers and SOC analysts transitioning into Kubernetes. It breaks down the mental model of containers, pods, nodes, and VMs, thoroughly demystifies our local cluster infrastructure (`siem-k8s-cluster`), and provides an interactive command playbook so you can build muscle memory working with Kubernetes hands-on.

---

## 1. Demystifying the Concepts: VMs vs. Containers vs. Pods vs. Nodes

If you come from a traditional VM background (VMware Workstation, VirtualBox, Proxmox), Kubernetes can seem like an overwhelming layer of abstractions. Here is the concrete mental model:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PHYSICAL HOST / LAPTOP                          │
├──────────────────────────────────┬─────────────────────────────────────┤
│        ASSET 2: REAL VM          │     ASSET 3: KUBERNETES INFRA       │
│  (VMware Workstation - Debian)   │          (Kind Cluster)             │
│                                  │                                     │
│ ┌──────────────────────────────┐ │ ┌─────────────────────────────────┐ │
│ │ VMware Hypervisor            │ │ │ Docker Engine                   │ │
│ │ ┌──────────────────────────┐ │ │ │ ┌─────────────────────────────┐ │ │
│ │ │ Guest OS Kernel (Debian) │ │ │ │ │ Kind Node Container         │ │ │
│ │ │ ┌──────────────────────┐ │ │ │ │ │ (Simulates a Linux Machine) │ │ │
│ │ │ │ Systemd, auditd      │ │ │ │ │ │ ┌─────────────────────────┐ │ │ │
│ │ │ │ SSH server (sshd)    │ │ │ │ │ │ │ containerd Runtime      │ │ │ │
│ │ │ └──────────────────────┘ │ │ │ │ │ │ ┌─────────────────────┐ │ │ │ │
│ │ └──────────────────────────┘ │ │ │ │ │ │ Kubernetes Pod      │ │ │ │ │
│ └──────────────────────────────┘ │ │ │ │ │ │ ┌───────────────┐ │ │ │ │ │
│                                  │ │ │ │ │ │ │ Container (App│ │ │ │ │ │
│   Separate Virtual Hardware      │ │ │ │ │ │ └───────────────┘ │ │ │ │ │
│   Virtual CPU, RAM, Disk, NIC    │ │ │ │ │ └───────────────────┘ │ │ │ │
│                                  │ │ │ │ └─────────────────────────┘ │ │ │
│                                  │ │ └─────────────────────────────┘ │ │ │
│                                  │ └─────────────────────────────────┘ │ │
└──────────────────────────────────┴─────────────────────────────────────┘
```

### The Hierarchy Explained:
1. **Virtual Machine (VM)**:
   - Packages a complete Guest Operating System with its own Linux kernel, memory allocation, and virtual hardware emulated by a hypervisor (e.g. VMware Workstation).
   - Our **Asset 2** (`debianvm` at `172.16.151.134`) is a real VM.
2. **Container (Docker / containerd)**:
   - Does **not** boot a new kernel. It is simply an isolated Linux process running on the host kernel, separated using Linux **Namespaces** (PID, mount, network isolation) and **cgroups** (CPU/RAM resource limits).
3. **Pod (The Atomic Unit of Kubernetes)**:
   - Kubernetes does **not** manage individual containers directly. It manages **Pods**.
   - A Pod is a wrapper around one (or occasionally several closely coupled) containers.
   - All containers inside the same Pod share the exact same **Network Namespace** (same IP address, can talk to each other via `localhost`) and can share the same **Volumes** (storage).
4. **Node (The Worker Machine)**:
   - A Node is the computer (physical server or VM) where Pods actually execute.
   - In production clouds (AWS EKS, GCP GKE), each Node is an EC2/Compute instance VM running Linux.
   - In our local setup, **Kind** (*Kubernetes in Docker*) simulates a full Kubernetes Node by running a specialized Docker container (`siem-k8s-cluster-control-plane`) that runs `systemd` and `containerd` inside itself!

---

## 2. Our Mini SIEM Kubernetes Architecture

In our Mini SIEM project, Kubernetes is **Asset 3**. Let's examine how it is configured and how telemetry flows from K8s into ClickHouse.

### Cluster Topology
- **Cluster Name**: `siem-k8s-cluster`
- **Kubernetes Version**: `v1.31.2` (stable control-plane node image)
- **Control Plane Container**: `siem-k8s-cluster-control-plane` (managed by Docker on port `41095`)
- **Container Runtime**: `containerd://1.7.18`

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES SECURITY TELEMETRY PIPELINE                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  1. Analyst / Attacker Executes Action
     (e.g., `kubectl exec`, `kubectl run privileged-pod`, `kubectl get secrets`)
                       │
                       ▼
  2. kube-apiserver (API Gateway for the entire cluster)
     Evaluates request against `/etc/kubernetes/policies/audit-policy.yaml`
                       │
                       ▼ [Request & Response Matching Events]
  3. Writes JSON Audit Log to Container Disk:
     `/var/log/kubernetes/kube-audit.log`
                       │
                       ▼ [Docker Volume Mount Bind]
  4. Flushed to Host File:
     `mini-siem-clickhouse/.audit/kube-audit.log`
                       │
                       ▼
  5. Python Ingest Collector (`assets/k8s/collector.py`)
     - Parses JSON records
     - Extracts Actor identity (`user.username`), Source IP, URI, Verb, Resource
     - Identifies high-risk events (Pod Exec, Privileged Pod, Secret Harvesting)
                       │
                       ▼ [HTTP POST /api/v1/telemetry]
  6. FastAPI Ingestion Gateway (`siem_gateway`: port 8000)
                       │
                       ▼ [SQL INSERT]
  7. ClickHouse Database (`siem.raw_telemetry`)
                       │
                       ▼ [Scheduled Detection Rule Evaluation]
  8. Detection Engine (`detections/engine.py`)
     - Fires `SEC-K8S-001` (Privileged Pod Escalation)
     - Fires `SEC-K8S-002` (Suspicious Pod Exec & Token Snooping)
                       │
                       ▼
  9. ClickHouse Alerts (`siem.security_alerts`) ──► Grafana Dashboard (Port 3000)
```

### The Audit Policy (`assets/k8s/audit-policy.yaml`)
Kubernetes audit logging is configured to capture high-severity security events at the `RequestResponse` level:
- **Interactive Container Access**: `pods/exec`, `pods/attach`, `pods/portforward`
- **Credential & Identity Snooping**: `secrets`, `serviceaccounts`
- **Privilege Escalation & Permissions**: `clusterroles`, `rolebindings`
- **Workload Lifecycle**: `pods`, `deployments`, `daemonsets`

---

## 3. Hands-On Interactive Command Playbook

Run these commands in your terminal to explore, inspect, and interact with the cluster.

### Step 1: Cluster & Node Inspection
Verify that your local `kubectl` is communicating with the Kind control-plane:

```bash
# Check cluster connection endpoint
kubectl cluster-info

# List all nodes in the cluster
kubectl get nodes -o wide

# Inspect the underlying Docker container running our Kubernetes Node
docker ps --filter "name=siem-k8s-cluster"
```

To see everything about how the node is provisioned (OS, Kernel, CPU capacity, allocated pods):
```bash
kubectl describe node siem-k8s-cluster-control-plane
```

---

### Step 2: Exploring Namespaces & Core System Pods
In Kubernetes, **Namespaces** partition a cluster into virtual workspaces.

```bash
# List all namespaces
kubectl get namespaces

# List all pods running across ALL namespaces (-A stands for --all-namespaces)
kubectl get pods -A
```

Notice the system pods running in `kube-system`:
- `kube-apiserver-siem-k8s-cluster-control-plane`: The brain and front door of Kubernetes.
- `etcd-siem-k8s-cluster-control-plane`: The key-value database storing cluster configuration.
- `kube-controller-manager`: Maintains desired state (e.g., restarts dead pods).
- `kube-scheduler`: Assigns pods to available worker nodes.
- `coredns-...`: Provides internal DNS names (`my-service.namespace.svc.cluster.local`).

To inspect the API server pod configuration:
```bash
kubectl describe pod -n kube-system kube-apiserver-siem-k8s-cluster-control-plane
```

---

### Step 3: Launching & Managing Your First Pod
Let's launch an interactive Alpine Nginx web server pod to see the full pod lifecycle.

#### 1. Create the Pod:
```bash
kubectl run learning-nginx --image=nginx:alpine --port=80
```

#### 2. Check Pod Status:
```bash
# Watch the pod status transition from ContainerCreating to Running
kubectl get pods -o wide

# Inspect detailed events, IP address, and container state
kubectl describe pod learning-nginx
```

#### 3. View Pod Logs:
```bash
kubectl logs learning-nginx
```

#### 4. Forward Ports to Your Host Browser:
Pods live on an internal private network (`10.244.x.x`). To test the web server from your host laptop:
```bash
kubectl port-forward pod/learning-nginx 8085:80
```
Open a separate terminal and test:
```bash
curl http://localhost:8085
```
*(Press `Ctrl+C` to stop the port-forward).*

---

### Step 4: Interactive Shell & Security Token Inspection
Every pod in Kubernetes is automatically assigned a default **ServiceAccount**, which mounts a JWT identity token into the container. Attackers frequently harvest these tokens to authenticate directly to the Kubernetes API server.

#### 1. Open an interactive shell inside the running pod:
```bash
kubectl exec -it learning-nginx -- /bin/sh
```

#### 2. Run commands inside the container:
```sh
# Check your identity inside the container
whoami
hostname
ip addr

# Inspect the automatically mounted Kubernetes ServiceAccount credentials!
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# View the CA certificate and namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# View the actual JWT bearer token
cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 50 && echo "..."

# Exit the container
exit
```

#### 3. Clean up the test pod:
```bash
kubectl delete pod learning-nginx
```

---

### Step 5: Deployments & Self-Healing Workloads
In real production environments, you rarely create standalone pods with `kubectl run`. If a standalone pod crashes or the node restarts, the pod dies permanently. Instead, you create a **Deployment**, which manages a **ReplicaSet** and guarantees that a specific number of pod copies are always healthy.

#### 1. Create a Deployment with 3 replicas:
```bash
kubectl create deployment web-fleet --image=nginx:alpine --replicas=3
```

#### 2. View the deployment and its 3 managed pods:
```bash
kubectl get deployments
kubectl get pods -l app=web-fleet
```

#### 3. Test Kubernetes Self-Healing (Resilience):
Kill one of the pods manually and observe what happens:
```bash
# Grab the name of one of the 3 pods
FIRST_POD=$(kubectl get pods -l app=web-fleet -o jsonpath='{.items[0].metadata.name}')
echo "Killing pod: $FIRST_POD"

# Delete that pod
kubectl delete pod "$FIRST_POD"

# Immediately list pods again
kubectl get pods -l app=web-fleet
```
*Notice: Kubernetes instantly detected the missing replica and created a brand-new replacement pod within milliseconds!*

#### 4. Scale up the fleet:
```bash
kubectl scale deployment web-fleet --replicas=5
kubectl get pods -l app=web-fleet
```

#### 5. Clean up:
```bash
kubectl delete deployment web-fleet
```

---

### Step 6: Seeing the Security Telemetry Flow into the SIEM Live!

Now let's connect Kubernetes actions directly to our Mini SIEM pipeline so you can see how an action produces an audit log, gets ingested into ClickHouse, and triggers alerts.

#### 1. Run a command that generates an audit trail:
```bash
# Spin up a temporary pod and execute a command
kubectl run audit-demo --image=busybox:1.36 --restart=Never -- sleep 30
kubectl wait --for=condition=Ready pod/audit-demo --timeout=15s
kubectl exec -i audit-demo -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/
kubectl delete pod audit-demo
```

#### 2. Check the raw Kubernetes Audit Log on the host:
```bash
# View the latest audit records in JSON format
tail -n 2 mini-siem-clickhouse/.audit/kube-audit.log | jq .
```
Notice the fields: `verb` (`create`), `resource` (`pods/exec`), `user.username`, `sourceIPs`, and `requestURI`.

#### 3. Ship the new audit records to the Mini SIEM:
```bash
python3 mini-siem-clickhouse/assets/k8s/collector.py
```

#### 4. Query ClickHouse to see your events:
Since ClickHouse runs inside the `siem_clickhouse` Docker container, you can run queries directly from your host terminal using `docker exec`:

```bash
docker exec -i siem_clickhouse clickhouse-client \
  --user default \
  --password "$(grep CLICKHOUSE_ADMIN_PASSWORD mini-siem-clickhouse/.env | cut -d= -f2)" \
  --query "
SELECT timestamp, asset_id, event_name, actor, details
FROM siem.raw_telemetry
WHERE asset_type = 'k8s'
ORDER BY timestamp DESC
LIMIT 5
FORMAT PrettyCompact
"
```
*(Alternatively, you can also paste this query directly into **Grafana Explore** at `http://localhost:3000/explore` selecting the ClickHouse datasource!)*

#### 5. Run the detection engine:
```bash
python3 mini-siem-clickhouse/detections/engine.py
```

---

## 4. Understanding the Two Kubernetes Attack Scenarios

Our project includes two realistic attack scenarios modeled after actual Kubernetes compromises:

### Attack Scenario 3: Privileged Container Escape (`attacks/attack_3_privileged_pod.sh`)
- **MITRE ATT&CK**: T1610 (Deploy Container), T1611 (Escape to Host)
- **The Concept**: A malicious pod is deployed with:
  ```yaml
  securityContext:
    privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
  ```
  By mounting the host's `/` filesystem inside the container, the container process has full read/write access to the host node's operating system, breaking container isolation.
- **SIEM Detection**: Rule `SEC-K8S-001` queries `siem.raw_telemetry` for `pod_create` events where `details` contain `privileged: true` or `hostPath: /`.

### Attack Scenario 4: Pod Exec & Token Snooping (`attacks/attack_4_k8s_exec.sh`)
- **MITRE ATT&CK**: T1059 (Execution), T1552.007 (Container Credentials)
- **The Concept**: An attacker with stolen `kubectl` credentials runs `kubectl exec` into an active workload to steal its mounted ServiceAccount JWT token.
- **SIEM Detection**: Rule `SEC-K8S-002` queries `siem.raw_telemetry` for `verb = 'create'` and `resource = 'pods/exec'` targeting non-system pods.

---

## 5. Quick-Reference Kubernetes Cheat Sheet

| Command | Purpose |
|---|---|
| `kubectl cluster-info` | Display control plane address and cluster health |
| `kubectl get nodes -o wide` | List all nodes with IP and OS information |
| `kubectl get pods -A` | List all pods across all namespaces |
| `kubectl get pods -n <namespace>` | List pods in a specific namespace |
| `kubectl describe pod <name>` | Show detailed events, image pulls, and status |
| `kubectl logs <name>` | Show stdout/stderr logs from a pod's container |
| `kubectl logs <name> -f` | Stream live logs (follow mode) |
| `kubectl exec -it <name> -- /bin/sh` | Open an interactive shell inside a running pod |
| `kubectl port-forward pod/<name> 8080:80` | Map port 8080 on your host to port 80 inside the pod |
| `kubectl run <name> --image=<img-name>` | Quick one-liner to start a standalone pod |
| `kubectl create deployment <name> --image=<img>` | Create a managed, scalable deployment |
| `kubectl scale deployment <name> --replicas=N` | Adjust number of pod replicas |
| `kubectl delete pod <name>` | Terminate a pod |
| `kubectl delete deployment <name>` | Remove a deployment and all its child pods |
| `kubectl get events --sort-by='.metadata.creationTimestamp'` | List recent cluster events (errors, scheduling) |

---

## 6. Summary: Where to Go From Here
- Whenever you make changes or deploy test pods, run `python3 mini-siem-clickhouse/assets/k8s/collector.py` to ingest the audit logs.
- Open your Grafana dashboard at `http://localhost:3000/d/mini-siem-overview` and set the top filter dropdown `$asset_type` to **`k8s`** to isolate your Kubernetes posture, alerts, and live event telemetry.
