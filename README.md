# meshid — 零信任的服务间身份

把“几百个微服务共用一个长期密钥”换成：每个服务实例启动时，用自己的硬件身份向签发服务证明“我是这台机器的这个二进制”，拿到一张只有自己能用、几分钟就过期的证书；服务之间用双向 TLS 凭证书互相认证。

这里的核心不是 TLS，而是三个工程问题的答案，代码里都有对应实现和测试：

1. **不靠预置秘密，实例怎么证明自己是谁** —— 见 [机器身份的证明链](#1-机器身份的证明链)
2. **攻击者控制一台机器，能不能拿到别人的身份** —— 见 [爆炸半径](#2-爆炸半径) 与 `test/e2e/attacker_test.go`
3. **证书怎么在不中断调用的情况下持续轮换；签发服务宕机怎么办** —— 见 [轮换](#3-轮换不中断调用) 与 [故障容忍](#4-签发服务宕机)

---

## 快速开始

```bash
go test ./...                                  # 单元测试 + 端到端（约 10 秒）
go test ./test/e2e -v -run TestAttestationGrantsIdentity   # 单看主流程
go test ./test/e2e -race                       # 竞态检测（约 45 秒）
```

用真实进程体验一遍（会打印每台机器、每个 authd 副本的地址）：

```bash
go run ./cmd/simctl up -dir /tmp/w -nodes 3 -authd 2
```

用单独的进程运行一个完整部署：

```bash
go run ./cmd/simctl up -dir /tmp/w        # 前台，Ctrl-C 退出
# 另一个终端：给 node-1 上的服务取身份并起一个 mTLS 服务
go run ./cmd/workload -socket /tmp/msk-xxx/agent.sock -ns demo -svc frontend -listen 127.0.0.1:8080
go run ./cmd/workload -socket /tmp/msk-yyy/agent.sock -ns demo -svc echo -call https://127.0.0.1:8080
```

---

## 1. 机器身份的证明链

实例启动时**没有任何预置秘密**。它唯一拥有的、且攻击者偷不走的东西，是这台机器的 TPM（`internal/hsm` 是它的可执行模拟）。证明分四步，任何一步缺失都签不出证书：

```
平台厂商根 (离线, 10年)
   └── EK 证书            每台机器出厂时固化在 TPM 里
         └── AK 证书      AK 由 EK 在 TPM 内部签发（TPM2_Certify）
               └── quote  AK 对 (一次性 nonce, 节点名, TLS 公钥哈希, 节点CA公钥哈希) 签名
```

签发服务（authd）验证：

1. EK 证书能链到**平台厂商根** —— 这是一台真实机器。
2. AK 证书的**直接签发者就是这张 EK** —— AK 和 EK 在同一块芯片里，不是随便哪台机器的 AK。
3. AK 的签名覆盖了**我们刚发的、只能用一次的 nonce**，以及 CSRs 里的两个公钥哈希 —— 这是现场生成的证明，不是录下来的。

关键设计：**nonce 在验证前就被原子消费掉**（`store.ConsumeChallenge`，用的是文件系统的原子删除 + flock，多个 authd 副本共享），所以录制一次完整的入网流量无法重放；签名里绑定公钥哈希，所以即使能重放也无法把证书挪到自己的密钥上。

**还要防“李鬼机器”**：attestation 只证明“这是一台真机器”，不证明“这是我配的那台 node-7”。所以 authd 还有一张设备清单（`store.NodeRecord`，部署时把节点名和 EK 指纹绑定，生产环境来自 TPM 厂商的 EK 注册库）。没有这条，任何有一台真机器的人都能用别人的名字入网。这条检查在 `authd/attest.go`，测试是 `TestCompromisedMachineCannotImpersonateNeighbour/attacker_cannot_enroll_under_node-1's_name`。

> 模拟器的诚实边界：`internal/hsm` 没有 PCR 度量、没有绑定启动状态的 sealed storage，“出厂”发生在测试进程里。它忠实建模的只有一件事：**运行时秘密 ≠ 硬件身份，且只有模块能用后者**。生产环境换成真 TPM 2.0，接口不变。

### 进程身份：agent 怎么知道“你是你”

服务向本机 agent（Unix socket）要证书时，**请求体里的服务名只是“声称”**。agent 用内核提供的事实来判断（`internal/procinfo`，macOS 用 `LOCAL_PEERPID` + `sysctl`，Linux 用 `SO_PEERCRED` + `/proc`）：

- 对端 PID（内核报告的，不是客户端说的）
- UID
- 进程启动时间（防 PID 复用）
- 可执行文件的真实路径 + **SHA-256**（打开后 stat 两次，中途被换会拒绝）

拿这些事实对照**签名过的策略**（`certutil.Policy`），默认拒绝，必须显式授权：

```json
{ "ns": "pay", "svc": "ledger",
  "binary_sha256": "…",        // 必须是这个构建产物
  "require_uid": 501,           // 必须这个用户
  "nodes": ["node-7"],          // 只允许在这台机器上
  "allow_degraded": false,      // authd 挂掉时不许自签
  "max_ttl_sec": 300 }
```

accept 时拿到的事实，和签证书前**再读一次**的事实会比对 `StableID()`（PID + 启动时间 + UID + 二进制哈希），关掉“进程退出、PID 被复用”的窗口。

---

## 2. 爆炸半径

这是整个设计的中心问题。假设攻击者拿到了 node-2 的 root、agent 进程、TPM，甚至连 node-2 的中间 CA 私钥都挖出来了。他能得到什么？

| 攻击手段 | 结果 | 测试 |
|---|---|---|
| 用 node-2 的 agent 申请 node-1 的服务 | 拒绝：策略里 `nodes:["node-1"]`，二进制哈希也不符 | `own_agent_refuses_neighbour` |
| 用偷来的 node-2 中间 CA 直接签一张谎称 node-1 的叶子 | 拒绝：签发的中间 CA 带 **scope 扩展**，只能签自己那个节点；对端逐张检查叶子的 `node` 必须等于签发者的 scope | `forged_leaf_from_stolen_node_CA` |
| 签一张 `mode=degraded`（宕机自签）的假叶子 | 拒绝：degraded 叶子对 scope 的检查更严 | `degraded_self-issued_leaf` |
| 拿一台全新的真机器，用 node-1 的名字入网 | 拒绝：设备清单里 node-1 的 EK 指纹对不上 | `cannot_enroll_under_node-1's_name` |
| 用 node agent 的证书去调服务 | 拒绝：对端要求 `role=workload` | `TestAgentRoleCannotIssue` |

**node-scoped 中间 CA** 是关键：authd 给每个节点发一张只覆盖该节点、只有几小时寿命的中间证书（`Scope{Node, MaxTTLSec}`）。这张密钥就算被偷，也只能为一个节点签发短命身份；而且它本身可以被单独吊销。因此“控制一台机器”=“最多拿到那台机器的身份”，不会横向扩散。

> 一个必须诚实说明的残余风险：如果攻击者的目标是**node-2 自己**，而 node-2 的 agent 又有权限给某个敏感服务签发（策略允许），那他用 node-2 的身份就是合法的——这是分布式系统的固有事实。设计能做的是让这件事可观测（审计日志）、可快速切断（节点级吊销）、并且不波及其他节点。

---

## 3. 轮换不中断调用

- 证书默认 10 分钟（可配到秒级），在寿命 2/3 处开始续签；**续签用的还是同一把 TPM 里的私钥**，全程不搬运私钥。
- 调用方/服务端用的是 `tls.Config.GetCertificate` / `GetClientCertificate`（`internal/identity`），**TLS 配置本身在进程生命周期内不变**，底层证书原子替换：新握手用新证书，已经建立的连接不受影响。
- 旧证书在自身过期前仍然可用，所以“续签瞬间”不会出现两边证书对不上。
- 测试 `TestRotationWithoutDroppingConnections` 在持续调用中连转 3 次，断言**零失败请求**，且对端确实看到了不同的序列号。

## 4. 签发服务宕机

把 authd 从关键路径上拿下来，靠三件事：

1. **证书都是短命的、但不会在宕机时同时过期**：错峰续签，且 node agent 手上有一张几小时有效的节点 CA，可以在 authd 不可达时**自签降级证书**（`mode=degraded`）。
2. **信任材料是签过名的文档**：bundle / policy / 吊销列表都由根密钥签名，agent 缓存副本（`internal/trust`）。authd 全挂，缓存继续生效，验证不停。
3. **降级签发是白名单**：只有策略里 `allow_degraded:true` 的服务才能在宕机时自签，TTL 更短，且带 `mode=degraded` 标记，对端可以据此做更严的授权。敏感服务默认**失败关闭**。

`TestAuthdOutageKeepsMeshRunning`：两个 authd 副本全停后，已有证书的双向认证照常；未授权的服务自签被拒；授权的服务拿到 degraded 证书且能被对端识别。`TestSustainedTrafficThroughRotationAndOutage` 在 8 路并发流量下经历轮换 + 全量宕机，要求继续有成功调用、失败率 <10%。

---

## 5. 吊销：对已建立的连接也生效

TLS 只在握手时校验证书，长连接会绕过吊销。所以两个层面都做（`internal/mesh/mesh.go` 的 `Guard`）：

- 每次请求都拿**当前的**吊销列表重新校验对端身份；
- 吊销列表由根密钥签名、定期拉取（测试里推到毫秒级）；
- 吊销支持 实例 / 节点+服务 / **整节点** 三个粒度 —— 怀疑一台机器被控，一条 `{"node":"node-2"}` 就切断它所有历史凭据。

`TestRevocationCutsLiveConnections` 先在池化连接上打通一次，再吊销 node-1，确认下一次请求失败。

---

## 代码地图

```
internal/
  certutil/    证书形态、私有扩展、签名信封、吊销、scope 检查
  hsm/         模拟 TPM：EK/AK/quote，私钥不出模块
  procinfo/    内核事实：peer PID、UID、启动时间、二进制哈希（darwin/linux）
  agent/       节点 agent：证明→入网→轮换→给本机进程签证书（含降级签发）
  authd/       签发服务：验证证明、签节点/工作负载证书、签发/轮换/吊销 API
  mesh/        服务端接入库：Verifier、Guard 中间件、热轮换 TLS
  identity/    客户端凭证：活性续签，旧证书保留
  trust/       不可变信任快照、签名文档校验
  store/       控制面状态：bundle/policy/吊销/一次性 nonce/设备清单/审计
  deploy/      把整个部署落盘，供独立进程使用
  sim/         内存里的多机环境（测试和 simctl 的基座）
cmd/
  authd nodeagent workload hsmd loadgen simctl
test/e2e/      真实进程、真实 Unix socket、真实 TLS 的端到端测试
```

### 端到端测试覆盖的安全属性

| 测试 | 证明什么 |
|---|---|
| `TestAttestationGrantsIdentity` | 无预置秘密入网 → 按二进制取身份 → 跨机 mTLS → 轮换后继续可用 |
| `TestCompromisedMachineCannotImpersonateNeighbour` | 控制整台 node-2（含其中间 CA、TPM）拿不到 node-1 的身份（4 条攻击路径） |
| `TestRevokeWholeNodeKillsAllItsIssuance` | 节点级吊销同时切断：对端信任、在线签发、降级签发 |
| `TestRevocationCutsLiveConnections` | 吊销对已建立的连接下一次请求即生效 |
| `TestAuthdOutageKeepsMeshRunning` | authd 全挂：已有身份照常、未授权服务失败关闭、授权服务 degraded 签发 |
| `TestRotationWithoutDroppingConnections` | 持续调用中轮换证书，零失败请求 |
| `TestSustainedTrafficThroughRotationAndOutage` | 8 路并发 + 轮换 + 全量宕机，要求持续有成功调用 |
| `TestPolicyWithdrawalBeatsStaleCache` | 撤回授权后，节点不能用过期缓存走降级签发 |
| `TestWorkloadCertificateCannotRequestIdentities` | 工作负载证书不能当签发者用（即使伪造完美的请求体） |
| `TestWrongBinaryIsRefused` / `TestReplayedEnrollmentFails` / `TestNonceIsBoundToNode` | 二进制钉死、nonce 一次性、nonce 绑定节点名 |

**接入一个现有服务**（`internal/mesh`）：

```go
verifier := mesh.NewVerifier(mesh.VerifierConfig{
    Trust: trustStore, Expect: mesh.ExpectClient, RequireRole: certutil.RoleWorkload,
})
mux := http.NewServeMux()
mux.HandleFunc("/api", handler)   // handler 里用 mesh.FromContext(r.Context()) 取调用方身份
srv := &http.Server{
    Handler:   mesh.Guard(trustStore, func(w http.ResponseWriter, r *http.Request, id *mesh.Identity) { mux.ServeHTTP(w, r) }),
    TLSConfig: mesh.ServerConfig{Verifier: verifier, Certs: creds}.TLSConfig(),
}
srv.ServeTLS(ln, "", "")   // 证书来自 creds，轮换在底下发生
```

---

## 已知边界与生产化清单

- **根密钥**：模拟里放在磁盘上；生产必须在离线机 / HSM 上，authd 只持有短命中间证书，bundle/policy 由离线流程预签。
- **设备清单**：生产应来自 TPM 厂商 EK 注册库 + CMDB，而不是手工登记。
- **平台可证明性**：当前证明“真机器 + 那台机器”；若要对构建产物更强保证，需要 PCR 度量 + 签名镜像（如 `dm-verity` / attestation of container image digest）。
- **UID 冒充**：同一 UID 下的进程在 agent 看来只能靠二进制哈希区分；更严的场景需要 UID 隔离或内核级可信启动。
- **错误方向**：所有平台相关代码在无法读取事实时**失败关闭**（`procinfo` 直接返回错误）。
- **性能**：每次请求重校验吊销列表是 O(条目数) 的；生产应改为布隆过滤器 + 按版本号缓存。
