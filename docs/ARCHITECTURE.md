# ReadinessOps architecture

ReadinessOps does not prescribe a two-account topology. The product core remains
usable without an execution adapter: evidence is versioned, the agent proposes,
a human decides and explicitly publishes, Actions and Outcomes are recorded, and
Authority Delta identifies which official decisions are affected by change.

Connected enforcement targets the AWS account registered by an adapter and starts
only after a separate human delegation. The live RO-07 acceptance used distinct
ReadinessOps and target accounts as a least-privilege deployment choice. That is
the topology proven by this repository, not a prerequisite of the product core or
a mandate for every future connector.

The supplied VendorPayment foundation and connector operators require a distinct
target account. A same-account enforcement deployment is not supported or
verified by this release; the core workflow needs neither operator.

## Product boundary

```mermaid
flowchart TB
    subgraph core["ReadinessOps core · no execution adapter required"]
        direction TB

        subgraph assessment["Evidence and assessment"]
            direction LR
            intake["Business object<br/>question · owner · goals"]
            evidence["Versioned evidence<br/>fixed input snapshot"]
            agent["Cited assessment<br/>Strands · AgentCore Runtime · Nova Pro"]
            intake --> evidence --> agent
        end

        subgraph governance["Human governance and operation"]
            direction LR
            review["Human review<br/>edit · approve · return · reject"]
            publication["Explicit publication<br/>official human decision"]
            operations["Actions · Outcomes<br/>retained history"]
            delta["Authority Delta on change<br/>Affected · Unchanged · Unknown"]
            review --> publication --> operations --> delta
        end

        agent -->|"cited proposals only"| review
    end

    noAdapter["Core-only use<br/>AWS authority = NOT_APPLIED"]
    connected["Optional connected enforcement<br/>registered adapter + separate delegation"]

    publication -->|"no execution adapter"| noAdapter
    publication -.->|"separate approval only"| connected

    classDef human fill:#EFF6FF,stroke:#2563EB,color:#0F2747,stroke-width:2px
    classDef service fill:#FFFFFF,stroke:#64748B,color:#0F2747,stroke-width:1.5px
    classDef ai fill:#ECFDF5,stroke:#059669,color:#0F2747,stroke-width:2px
    classDef decision fill:#EEF4FF,stroke:#1D4ED8,color:#0F2747,stroke-width:2px
    classDef optional fill:#F0FDFA,stroke:#0F766E,color:#0F2747,stroke-width:2px
    classDef inactive fill:#FFFFFF,stroke:#94A3B8,color:#334155,stroke-dasharray:5 4

    class intake,evidence,operations service
    class agent ai
    class review human
    class publication,delta decision
    class connected optional
    class noAdapter inactive
    style core fill:#F8FAFC,stroke:#94A3B8,color:#0F2747
    style assessment fill:#FFFFFF,stroke:#CBD5E1,color:#0F2747
    style governance fill:#FFFFFF,stroke:#CBD5E1,color:#0F2747
```

Authority Delta belongs to the product core because change-impact review remains
useful when no execution adapter exists. Publication is an official business
decision in both branches. It never grants AWS runtime authority by itself.

## Optional connected-enforcement roles

The verified connection separates deployment verification, Policy lifecycle and
normal execution. A normal invocation does not pass through the Policy Publisher.

| Purpose | ReadinessOps origin | Connector trust boundary | Qualified connector target |
| --- | --- | --- | --- |
| Deployment verification | CodeBuild deployer | `DiscoveryRole` | Read-only Runtime, Gateway, Policy Engine, target, functions and registry readback |
| Policy application or revocation | Application/Revocation Worker | `PublishInvokeRole` | Limited Publisher Lambda |
| Normal controlled invocation | Invocation Worker | `RuntimeInvokeRole` | Invocation Lambda |

### Policy application and revocation

```mermaid
flowchart LR
    receipt["Official publication<br/>+ separate delegation receipt"]
    worker["Application / Revocation Worker<br/>SQS · retry · reconciliation"]
    boundary["STS AssumeRole<br/>PublishInvokeRole + ExternalId"]
    publisher["Limited Publisher Lambda<br/>exact Policy ownership only"]
    proof["AgentCore Policy lifecycle<br/>deny-first Canary · journal · proof"]

    receipt --> worker --> boundary --> publisher --> proof

    classDef accountA fill:#EEF4FF,stroke:#1D4ED8,color:#0F2747,stroke-width:2px
    classDef trust fill:#FFFFFF,stroke:#64748B,color:#0F2747,stroke-dasharray:5 4
    classDef accountB fill:#F0FDFA,stroke:#0F766E,color:#0F2747,stroke-width:2px

    class receipt,worker accountA
    class boundary trust
    class publisher,proof accountB
```

The Publisher creates, reads or removes only the exact Policy derived from the
immutable candidate. Complete canary and readback evidence must return before
account A installs an AppliedBinding or confirms suspension.

### Normal controlled invocation

```mermaid
flowchart LR
    gate["Authenticated Invocation Gate<br/>exact-current authority check"]
    worker["SQS Invocation Worker<br/>accepted operation recovery"]
    boundary["STS AssumeRole<br/>RuntimeInvokeRole + ExternalId"]
    invocation["Registered Invocation Lambda<br/>verify active Publisher journal"]
    runtime["Registered Runtime → Gateway / Policy<br/>synthetic target · registry · ledger"]

    gate --> worker --> boundary --> invocation --> runtime

    classDef accountA fill:#EEF4FF,stroke:#1D4ED8,color:#0F2747,stroke-width:2px
    classDef trust fill:#FFFFFF,stroke:#64748B,color:#0F2747,stroke-dasharray:5 4
    classDef accountB fill:#F0FDFA,stroke:#0F766E,color:#0F2747,stroke-width:2px

    class gate,worker accountA
    class boundary trust
    class invocation,runtime accountB
```

The browser can select only a registered request identity. The server fixes the
connection, roles, Runtime, principal, tools, request payload, Policy hash and
expiry. `VendorPayment V2` is a synthetic adapter and performs no real payment.

## Stop and expiry completion rule

This rule applies only when connected authority is active.

```mermaid
flowchart LR
    stop["Stop request or expiry"]
    close["Close entry<br/>invalidate generation"]
    remove["Remove exact<br/>owned Policy"]
    deny["Prove live DENY for<br/>all registered requests"]
    confirmed["Suspension confirmed<br/>history retained"]

    stop --> close --> remove --> deny --> confirmed

    classDef trigger fill:#FFF1F2,stroke:#E11D48,color:#4C0519,stroke-width:2px
    classDef check fill:#FFFFFF,stroke:#BE123C,color:#4C0519,stroke-width:1.5px
    classDef complete fill:#ECFDF5,stroke:#047857,color:#052E2B,stroke-width:2px

    class stop trigger
    class close,remove,deny check
    class confirmed complete
```

Suspension is complete only when the entry is closed, the exact owned Policy is
absent, every registered request has a fresh live `DENY`, and the ledger remains
unchanged. An unknown result remains nonterminal and is recovered fail closed.
