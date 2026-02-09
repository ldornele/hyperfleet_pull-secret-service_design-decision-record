# HyperFleet Pull Secret Service - Design Decision Record

---

## Executive Summary

The **HyperFleet Pull Secret Service** is a cloud-agnostic credential management service that generates, stores, and rotates container registry pull secrets for HyperFleet-managed clusters. This design lifts and shifts proven logic from the AMS (UHC Account Manager) pull secret implementation, adapting it for HyperFleet's multi-cloud, adapter-driven architecture.

**Scope**:
- **M1 (MVP)**: Cloud-agnostic pull secret generation for Quay.io and Red Hat registries
- **M2**: Automated credential rotation and lifecycle management
- **M3**: Support for private/customer-specific registries (e.g., Harbor, Nexus) and multi-cloud secret storage

**Assumptions**:
- **HyperFleet Pull Secret Service** will not interact with OCM components (including AMS).
- Red Hat SSO authentication is out of scope. As token retrieval is effectively anonymous and relies on cloud provider–based identification, the **HyperFleet Pull Secret Service** will not have access to Red Hat IT user information for screening purposes. 
- A per-hyperfleet instance deployment (Option A) is adopted over a global shared service to prioritize operational simplicity and failure isolation during the MVP phase, while preserving a path to post-MVP consolidation. Post-MVP, the architecture should support both per-hyperfleet and global deployments, enabling broader reuse (e.g., for OCP self-managed use cases).
- **HyperFleet Pull Secret Service** will adopt the T-Rex pattern as its architectural pattern.

---

## Table of Contents

1. [Pull Secret Service Purpose and Responsibilities](#1-pull-secret-service-purpose-and-responsibilities)
2. [AMS Lift-and-Shift Assessment](#2-ams-lift-and-shift-assessment)
8. [Pull Secret Rotation Requirements](#8-pull-secret-rotation-requirements)

---

## 1. Pull Secret Service Purpose and Responsibilities

### 1.1 Service Overview

The **Pull Secret Service** is responsible for:

1. **Credential Generation**: Create robot accounts (Quay) and partner service accounts (Red Hat Registry) for cluster access to container registries
2. **Secret Storage**: Store generated credentials in appropriate secret management systems (cloud-specific secret managers, Vault, Kubernetes Secrets)
3. **Pull Secret Formatting**: Generate standard Docker auth config format for HyperShift consumption
4. **Credential Rotation**: Automatically rotate credentials on a configurable schedule or on-demand
5. **Lifecycle Management**: Track credential status, handle bans/unbans, and clean up expired credentials
6. **Multi-Registry Support**: Support multiple registries (Quay.io, registry.redhat.io, cloud.openshift.com, private registries)

### 1.2 Service Boundaries

**In Scope**:
- Registry credential generation (Quay robot accounts, Red Hat partner service accounts)
- Docker auth config formatting
- Credential storage and retrieval
- Rotation orchestration
- Ban/unban operations
- Credential pool pre-generation (performance optimization)

**Out of Scope**:
- Cluster authentication (handled by HyperFleet API)
- Registry deployment or management
- Image scanning or vulnerability management
- Registry mirror/proxy configuration
- Network policies for registry access

---

## 2. AMS Lift-and-Shift Assessment

Based on analysis of `uhc-account-manager` repository, the following components should be lifted and shifted:

#### 3.1.1 Data Model

**RegistryCredential** (`pkg/api/registry_credential_types.go`):
```go
type RegistryCredential struct {
    ID                  string    // UUID
    Username            string    // External registry account name (e.g., hyperfleet_{provider}_{region}_{uuid} for Quay, uhc-{cluster-id} for RHIT)
                                  // NOTE: This is the technical identifier of the credential in the external registry,
                                  // NOT Red Hat IT user information. Derived from cluster ID and cloud context, not user identity.
    Token               string    // External registry access token (encrypted at rest)
    AccountID           *string   // Link to cluster owner (nullable for pool credentials)
                                  // NOTE: In HyperFleet context, this is cluster ID, not RHIT user account ID
    RegistryID          string    // Link to Registry definition
    ExternalResourceID  *string   // Cluster external ID
    CreatedAt           time.Time
    UpdatedAt           time.Time
}
```
**Note on Rotation Implementation**:
The AMS code does **not** use a `Rotated` boolean field. Instead, rotation is handled by:
1. Creating new `RegistryCredential` records for the cluster
2. Maintaining multiple credentials for the same cluster during dual-credential period
3. Deleting old `RegistryCredential` records after rotation completes
4. Using `CreatedAt` timestamps to identify newest credentials

**HyperFleet Adaptation**: Follow the same pattern - multiple credential records per cluster, delete old records after successful rotation.

**Important Clarification on Field Semantics**:

The `Username` and `AccountID` fields in the `RegistryCredential` model have **different semantics** in HyperFleet compared to AMS:

| Field | AMS (User-Centric) | HyperFleet (Cluster-Centric) |
|-------|-------------------|------------------------------|
| `Username` | Could reference RHIT user account in some contexts | **Technical identifier** of the credential created in external registry (e.g., `hyperfleet_gcp_us-east1_abc123`, `uhc-cls-abc-123`). **Never** contains Red Hat IT user information. Includes cloud provider and region for better traceability. |
| `AccountID` | Red Hat organization/account ID | **Cluster ID** in HyperFleet. Nullable for pool credentials. |

**Key Point**: No Red Hat IT user information (email, user ID, personal data) is stored in this model. All identifiers are derived from **cluster ID** or are **auto-generated UUIDs** for technical registry accounts.

**PullSecretRotation** (`pkg/api/pull_secret_rotation_types.go`):
```go
type PullSecretRotation struct {
    ID         string    // UUID
    ClusterID  string    // HyperFleet cluster ID
    Status     string    // "pending" | "completed"
    CreatedAt  time.Time
    UpdatedAt  time.Time
}
```

**Registry** (`pkg/api/registry_types.go`) - hardcoded configuration:
```go
type RegistryType string

const (
    QuayRegistry   RegistryType = "Quay"
    RedhatRegistry RegistryType = "Redhat"
)

type Registry struct {
    ID         string       // "quay", "redhat", "cloud-openshift"
    Name       string       // Human-readable name (e.g., "Quay.io", "Red Hat Registry")
    Type       RegistryType // QuayRegistry or RedhatRegistry
    URL        string       // Registry URL (e.g., "quay.io", "registry.redhat.io", "cloud.openshift.com")
    OrgName    string       // Organization name in registry (e.g., "redhat-openshift" for Quay)
    TeamName   string       // Team name for robot account assignment (e.g., "hyperfleet-installers")
    CloudAlias bool         // Whether this registry should be used as cloud alias in pull secret output
                            // Example: cloud.openshift.com is a cloud alias for Quay registry
}
```

#### 3.1.2 Access Token Service

**File**: `pkg/services/access_token.go`


---


## 8. Pull Secret Rotation Requirements


In general, pull secret rotation is required in the following scenarios:

- The current pull secret is no longer valid or is not functioning correctly.  
- A new pull secret is required due to security policies or incident response.

**Pull Secret Rotation Policy (based on industry best practices):**

- **90 days** – Industry standard  
- **60 days** – Enhanced security for regulated environments (e.g., financial or healthcare sectors)
