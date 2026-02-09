# HyperFleet Pull Secret Service - Design Decision Record

---

## Executive Summary

The **HyperFleet Pull Secret Service** is a cloud-agnostic credential management service that generates, stores, and rotates container registry pull secrets for HyperFleet-managed clusters. This design lifts and shifts proven logic from the AMS (UHC Account Manager) pull secret implementation, adapting it for HyperFleet's multi-cloud, adapter-driven architecture.

**Scope**:
- **M1 (MVP)**: Cloud-agnostic pull secret generation for Quay.io and Red Hat registries
- **M2**: Introduces credential rotation and reconciler support, credential pool management, ban/unban operations, and end-to-end lifecycle management
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
    Username            string    // External registry account name (e.g., hyperfleet_{provider}_{region}_{uuid} for Quay, hyp-{cluster-id} for RHIT)
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
| `Username` | Could reference RHIT user account in some contexts | **Technical identifier** of the credential created in external registry (e.g., `hyperfleet_gcp_us-east1_abc123`, `hyp-cls-abc-123`). **Never** contains Red Hat IT user information. Includes cloud provider and region for better traceability. |
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

**Logic to Adopt**:
1. Acquire advisory lock on `(clusterID, externalResourceID)` to prevent race conditions
2. Iterate through all registered registries
3. For each registry, check if credentials exist for cluster
4. If not found, create new credential
5. Format credentials as Docker auth config JSON
6. Return formatted pull secret

**Cloud-Agnostic Pattern**:
```go
import (
    "gitlab.cee.redhat.com/service/hyperfleet/pull-secret-service/pkg/api/registries"
)

func (s *AccessTokenService) GeneratePullSecret(ctx context.Context, clusterID string) (*DockerAuthConfig, error) {
    // 1. Acquire advisory lock
    lock := s.db.AcquireAdvisoryLock(ctx, clusterID)
    defer lock.Release()

    // 2. Fetch or create credentials for all registries
    credentials := []RegistryCredential{}
    for _, registry := range registries.All() {
        cred, err := s.credentialService.FindOrCreate(ctx, clusterID, registry.ID)
        if err != nil {
            return nil, err
        }
        credentials = append(credentials, cred)
    }

    // 3. Format as Docker auth config
    authConfig := s.formatDockerAuthConfig(credentials)
    return authConfig, nil
}
```

#### 3.1.3 Registry Integrations

**Quay Robot Users** (`pkg/client/quay/robot_users.go`):

**HyperFleet Pattern (Adapted from AMS `uhc-account-manager/pkg/client/quay/robot_users.go:99`)**:

```go
package quay

import (
    "fmt"
    "regexp"
    "strings"

    "github.com/google/uuid"
)

const (
    UsernameRegex              = "^[a-z0-9_]{1,254}$"
    UnacceptableCharsRegex     = "[^a-z0-9_]"
    FirstCharRegex             = "^[a-z0-9].*"
    ConsecutiveUnderscoreRegex = "__+"
    robotUserDescription       = "Created by HyperFleet Pull Secret Service"
    RobotUserPrefix            = "hyperfleet"
)

type RobotUser struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Token       string `json:"token"`
}

type RobotUserRequest struct {
    Description string `json:"description"`
}

// QuayUsername generates a Quay-compliant username with cloud context
// Returns: "hyperfleet_{provider}_{region}_{uuid}" (e.g., "hyperfleet_gcp_useast1_a1b2c3d4")
func QuayUsername(provider, region string) (string, error) {
    usernameRe := regexp.MustCompile(UsernameRegex)
    badCharsRe := regexp.MustCompile(UnacceptableCharsRegex)
    firstCharRe := regexp.MustCompile(FirstCharRegex)
    consecutiveUnderscoreRe := regexp.MustCompile(ConsecutiveUnderscoreRegex)

    // Normalize region (remove hyphens, dots - Quay only allows underscores)
    normalizedRegion := NormalizeRegion(region)

    // Generate UUID suffix (first 16 chars without hyphens)
    uuidSuffix := strings.ReplaceAll(uuid.New().String(), "-", "")[:16]

    // Generate username: hyperfleet_{provider}_{region}_{uuid}
    var username = fmt.Sprintf("%s_%s_%s_%s", RobotUserPrefix, provider, normalizedRegion, uuidSuffix)
    username = strings.ToLower(username)

    // Remove unacceptable characters (safety check)
    username = badCharsRe.ReplaceAllLiteralString(username, "")

    // Ensure first character is acceptable for Quay
    if !firstCharRe.MatchString(username) {
        username = "0" + username[1:]
    }

    // Remove consecutive underscores (not allowed by Quay)
    if consecutiveUnderscoreRe.MatchString(username) {
        username = consecutiveUnderscoreRe.ReplaceAllLiteralString(username, "_")
    }

    // Validate final username
    var err error
    matched := usernameRe.MatchString(username)
    if !matched {
        err = fmt.Errorf("Generated quay username %s does not meet regex requirements", username)
    }

    return username, err
}

// NormalizeRegion normalizes region names for Quay compliance
// Replaces hyphens and dots with underscores (Quay regex: ^[a-z0-9_]{1,254}$)
func NormalizeRegion(region string) string {
    // us-east-1 -> useast1
    // europe-west1-a -> europewest1a
    normalized := strings.ReplaceAll(region, "-", "")
    normalized = strings.ReplaceAll(normalized, ".", "")
    return normalized
}

// Create creates a robot user in Quay
func (s *RobotUsersService) Create(organization string, provider string, region string) (*RobotUser, error) {
    username, err := QuayUsername(provider, region)
    if err != nil {
        return nil, fmt.Errorf("Could not generate registry username %s", err)
    }

    path := fmt.Sprintf("organization/%s/robots/%s", organization, username)
    robotUserReq := &RobotUserRequest{Description: robotUserDescription}

    req, err := s.client.newRequest("PUT", path, robotUserReq)
    if err != nil {
        return nil, err
    }

    var robotUser RobotUser
    _, err = s.client.do(req, &robotUser)
    if err != nil {
        return nil, err
    }
    return &robotUser, nil
}

// Delete removes a robot user from Quay
func (s *RobotUsersService) Delete(organization string, robotUsername string) (*RobotUser, error) {
    path := fmt.Sprintf("organization/%s/robots/%s", organization, getUsernameFromRobotUserName(robotUsername))

    req, err := s.client.newRequest("DELETE", path, nil)
    if err != nil {
        return nil, err
    }

    var robotUser RobotUser
    _, err = s.client.do(req, &robotUser)
    if err != nil {
        return nil, err
    }
    return &robotUser, nil
}

// getUsernameFromRobotUserName extracts username from full robot name
// Quay returns robot names as "org+username", but API expects just "username"
func getUsernameFromRobotUserName(robotUserName string) string {
    split := strings.Split(robotUserName, "+")
    if len(split) < 2 {
        return ""
    }
    return split[1]
}
```

**Usage in Registry Credential Service** (`pkg/services/registry_credential.go`):

```go
// createExternalQuayCredentials creates a robot account in Quay.io and populates the RegistryCredential object.

func (s *sqlRegistryCredentialService) createExternalQuayCredentials(
    ctx context.Context,
    cred *api.RegistryCredential,
    cluster *api.Cluster,
    registry *api.Registry,
) error {
    // Extract cloud context from cluster
    provider := strings.ToLower(cluster.CloudProvider)  // "gcp", "aws", "azure"
    region := cluster.Region                             // "us-east1", "us-west-2", "eastus"

    // Create robot user in Quay with cloud context
    robotUser, err := s.quayClient.RobotUsers.Create(registry.OrgName, provider, region)
    if err != nil {
        return fmt.Errorf("Unable to create external quay registry credential user account: %s", err)
    }

    // Store credentials
    cred.Username = robotUser.Name  // e.g., "redhat-openshift+hyperfleet_gcp_useast1_a1b2c3d4e5f6"
    cred.Token = robotUser.Token
    cred.RegistryID = registry.ID
    cred.AccountID = &cluster.ID  // In HyperFleet, AccountID stores cluster ID

    // Add robot to team for permissions
    if err := addQuayTeamMember(ctx, s.quayClient, registry, robotUser); err != nil {
        // Clean up robot if team assignment fails
        s.quayClient.RobotUsers.Delete(registry.OrgName, robotUser.Name)
        return err
    }

    return nil
}
```

**Key Implementation Notes**:
- **Naming Pattern**: HyperFleet uses `hyperfleet_{provider}_{region}_{uuid}` (e.g., `hyperfleet_gcp_useast1_a1b2c3d4e5f6`)
  - **Difference from AMS**: AMS uses `ocm_access_{uuid}` without cloud context
  - **Rationale**: Include provider/region for better traceability and audit trails
  - **Components**:
    - `hyperfleet` - Service identifier
    - `{provider}` - Cloud provider (gcp, aws, azure)
    - `{region}` - Normalized region (us-east1 → useast1, removes hyphens/dots)
    - `{uuid}` - First 16 chars of UUID (uniqueness)
- **Quay Username Format**: After creation, Quay returns `{org}+{username}` (e.g., `redhat-openshift+hyperfleet_gcp_useast1_a1b2c3d4`)
- **Organization**: Uses `OrgName` from Registry config (e.g., `redhat-openshift` for HyperFleet)
- **Team Assignment**: Robot accounts assigned to `TeamName` from Registry config (e.g., `hyperfleet-installers`)
- **Auto-create Team**: If team doesn't exist, creates it automatically with "member" role
- **Regex Compliance**: Quay enforces `^[a-z0-9_]{1,254}$` - function normalizes regions and removes hyphens
- **Cloud Context**: Provider and region extracted from cluster metadata at creation time
- **Note**: `OrgName` and `TeamName` from Registry config used in Quay API calls


---


## 8. Pull Secret Rotation Requirements


In general, pull secret rotation is required in the following scenarios:

- The current pull secret is no longer valid or is not functioning correctly.  
- A new pull secret is required due to security policies or incident response.

**Pull Secret Rotation Policy (based on industry best practices):**

- **90 days** – Industry standard  
- **60 days** – Enhanced security for regulated environments (e.g., financial or healthcare sectors)
