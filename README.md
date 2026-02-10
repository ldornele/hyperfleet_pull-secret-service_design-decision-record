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
- Partner Code Usage for **HyperFleet Pull Secret Service**. The `partner_code` effectively acts as a tenant ID used by Red Hat IT to organize and isolate credentials for different Red Hat services accessing `registry.redhat.io`. For the MVP, the `partner_code` will be shared between AMS and HyperFleet to avoid delivery delays, since provisioning a new partner code can take several weeks.

---

## Table of Contents

1. [Pull Secret Service Purpose and Responsibilities](#1-pull-secret-service-purpose-and-responsibilities)
2. [AMS Lift-and-Shift Assessment](#2-ams-lift-and-shift-assessment)
3. [Pull Secret Rotation Requirements](#8-pull-secret-rotation-requirements)
4. [Registry Authentication Architecture](#4-registry-authentication-architecture)
5. [API Design](#5-api-design)
6. [Deployment Architecture Decision](#6-deployment-architecture-decision)
7. [Storage Backend](#7-storage-backend)
8. [Security Considerations](#8-security-considerations)
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

#### 2.1.1 Data Model

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

#### 2.1.2 Access Token Service

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

#### 2.1.3 Registry Integrations

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
  - **Decision Drivers**: Include provider/region for better traceability and audit trails
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

**Red Hat Partner Service Accounts** (`pkg/client/rhit/registry.go`):

**HyperFleet Pattern (Adapted from AMS `uhc-account-manager/pkg/client/rhit/registry.go`)**:

Red Hat Registry uses a different system than Quay - the **Red Hat IT Container Registry Authorizer** API. This system uses **Partner Service Accounts** instead of Robot Accounts.

**API Reference**: https://gitlab.corp.redhat.com/it-platform/container-registry-authorizer

```go
package rhit

const (
    hyperfleetAccountDescription = "HyperFleet Pull Secret Service cluster credential"
)

type ITRegistryService interface {
    CreatePartnerServiceAccount(name string) (*PartnerServiceAccount, error)
    GetPartnerServiceAccount(name string) (*PartnerServiceAccount, error)
    UpdatePartnerServiceAccount(name string, recover bool) (*PartnerServiceAccount, error)
    DeletePartnerServiceAccount(name string) error
}

type PartnerServiceAccount struct {
    Name          string      `json:"name"`
    Description   string      `json:"description"`
    PartnerCode   string      `json:"partnerCode"`      // "ocm-service" for HyperFleet
    Created       string      `json:"created"`
    CreatedBy     string      `json:"createdBy"`
    TokenDate     string      `json:"tokenDate"`
    Credentials   Credentials `json:"credentials"`
}

type Credentials struct {
    Username string `json:"username"`   // Format: "|{name}" (pipe prefix added by RHIT)
    Password string `json:"password"`   // JWT token
}

// CreatePartnerServiceAccount creates a service account in Red Hat Registry
func (r *RegistryService) CreatePartnerServiceAccount(name string) (*PartnerServiceAccount, error) {
    // API: POST /partners/{partnerCode}/service-accounts
    urlPath := fmt.Sprintf("partners/%s/service-accounts", api.OCMServicePartnerCode)
    //                                                      └─────────────────────┘
    //                                                      "ocm-service"

    createRequest := CreatePartnerServiceAccountRequest{
        Name:        name,
        Description: hyperfleetAccountDescription,
    }

    req, err := r.client.newRequest("POST", RegistryBase, urlPath, nil, createRequest)
    if err != nil {
        return nil, err
    }

    var partnerServiceAccount PartnerServiceAccount
    _, err = r.client.do(req, &partnerServiceAccount)
    if err != nil {
        return nil, err
    }

    return &partnerServiceAccount, nil
}

// UpdatePartnerServiceAccount recovers a soft-deleted service account
func (r *RegistryService) UpdatePartnerServiceAccount(name string, recover bool) (*PartnerServiceAccount, error) {
    urlPath := fmt.Sprintf("partners/%s/service-accounts/%s", api.OCMServicePartnerCode, name)

    updateRequest := UpdatePartnerServiceAccountRequest{
        Recover: recover,  // true = recover deleted account
    }

    req, err := r.client.newRequest("POST", RegistryBase, urlPath, nil, updateRequest)
    if err != nil {
        return nil, err
    }

    var partnerServiceAccount PartnerServiceAccount
    _, err = r.client.do(req, &partnerServiceAccount)
    if err != nil {
        return nil, err
    }

    return &partnerServiceAccount, nil
}

// DeletePartnerServiceAccount soft-deletes a service account (can be recovered)
func (r *RegistryService) DeletePartnerServiceAccount(name string) error {
    urlPath := fmt.Sprintf("partners/%s/service-accounts/%s", api.OCMServicePartnerCode, name)

    req, err := r.client.newRequest("DELETE", RegistryBase, urlPath, nil, nil)
    if err != nil {
        return err
    }

    var partnerServiceAccount PartnerServiceAccount
    _, err = r.client.do(req, &partnerServiceAccount)
    if err != nil {
        return err
    }

    return nil
}
```

**Usage in Registry Credential Service** (`pkg/services/registry_credential.go`):

```go
// RedHatRegistryAccountName generates account name for Red Hat Registry
// HyperFleet uses "hyp-" prefix (vs AMS "uhc-")
func (s *sqlRegistryCredentialService) RedHatRegistryAccountName(
    cluster *api.Cluster,
    externalResourceID string,
) string {
    var name string

    switch {
    case cluster == nil:
        // Pool credential (unassigned)
        name = fmt.Sprintf("hyp-pool-%s", uuid.New().String())
        // Example: "hyp-pool-a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    case externalResourceID != "":
        // Cluster credential with external resource ID
        // Use short cluster ID to work around RHIT length limit of 49 characters
        name = fmt.Sprintf("hyp-cls-%s", externalResourceID)
        // Example: "hyp-cls-abc123def456"

    default:
        // Cluster credential (default)
        name = fmt.Sprintf("hyp-cls-%s", cluster.ID)
        // Example: "hyp-cls-cls-abc-123"
    }

    return name
}

// createExternalRedhatCredentials creates credentials in Red Hat Registry
// Responsibilities:
//   - Create partner service account in RHIT via API
//   - Populate RegistryCredential object with returned Username (with pipe prefix), Token (JWT)
//   - Handle conflicts (account already exists)
//
// Important:
//   - Username format: "|{name}" (RHIT adds pipe prefix)
//   - Token is JWT, not simple password
//   - Supports soft delete and recovery
//   - Does NOT save to database (parent Create() method handles that)
//
func (s *sqlRegistryCredentialService) createExternalRedhatCredentials(
    ctx context.Context,
    cred *api.RegistryCredential,
    cluster *api.Cluster,
    registry *api.Registry,
) error {

    // Generate service account name
    name := s.RedHatRegistryAccountName(cluster, cred.ExternalResourceId)
    // Example: "hyp-cls-abc123"

    // Create partner service account in RHIT
    acct, err := s.rhitClient.Registry.CreatePartnerServiceAccount(name)
    if err != nil {
        // Handle conflict: account already exists
        if _, ok := err.(rhit.ConflictError); ok {
            // Fetch existing account
            acct, err = s.rhitClient.Registry.GetPartnerServiceAccount(name)
            if err != nil {
                return fmt.Errorf("Unable to get existing Red Hat partner service account: %s", err)
            }
        } else {
            return fmt.Errorf("Unable to create Red Hat partner service account: %s", err)
        }
    }

    // Populate RegistryCredential with credentials from RHIT
    cred.Username = acct.Credentials.Username  // e.g., "|hyp-cls-abc123" (pipe prefix added by RHIT)
    cred.Token = acct.Credentials.Password     // JWT token
    cred.RegistryID = registry.ID              // "Redhat_registry.redhat.io"
    cred.AccountID = &cluster.ID               // In HyperFleet, AccountID stores cluster ID

    return nil
}

// removeExternalRedhatCredentials deletes (soft delete) a service account
func (s *sqlRegistryCredentialService) removeExternalRedhatCredentials(
    ctx context.Context,
    username string,
) error {
    ulog := logger.NewOCMLogger(ctx)

    // Remove pipe prefix from username
    name, err := getRHServiceAccountNameFromUsername(username)
    // "|hyp-cls-abc123" -> "hyp-cls-abc123"
    if err != nil {
        err = fmt.Errorf("Error removing external credentials for Red Hat username %s: Service Account name could not be determined", username)
        ulog.Contextual().Error(err, err.Error())
        return err
    }

    // Delete (soft delete) the service account
    err = s.rhitClient.Registry.DeletePartnerServiceAccount(name)
    if err != nil && err.Error() == "404: Service Account not found" {
        // Already deleted, ignore
        return nil
    } else if err != nil {
        ulog.Contextual().Error(err, "Error removing external credentials for Red Hat username", "username", username, "trimmed name", name)
    }

    return err
}

// recoverDeletedRedhatCredentials recovers a soft-deleted service account
func (s *sqlRegistryCredentialService) recoverDeletedRedhatCredentials(
    ctx context.Context,
    username string,
) error {
    ulog := logger.NewOCMLogger(ctx)

    // Remove pipe prefix from username
    name, err := getRHServiceAccountNameFromUsername(username)
    if err != nil {
        err = fmt.Errorf("Error recovering external credentials for Red Hat username %s: Service Account name could not be determined", username)
        ulog.Contextual().Error(err, err.Error())
        return err
    }

    // Recover the service account (soft delete reversal)
    _, err = s.rhitClient.Registry.UpdatePartnerServiceAccount(name, true)
    //                                                           └────┘
    //                                                           recover=true
    if err != nil && err.Error() == "404: Service Account not found" {
        // Account doesn't exist, nothing to recover
        return nil
    } else if err != nil {
        ulog.Contextual().Error(err, "Error recovering external credentials for Red Hat username", "username", username, "trimmed name", name)
    }

    return err
}

// getRHServiceAccountNameFromUsername removes pipe prefix from RHIT username
func getRHServiceAccountNameFromUsername(username string) (string, error) {
    // RHIT prepends all partner service accounts with a "|" character
    // This prefix needs to be removed prior to API calls
    substrings := strings.SplitN(username, "|", 2)
    if len(substrings) < 2 {
        return "", fmt.Errorf("RH Service Account Username %s does not match known format", username)
    }
    return substrings[1], nil
}
```

**Key Implementation Notes**:
- **Naming Pattern**: HyperFleet uses `hyp-cls-{cluster_id}` (vs AMS `uhc-{account_id}`)
  - **Example**: `hyp-cls-abc123def456`
  - **Decision Drivers**: Shorter than including provider/region (RHIT has 49 char limit)
  - **Traceability**: Cluster ID is sufficient for audit trails
- **Username Format**: RHIT returns `|{name}` (pipe prefix added by system)
  - **Example**: Request name `hyp-cls-abc123`, receive username `|hyp-cls-abc123`
- **Token Format**: JWT token (not simple password like Quay)
- **Partner Code**: `ocm-service` (shared between AMS and HyperFleet)
  - **Decision Drivers**: Time to market, operational simplicity, reuse of client certificates and keys for RHIT API authentication.
  - **Post-MVP**: Adopt a dedicated partner code as HyperFleet scales significantly (e.g., to thousands of clusters).
- **Soft Delete**: Deleted accounts can be recovered via `UpdatePartnerServiceAccount(name, recover=true)`
- **Length Limit**: **49 characters maximum** (RHIT limitation)
- **No Team Assignment**: Red Hat Registry doesn't use teams (unlike Quay)
- **API Endpoint**: `https://container-registry-authorizer.api.redhat.com/v1/partners/ocm-service/service-accounts`
- **Credential Reuse**: Multiple Red Hat registries (`registry.redhat.io`, `registry.connect.redhat.com`) share same credentials

#### 2.1.4 Credential Pool Management (Milestone 2)

**File**: `cmd/account-manager/jobs/registry_credential_pool_loader.go`

**Logic to Adopt**:
1. Maintain pool of unassigned credentials (`AccountID IS NULL`)
2. High-water mark threshold (e.g., 100 credentials per registry)
3. Low-water mark alerts (e.g., <25 credentials)
4. Batch creation jobs (configurable cardinality)
5. Periodic reconciliation (e.g., every 5 minutes)

**Benefits**:
- **Performance**: Credentials available immediately (no registry API call on critical path)
- **Resilience**: Pool absorbs temporary registry API outages
- **Scalability**: Pre-generation parallelized, not blocking cluster creation

**HyperFleet Pool Strategy with Cloud Context Naming**:

Since robot account names include `{provider}_{region}`, there are two approaches:

**Option A: On-Demand Generation (Recommended for MVP)**
- Generate credentials **when cluster is created** (not pre-generated)
- Username includes actual cluster's provider/region at creation time
- **Pros**: No renaming logic, simpler implementation, accurate cloud context
- **Cons**: Adds ~2-3 seconds to cluster creation (Quay API call on critical path)
- **Fallback**: If Quay API fails, return error and retry (no pool to fall back to)

**Option B: Pre-Generated Pool with Placeholder Regions**
- Pre-generate pool with generic provider/region (e.g., `hyperfleet_multi_global_{uuid}`)
- Rename robot account via Quay API when assigning to cluster
- **Pros**: Fast assignment, resilient to Quay API outages
- **Cons**: Requires Quay robot renaming API (if available), added complexity
- **Challenge**: Quay may not support renaming robot accounts (needs verification)

**Recommendation**: Start with **Option A** (on-demand) for MVP. Add pool (Option B) in M2 if:
1. Quay API latency becomes bottleneck (>5 seconds p99)
2. Quay robot renaming API is available and tested
3. Operational complexity is acceptable

#### 2.1.5 Rotation Reconciler (Milestone 2)

**File**: `cmd/account-manager/jobs/pull_secret_rotations_reconciler.go`

**Logic to Adopt**:
1. Query pending `PullSecretRotation` records
2. Create new `RegistryCredential` records for all registries (new robot accounts in Quay/RHIT)
3. **Dual credential period begins**: Both old and new credentials exist in database for same cluster
4. Format pull secret with new credentials and notify cluster
5. Wait for cluster to update (health check via API or grace period, e.g., 7 days)
6. Delete old `RegistryCredential` records from database
7. Delete old robot accounts from external registries (Quay/RHIT)
8. Mark `PullSecretRotation` status as `completed`

**Key Pattern**: **Dual credential period** ensures zero-downtime rotation:
- New credentials created without deleting old ones
- Both old and new `RegistryCredential` records coexist for same cluster
- Cluster can use either old or new credentials during transition
- Old credentials only deleted after confirmation cluster has updated
- **Implementation**: Query for credentials by `(cluster_id, registry_id)` returns multiple records; use most recent based on `CreatedAt`

### 2.2 Components to Adapt

#### 2.2.1 Authentication and Authorization

**AMS Approach**:
- OCM JWT tokens

**HyperFleet Adaptation**:
- Service-to-service authentication via Kubernetes ServiceAccount tokens

#### 2.2.2 Database Schema

**AMS Approach**:
- PostgreSQL with GORM ORM
- Advisory locks for concurrency control
- Indexes on `(account_id)`, `(registry_id)`, `(account_id, external_resource_id)`

**HyperFleet Adaptation**:
- Reuse PostgreSQL schema (semantic mapping: `account_id` column stores `cluster_id` in HyperFleet)
- Column name `account_id` is kept for code reuse (AMS lift-and-shift)
- If using per-instance deployment, consider adding `hyperfleet_instance_id` column for cross-instance queries
- Add composite index on `(hyperfleet_instance_id, account_id)` if multi-instance tracking is needed

#### 2.2.3 API Endpoints

**AMS Approach**:
- REST endpoints: `POST /access_token`, `DELETE /access_token/{id}`
- Pull secret rotation endpoints under `/accounts/{id}/pull_secret_rotation`

**HyperFleet Adaptation**:
- Align with HyperFleet REST patterns: `/clusters/{id}/pull-secrets`
- Use CloudEvents for async rotation triggers (not direct HTTP calls)
- Status reporting via `/clusters/{id}/statuses` (adapter pattern)

### 2.3 Components to Replace

#### 2.3.1 Export Control Checks and User Screening

**AMS Logic**: Account screening middleware checks for export control restrictions based on Red Hat IT user information (user email, organization, geographic location)

**HyperFleet Replacement**: Not applicable - **HyperFleet Pull Secret Service does not require Red Hat IT user information for screening**

**Key Architectural Difference**:

The Pull Secret Service operates with **effectively anonymous credential fetching**, relying on **cloud provider identification** rather than user identity:

1. **No User Context Required**:
   - AMS model: User-centric (requires RHIT user email, account ID, organization hierarchy)
   - HyperFleet model: Cluster-centric (uses cluster ID, cloud provider ServiceAccount/IAM identity)

2. **Authentication Flow**:
   - Service-to-service authentication via **Kubernetes ServiceAccount tokens**
   - Cloud provider authentication via **Workload Identity** (GCP), **IAM Roles** (AWS), or **Managed Identity** (Azure)
   - No user credentials or personal information involved in the pull secret generation flow

3. **Credential Naming Convention**:

   **Quay Robot Accounts**: `hyperfleet_{provider}_{region}_{uuid}` (includes cloud context)
   - **Example**: `hyperfleet_gcp_useast1_a1b2c3d4e5f6`
   - **Format**: `hyperfleet_{provider}_{normalized_region}_{uuid_16_chars}`
   - **Decision Drivers**: Include cloud context for traceability and audit trails
   - **Components**:
     - `hyperfleet`: Service identifier (distinguishes from AMS `ocm_access_` prefix)
     - `{provider}`: Cloud provider (lowercase: `gcp`, `aws`, `azure`)
     - `{region}`: Normalized region (hyphens/dots removed: `useast1`, `uswest2`, `eastus`)
     - `{uuid}`: Auto-generated unique identifier (first 16 chars of UUID v4, no hyphens)

   **Benefits of New Naming Pattern**:
   - ✅ Clear service attribution (HyperFleet vs AMS credentials)
   - ✅ Audit trail includes deployment context (which cloud, which region)
   - ✅ Troubleshooting: easily identify credentials by environment
   - ✅ Cost tracking: can map credentials to specific cloud deployments
   - ✅ Security: credentials can be filtered/revoked by provider/region in incident response

   **Red Hat Partner Service Accounts**: `hyp-cls-{cluster-id}` (cluster-scoped, not user-scoped)
   - **Example**: `hyp-cls-abc123` (returned as `|hyp-cls-abc123` by RHIT with pipe prefix)
   - **Decision Drivers**: Shorter than provider/region pattern (RHIT has 49 char limit)
   - **Format**: HyperFleet uses `hyp-` prefix (vs AMS `uhc-`) for differentiation

4. **Export Control Handling**:
   - HyperFleet assumes export control is handled at **organization/subscription level** during onboarding
   - Credential generation does not re-evaluate export control per cluster creation
   - Post-MVP consideration: Organization-level policy enforcement if needed

**Decision Drivers**: This design simplifies compliance by moving screening upstream (organization onboarding) and enables fully automated, cloud-native credential management without human-in-the-loop identity verification.

#### 2.3.2 Ban/Unban Operations (Milestone 2)

**AMS Logic**: Bans remove credentials from registries, moves Quay robots to "banned" team

**HyperFleet Adaptation**: Simplify to "suspend" (delete external credentials but keep DB record) and "resume" (recreate credentials)

### 3.4 Key Files Reference from AMS

**Core Services** (lift-and-shift with adaptations):
- `/pkg/services/access_token.go` - Pull secret generation logic
- `/pkg/services/registry_credential.go` - Credential CRUD and pool management
- `/pkg/services/pull_secret_rotation.go` - Rotation orchestration
- `/pkg/services/registry.go` - Registry abstraction layer

**External Clients** (reuse as-is):
- `/pkg/client/quay/robot_users.go` - Quay integration
- `/pkg/client/rhit/registry.go` - Red Hat registry integration

**Jobs** (adapt to HyperFleet job framework):
- `/cmd/account-manager/jobs/registry_credential_pool_loader.go`
- `/cmd/account-manager/jobs/pull_secret_rotations_reconciler.go`

**Documentation** (adapt for HyperFleet):
- `/docs/pull_secret_rotation.md`
- `/docs/pull_secret_auto_rotation.md`

---


## 3. Pull Secret Rotation Requirements


In general, pull secret rotation is required in the following scenarios:

- The current pull secret is no longer valid or is not functioning correctly.  
- A new pull secret is required due to security policies or incident response.

**Pull Secret Rotation Policy (based on industry best practices):**

- **90 days** – Industry standard  
- **60 days** – Enhanced security for regulated environments (e.g., financial or healthcare sectors)

---

## 4. Registry Authentication Architecture

This section documents the authentication mechanisms used by HyperFleet (and AMS) to interact with container registries, highlighting the key differences between Quay.io and Red Hat IT Registry (RHIT).

### 4.1 Authentication Layers Overview

HyperFleet interacts with two types of container registries, each with different authentication architectures:

| Registry | Authentication Layers | Service Auth Type | Cluster Auth Type |
|----------|----------------------|-------------------|-------------------|
| **Quay.io** | **1 layer** | Bearer Token | Robot Account Token |
| **Red Hat IT** | **2 layers** | mTLS (Client Cert/Key) | JWT Token |

### 4.2 Quay.io Authentication (Single Layer)

**Architecture**: Simple bearer token authentication for both service operations and robot account management.

#### 4.2.1 Service Authentication

HyperFleet authenticates to Quay.io API using a single **bearer token**:

```go
// pkg/client/quay/client.go
type Client struct {
    httpClient *http.Client
    authToken  string  // ← Single authentication credential
}

func (c *Client) newRequest(method string, path string, body interface{}) (*http.Request, error) {
    req, err := http.NewRequest(method, u.String(), buf)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.authToken))
    return req, nil
}
```

**Configuration**:

```yaml
# config/hyperfleet.yaml
quay:
  auth_token_file: "secrets/quay.token"  # ← Single secret file
  timeout: 5s
```

**API Request Example**:

```bash
PUT https://quay.io/api/v1/organization/redhat-openshift/robots/hyperfleet_gcp_useast1_abc123
Authorization: Bearer gcMDcAbpV0nI32FPQEYPABgaUCudVbCKl1sYL9mY
Content-Type: application/json

{
  "description": "Created by HyperFleet Pull Secret Service"
}
```

**Response** (Robot Account Credentials):

```json
{
  "name": "redhat-openshift+hyperfleet_gcp_useast1_abc123",
  "token": "ROBOT_TOKEN_XYZ",
  "description": "Created by HyperFleet Pull Secret Service"
}
```

#### 4.2.2 Namespace Model

Quay.io uses **organizations** as the namespace mechanism:

```
Organization: redhat-openshift
├── Robot Account: hyperfleet_gcp_useast1_abc123
├── Robot Account: hyperfleet_aws_uswest2_def456
└── Robot Account: hyperfleet_azure_eastus_ghi789

Full username format: {org}+{robot_username}
Example: redhat-openshift+hyperfleet_gcp_useast1_abc123
```

**Key Characteristics**:
- ✅ Single token authenticates service for ALL operations
- ✅ Organization determines namespace
- ✅ No certificate management required
- ✅ Simple HTTP bearer token authentication

---

### 4.3 Red Hat IT Registry Authentication (Dual Layer)

**Architecture**: Mutual TLS (mTLS) for service authentication, JWT tokens for cluster authentication.

#### 4.3.1 Layer 1: Service Authentication (mTLS)

HyperFleet authenticates to RHIT API using **client certificates**:

```go
// pkg/client/rhit/client.go
type Client struct {
    httpClient *http.Client  // ← Configured with mTLS
}

func NewClient(ctx context.Context, config *ClientConfiguration) (*Client, error) {
    // Load client certificate and key
    clientCert, err := tls.X509KeyPair([]byte(config.ClientCrt), []byte(config.ClientKey))

    // Configure TLS with client authentication
    tlsConfig := tls.Config{
        RootCAs:      rootCAs,
        Certificates: []tls.Certificate{clientCert},  // ← Client cert for auth
    }

    httpClient := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tlsConfig,
        },
    }
    return client, nil
}
```

**Configuration**:

```yaml
# config/hyperfleet.yaml
rhit:
  partner_code: "ocm-service"  # ← Namespace identifier
  base_registry_url: "https://container-registry-authorizer.redhat.com/v1/"
  client_crt_path: "secrets/rhsm.crt"    # ← Client certificate
  client_key_path: "secrets/rhsm.key"    # ← Private key
  root_ca_path:
    - "secrets/rhsm-2015.ca"
    - "secrets/rhsm-2022.ca"
  timeout: 5s
```

**Required Secrets** (3 files):

| File | Purpose | Shared with AMS? |
|------|---------|------------------|
| `rhsm.crt` | Client certificate | ✅ Yes (if using `ocm-service`) |
| `rhsm.key` | Private key | ✅ Yes (if using `ocm-service`) |
| `rhsm-*.ca` | Root CA certificates | ✅ Yes |

#### 4.3.2 Layer 2: Partner Service Account Credentials (JWT)

After authenticating via mTLS, HyperFleet creates Partner Service Accounts that receive **JWT tokens**:

**API Request Example**:

```bash
POST https://container-registry-authorizer.redhat.com/v1/partners/ocm-service/service-accounts
Client-Certificate: [rhsm.crt]  # ← mTLS authentication
Client-Key: [rhsm.key]          # ← mTLS authentication
Content-Type: application/json

{
  "name": "hyp-cls-abc123",
  "description": "HyperFleet cluster pull secret"
}
```

**Response** (Service Account with JWT):

```json
{
  "name": "hyp-cls-abc123",
  "partnerCode": "ocm-service",
  "created": "2026-02-08T10:00:00Z",
  "credentials": {
    "username": "|hyp-cls-abc123",  // ← Pipe prefix added by RHIT
    "password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  // ← JWT token
  }
}
```

#### 4.3.3 Partner Code Namespace Model

RHIT uses **partner codes** as the namespace mechanism:

```
Partner Code: ocm-service (shared between AMS and HyperFleet)
├── AMS Service Accounts:
│   ├── |uhc-cls-xyz789  (AMS cluster)
│   └── |uhc-pool-abc123 (AMS pool)
│
└── HyperFleet Service Accounts:
    ├── |hyp-cls-abc123  (HyperFleet cluster)
    └── |hyp-pool-def456 (HyperFleet pool)

Username format: |{name}
Example: |hyp-cls-abc123
```

**Namespace Isolation**:
- Prefixes (`uhc-` vs `hyp-`) prevent name collisions
- Partner code (`ocm-service`) shared between AMS and HyperFleet
- Same client certificates used by both services

**Key Characteristics**:
- ✅ mTLS provides strong authentication
- ✅ Partner code enables namespace sharing
- ✅ JWT tokens have automatic expiration/rotation capabilities
- ❌ Requires certificate management and renewal
- ❌ More complex configuration (3+ secret files)

---

### 4.4 Comparative Analysis

#### 4.4.1 Service Authentication Comparison

| Aspect | **Quay.io** | **Red Hat IT** |
|--------|-------------|----------------|
| **Method** | HTTP Bearer Token | Mutual TLS (mTLS) |
| **Secrets Required** | 1 file (`quay.token`) | 3+ files (`rhsm.crt`, `rhsm.key`, CAs) |
| **Certificate Management** | ❌ Not required | ✅ Required (renewal, rotation) |
| **Security Level** | Medium (token-based) | High (certificate-based) |
| **Complexity** | Low | Medium-High |
| **Shared with AMS** | ❌ No | ✅ Yes (if using `ocm-service`) |

#### 4.4.2 Robot/Service Account Comparison

| Aspect | **Quay.io** | **Red Hat IT** |
|--------|-------------|----------------|
| **Account Type** | Robot Account | Partner Service Account |
| **Token Type** | String token | JWT token |
| **Username Format** | `{org}+{robot_username}` | `\|{name}` |
| **Username Example** | `redhat-openshift+hyperfleet_gcp_useast1_abc123` | `\|hyp-cls-abc123` |
| **Naming Convention** | `hyperfleet_{provider}_{region}_{uuid}` | `hyp-cls-{cluster_id}` |
| **Max Length** | 254 characters | 49 characters |
| **Namespace** | Organization | Partner Code |
| **Soft Delete** | ❌ No | ✅ Yes (recoverable) |
| **Team Assignment** | ✅ Yes | ❌ No |

#### 4.4.3 Pull Secret Format Comparison

**Quay.io Pull Secret**:

```yaml
{
  "auths": {
    "quay.io": {
      "auth": "cmVkaGF0LW9wZW5zaGlmdCtoeXBlcmZsZWV0X2djcF91c2Vhc3QxX2FiYzEyMzpST0JPVF9UT0tFTl9YWVo="
    }
  }
}

# Decoded: redhat-openshift+hyperfleet_gcp_useast1_abc123:ROBOT_TOKEN_XYZ
# Format: {org}+{robot_username}:{token}
```

**RHIT Pull Secret**:

```yaml
{
  "auths": {
    "registry.redhat.io": {
      "auth": "fGh5cC1jbHMtYWJjMTIzOmV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS4uLg=="
    }
  }
}

# Decoded: |hyp-cls-abc123:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# Format: |{name}:{jwt_token}
```

---

### 4.5 HyperFleet Configuration Requirements

#### 4.5.1 Secrets Management

**For Quay.io**:

```bash
# Single secret file
secrets/quay.token
```

**For RHIT**:

```bash
# Three secret files (shared with AMS if using ocm-service partner code)
secrets/rhsm.crt        # Client certificate
secrets/rhsm.key        # Private key
secrets/rhsm-2015.ca    # Root CA (older)
secrets/rhsm-2022.ca    # Root CA (current)
```

#### 4.5.2 Partner Code Decision

**Option 1: Share `ocm-service` with AMS (Recommended for MVP)**

✅ **Advantages**:
- Immediate availability (no Red Hat IT approval process)
- Reuse existing certificates
- Proven infrastructure

❌ **Disadvantages**:
- Shared namespace with AMS
- Certificate rotation must be coordinated
- Failure blast radius affects both services

**Option 2: Request Dedicated `hyperfleet-service` Partner Code**

✅ **Advantages**:
- Isolated namespace
- Independent certificate management
- Clear separation from AMS

❌ **Disadvantages**:
- Requires Red Hat IT ticket/approval (days/weeks)
- Separate certificate management overhead
- Additional operational complexity

**Recommendation**: Use `ocm-service` for MVP, consider migration to dedicated partner code post-MVP if operational requirements warrant isolation.

#### 4.5.3 Implementation Checklist

**Quay.io Setup**:
- [ ] Obtain Quay.io bearer token for `redhat-openshift` organization
- [ ] Store token in `secrets/quay.token`
- [ ] Configure `quay.auth_token_file` in HyperFleet config
- [ ] Verify API access with test robot account creation

**RHIT Setup**:
- [ ] Obtain `rhsm.crt`, `rhsm.key`, and CA certificates from AMS team
- [ ] Store certificates in HyperFleet secrets directory
- [ ] Configure `rhit.partner_code: "ocm-service"` in HyperFleet config
- [ ] Configure certificate paths in HyperFleet config
- [ ] Verify API access with test service account creation
- [ ] Coordinate certificate rotation schedule with AMS team

---

### 4.6 Key Takeaways

1. **Quay.io**: Simple bearer token authentication, single layer, no certificate management
2. **RHIT**: Dual-layer authentication (mTLS + JWT), more secure but more complex
3. **Shared Infrastructure**: RHIT uses `ocm-service` partner code shared with AMS
4. **Different Credentials**: Despite sharing partner code, each service account receives unique JWT tokens
5. **Naming Conventions**: Different patterns for Quay (`hyperfleet_{provider}_{region}_{uuid}`) vs RHIT (`hyp-cls-{id}`)


### 4.7 Network Connectivity Test

✅ **Connectivity from RHIT over the public internet verified**

```bash
[root]$ nc -zv container-registry-authorizer.api.redhat.com 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 23.65.139.246:443.
Ncat: 0 bytes sent, 0 bytes received in 0.12 seconds.
```
✅ **Connectivity to Quay.io (Public SaaS) over the public internet verified**

```bash
[root]$ nc -zv quay.io 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 2600:1f18:d77:9002:6c26:2939:9ddb:3526:443.
Ncat: 0 bytes sent, 0 bytes received in 0.22 seconds.
```


---

## 5. API Design

### 5.1 API Endpoints

#### 5.1.1 Generate Pull Secret (Synchronous)

**Endpoint**: `POST /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets`

**Description**: Generate or retrieve pull secret for a cluster. Returns existing credentials if valid, creates new credentials if none exist.

**Request**:
```json
{
  "registries": ["quay", "redhat"],  // Optional: defaults to all registries
  "force_new": false  // Optional: force new credential creation
}
```

**Response** (200 OK):
```json
{
  "id": "ps-abc-123",
  "cluster_id": "cls-abc-123",
  "pull_secret": {
    "auths": {
      "quay.io": {
        "auth": "aHlwZXJmbGVldF9nY3BfdXMtZWFzdDFfYWJjMTIzZGVmNDU2OnRva2VuXzQ1Ng==",
        "email": "hyperfleet@redhat.com"
      },
      "cloud.openshift.com": {
        "auth": "aHlwZXJmbGVldF9nY3BfdXMtZWFzdDFfYWJjMTIzZGVmNDU2OnRva2VuXzQ1Ng==",
        "email": "hyperfleet@redhat.com"
      },
      "registry.redhat.io": {
        "auth": "dWhjLWNscy1hYmMtMTIzOnRva2VuXzc4OQ==",
        "email": "hyperfleet@redhat.com"
      }
    }
  },
  "credentials": [
    {
      "registry_id": "quay",
      "username": "redhat-openshift+hyperfleet_gcp_useast1_a1b2c3d4e5f6",
      "created_at": "2025-10-21T14:30:00Z",
      "expires_at": "2026-01-19T14:30:00Z"
    },
    {
      "registry_id": "redhat",
      "username": "|hyp-cls-abc123",
      "created_at": "2025-10-21T14:30:00Z",
      "expires_at": null
    }
  ],
  "created_at": "2025-10-21T14:30:00Z",
  "updated_at": "2025-10-21T14:30:00Z"
}
```

**Note on Docker Auth Format**:
The `auth` field contains base64-encoded `username:token` credentials:
- Quay: `base64("redhat-openshift+hyperfleet_gcp_useast1_a1b2c3d4:token_456")` (format: `{org}+{robot_username}:token`)
- RHIT: `base64("|hyp-cls-abc123:jwt_token_789")` (format: `|{name}:jwt_token`, pipe prefix added by RHIT)

**Errors**:
- `400 HYPERFLEET-8`: Invalid registry specified
- `404 HYPERFLEET-7`: Cluster not found
- `429 HYPERFLEET-3`: Rate limit exceeded
- `500 HYPERFLEET-9`: Internal server error
- `502 HYPERFLEET-16`: Registry API unavailable (falls back to pool)

**Idempotency**: Multiple calls return the same credentials unless `force_new=true`

#### 5.1.2 Get Pull Secret (Retrieve Existing)

**Endpoint**: `GET /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets`

**Description**: Retrieve existing pull secret for a cluster. Returns 404 if no credentials exist.

**Response** (200 OK):
```json
{
  "id": "ps-abc-123",
  "cluster_id": "cls-abc-123",
  "pull_secret": { ... },
  "credentials": [ ... ],
  "created_at": "2025-10-21T14:30:00Z",
  "updated_at": "2025-10-21T14:30:00Z"
}
```

**Errors**:
- `404 HYPERFLEET-7`: Pull secret not found for cluster

#### 5.1.3 Delete Pull Secret

**Endpoint**: `DELETE /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets`

**Description**: Delete pull secret and revoke credentials from all registries. Used when cluster is deleted or credentials are compromised.

**Response** (204 No Content)

**Errors**:
- `404 HYPERFLEET-7`: Cluster not found
- `500 HYPERFLEET-9`: Failed to revoke credentials from registry

**Side Effects**:
- Deletes robot accounts from Quay
- Deletes partner service accounts from Red Hat Registry
- Removes credentials from database
- Logs security event for audit

#### 5.1.4 Rotate Pull Secret (Async)

**Endpoint**: `POST /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets/rotations`

**Description**: Initiate pull secret rotation for a cluster. Returns rotation request ID. Actual rotation happens asynchronously via reconciler job.

**Request**:
```json
{
  "reason": "scheduled",  // "scheduled" | "compromise" | "manual"
  "force_immediate": false  // Skip dual-credential period (emergency only)
}
```

**Response** (202 Accepted):
```json
{
  "id": "psr-abc-123",
  "cluster_id": "cls-abc-123",
  "status": "pending",
  "reason": "scheduled",
  "created_at": "2025-10-21T14:30:00Z",
  "estimated_completion": "2025-10-21T14:35:00Z"
}
```

**Errors**:
- `404 HYPERFLEET-7`: Cluster not found
- `409 HYPERFLEET-6`: Rotation already in progress for cluster

#### 5.1.5 Get Rotation Status

**Endpoint**: `GET /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets/rotations/{rotation_id}`

**Response** (200 OK):
```json
{
  "id": "psr-abc-123",
  "cluster_id": "cls-abc-123",
  "status": "completed",
  "reason": "scheduled",
  "old_credentials": [ ... ],
  "new_credentials": [ ... ],
  "created_at": "2025-10-21T14:30:00Z",
  "completed_at": "2025-10-21T14:32:00Z"
}
```

**Status Values**:
- `pending`: Rotation request created, waiting for reconciler
- `in_progress`: New credentials created, waiting for cluster update
- `completed`: Rotation complete, old credentials deleted
- `failed`: Rotation failed (manual intervention required)

#### 5.1.6 List Rotations for Cluster

**Endpoint**: `GET /api/hyperfleet/v1/clusters/{cluster_id}/pull-secrets/rotations`

**Query Parameters**:
- `status`: Filter by status (pending, in_progress, completed, failed)
- `page`: Page number (default: 1)
- `size`: Page size (default: 20, max: 100)

**Response** (200 OK):
```json
{
  "items": [ ... ],
  "page": 1,
  "size": 20,
  "total": 42
}
```

### 5.2 Authentication and Authorization

#### 5.2.1 Authentication

**Method**: Service-to-service authentication via Kubernetes ServiceAccount tokens

**Flow**:
1. Pull Secret Adapter calls API with ServiceAccount token in `Authorization: Bearer {token}` header
2. API validates token signature against Kubernetes API
3. Extracts ServiceAccount identity (namespace + name)
4. Checks ServiceAccount has appropriate RBAC permissions

**Important**: This authentication model is **effectively anonymous** from a Red Hat IT user perspective. The service relies on **cloud provider identification** (Kubernetes ServiceAccount → Cloud IAM identity) rather than user credentials. No Red Hat IT user information is required for credential generation or export control screening.

**RBAC Permissions**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: hyperfleet-pull-secret-service
rules:
  - apiGroups: ["hyperfleet.redhat.com"]
    resources: ["clusters", "clusters/pull-secrets"]
    verbs: ["get", "create", "delete"]
  - apiGroups: ["hyperfleet.redhat.com"]
    resources: ["clusters/statuses"]
    verbs: ["create", "update"]
```

---

## 6. Deployment Architecture Decision

### 6.1 Options Analysis

#### Option A: Per-HyperFleet Instance Deployment (MVP)

- TBD

#### Option B: Global Shared Service

- TBD

---

## 7. Storage Backend

- TBD

---

## 8. Security Considerations

- TBD
  
- How to retrieve the pull secret from the vault in the Regional Cluster. We discussed possibles approaches:
    - Via the Maestro API — not recommended due to security concerns around transporting sensitive data. 
    - Using External Secrets Operator in the Management Cluster to pull from GCP Secret Manager in the Regional Cluster — also not recommended from a security standpoint, since a single Management Cluster could potentially access pull secrets across multiple MCs within Regional Cluster.
    - Running a Job in the Regional Cluster that stores the pull secret in GCP Secret Manager hosted in the Management Cluster — this appears to be the preferred approach from a security perspective. However, it introduces pull secret duplication across clusters. This could make pull secret rotation significantly more complex, especially when secrets are spread across multiple vaults (RC and MC).
    - MC consumes the Pull Secret Service endpoint (e.g., /v1/registry_credentials/{cluster_id}) to retrieve its credentials.
