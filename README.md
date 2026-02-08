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


## 8. Pull Secret Rotation Requirements

In general, pull secret rotation is required in the following scenarios:

- The current pull secret is no longer valid or is not functioning correctly.  
- A new pull secret is required due to security policies or incident response.

**Pull Secret Rotation Policy (based on industry best practices):**

- **90 days** – Industry standard  
- **60 days** – Enhanced security for regulated environments (e.g., financial or healthcare sectors)
