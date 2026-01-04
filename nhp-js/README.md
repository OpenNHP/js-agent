# @opennhp/agent

OpenNHP JavaScript/TypeScript SDK for zero-trust network authentication.

[![npm version](https://badge.fury.io/js/@opennhp%2Fagent.svg)](https://www.npmjs.com/package/@opennhp/agent)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

This SDK enables JavaScript and TypeScript applications to authenticate with OpenNHP servers using the Network Hiding Protocol. It supports both browser and Node.js environments with automatic transport selection.

### Features

- **Dual Cipher Scheme Support**
  - CURVE25519: Blake2s + AES-256-GCM + X25519 ECDH
  - GMSM: SM3 + SM4-GCM + SM2 ECDH (Chinese National Standards)
- **Multiple Transport Options**
  - UDP (Node.js default)
  - WebRTC DataChannel (Browser default)
  - WebSocket (legacy)
- **Zero Configuration**: Auto-generates keys and selects appropriate transport
- **Full TypeScript Support**: Complete type definitions included

## Installation

```bash
npm install @opennhp/agent
```

## Quick Start

```typescript
import { NHPAgent } from '@opennhp/agent';

// Create and initialize agent
const agent = new NHPAgent({
  cipherScheme: 'curve25519',  // or 'gmsm' for Chinese crypto
  logLevel: 'info'
});

await agent.init();

// Set identity
agent.setIdentity({
  userId: 'user@example.com',
  deviceId: 'device-uuid-here',
  organizationId: 'example.org'
});

// Add server
agent.addServer({
  publicKey: 'base64-encoded-server-public-key',
  host: 'nhp.example.com',
  port: 62206
});

// Knock on resource
const result = await agent.knockResource({
  resourceId: 'my-resource',
  serviceId: 'my-service',
  serverHost: 'nhp.example.com',
  serverPort: 62206
});

if (result.success) {
  console.log('Access granted until:', new Date(result.expiresAt!));
  console.log('Resource hosts:', result.resourceHosts);
} else {
  console.error('Access denied:', result.error);
}

// Cleanup
await agent.close();
```

## API Reference

### NHPAgent

The main class for interacting with NHP servers.

#### Constructor Options

```typescript
interface NHPAgentConfig {
  privateKey?: string;           // Base64-encoded private key (auto-generated if not provided)
  cipherScheme?: CipherScheme;   // 'curve25519' (default) or 'gmsm'
  transport?: TransportType;     // 'udp', 'webrtc', or 'websocket'
  logLevel?: LogLevel;           // 'silent', 'error', 'info', or 'debug'
}
```

#### Methods

| Method | Description |
|--------|-------------|
| `init()` | Initialize the agent (generates keys if needed) |
| `close()` | Close connections and cleanup resources |
| `setIdentity(identity)` | Set user/device identity for knock requests |
| `addServer(config)` | Add an NHP server configuration |
| `removeServer(serverId)` | Remove a server configuration |
| `knockResource(resource)` | Request access to a protected resource |
| `exitResource(resource)` | Release access to a resource |
| `getPublicKey()` | Get the agent's public key (base64) |
| `on(event, handler)` | Register event handler |
| `off(event, handler)` | Remove event handler |

#### Events

| Event | Description |
|-------|-------------|
| `connected` | Transport connected |
| `disconnected` | Transport disconnected |
| `error` | Error occurred |
| `knock` | Knock packet sent |
| `ack` | Acknowledgment received |

### Identity Configuration

```typescript
interface AgentIdentity {
  userId: string;          // User identifier
  deviceId: string;        // Device identifier
  organizationId?: string; // Optional organization
}
```

### Server Configuration

```typescript
interface ServerConfig {
  id?: string;           // Optional unique ID
  publicKey: string;     // Base64-encoded server public key
  host: string;          // Server hostname or IP
  port: number;          // Server port (default: 62206)
  expiresAt?: number;    // Optional expiration timestamp
}
```

### Resource Configuration

```typescript
interface ResourceConfig {
  resourceId: string;    // Resource identifier
  serviceId: string;     // Service/ASP identifier
  serverHost: string;    // Server hostname
  serverPort: number;    // Server port
}
```

### Knock Result

```typescript
interface KnockResult {
  success: boolean;
  accessToken?: string;               // ASP token if provided
  expiresAt?: number;                 // Access expiration (Unix ms)
  resourceHosts?: Record<string, string>; // Service -> host:port mapping
  agentAddress?: string;              // Agent's address as seen by server
  preAccessUrl?: string;              // Pre-access URL (captive portal)
  error?: string;                     // Error message if failed
  errorCode?: number;                 // Error code if failed
}
```

## Cipher Schemes

### CURVE25519 (Default)

Standard cryptographic scheme using:
- **Key Exchange**: X25519 ECDH
- **Hash**: Blake2s-256
- **AEAD**: AES-256-GCM

```typescript
const agent = new NHPAgent({ cipherScheme: 'curve25519' });
```

### GMSM (Chinese National Standards)

Chinese cryptographic standards (GB/T):
- **Key Exchange**: SM2 ECDH (GB/T 32918-2016)
- **Hash**: SM3 (GB/T 32905-2016)
- **AEAD**: SM4-GCM (GB/T 32907-2016)

```typescript
const agent = new NHPAgent({ cipherScheme: 'gmsm' });
```

## Transport Options

### UDP (Node.js)

Default for Node.js environments. Direct UDP communication.

```typescript
const agent = new NHPAgent({ transport: 'udp' });
```

### WebRTC (Browser)

Default for browser environments. Uses WebRTC DataChannel.

```typescript
const agent = new NHPAgent({ transport: 'webrtc' });
```

### WebSocket

Legacy transport option.

```typescript
const agent = new NHPAgent({ transport: 'websocket' });
```

## Advanced Usage

### Using Pre-existing Keys

```typescript
const agent = new NHPAgent({
  privateKey: 'your-base64-encoded-private-key',
  cipherScheme: 'curve25519'
});
```

### Key Generation Utilities

```typescript
import {
  generateX25519KeyPairBase64,
  generateSM2KeyPairBase64
} from '@opennhp/agent';

// Generate X25519 key pair
const x25519Keys = generateX25519KeyPairBase64();
console.log('Private:', x25519Keys.privateKey);
console.log('Public:', x25519Keys.publicKey);

// Generate SM2 key pair
const sm2Keys = generateSM2KeyPairBase64();
console.log('Private:', sm2Keys.privateKey);
console.log('Public:', sm2Keys.publicKey);
```

### Event Handling

```typescript
agent.on('knock', (data) => {
  console.log('Knock sent:', data.packetType);
});

agent.on('ack', (data) => {
  console.log('Server acknowledged:', data);
});

agent.on('error', (err) => {
  console.error('Error:', err);
});
```

### Multiple Servers

```typescript
agent.addServer({
  id: 'primary',
  publicKey: 'primary-server-key',
  host: 'primary.example.com',
  port: 62206
});

agent.addServer({
  id: 'backup',
  publicKey: 'backup-server-key',
  host: 'backup.example.com',
  port: 62206
});
```

## Error Handling

```typescript
try {
  const result = await agent.knockResource(config);

  if (!result.success) {
    switch (result.errorCode) {
      case 1: console.error('Agent not initialized'); break;
      case 2: console.error('Identity not set'); break;
      case 3: console.error('Server not configured'); break;
      case 4: console.error('Unexpected response'); break;
      case 5: console.error('Network error'); break;
      default: console.error(result.error);
    }
  }
} catch (err) {
  console.error('Exception:', err);
}
```

## Browser Usage

```html
<script type="module">
import { NHPAgent } from 'https://unpkg.com/@opennhp/agent/dist/index.js';

const agent = new NHPAgent({
  cipherScheme: 'curve25519',
  transport: 'webrtc'
});

await agent.init();
// ... use agent
</script>
```

## Requirements

- Node.js 18+ (for Node.js usage)
- Modern browser with WebRTC support (for browser usage)

## Related Projects

- [OpenNHP](https://github.com/OpenNHP/opennhp) - Main OpenNHP implementation (Go)
- [OpenNHP Documentation](https://docs.opennhp.org) - Official documentation

## License

Apache 2.0 - See [LICENSE](../LICENSE) for details.
