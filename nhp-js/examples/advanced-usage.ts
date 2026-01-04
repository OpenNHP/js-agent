/**
 * Advanced NHPAgent Usage Example
 *
 * This example demonstrates advanced features including:
 * - Event handling
 * - Multiple servers
 * - Custom key management
 * - Error handling patterns
 */

import {
  NHPAgent,
  generateX25519KeyPairBase64,
  generateSM2KeyPairBase64,
} from '@opennhp/agent';

async function main() {
  // Pre-generate keys (useful for persistent identity)
  const keys = generateX25519KeyPairBase64();
  console.log('Generated keys:');
  console.log('  Private:', keys.privateKey);
  console.log('  Public:', keys.publicKey);

  // Create agent with pre-existing key
  const agent = new NHPAgent({
    privateKey: keys.privateKey,
    cipherScheme: 'curve25519',
    transport: 'udp',
    logLevel: 'debug',
  });

  // Set up event handlers before init
  agent.on('knock', (data) => {
    console.log('[Event] Knock sent:', {
      type: data.packetType,
      size: data.packet.length,
    });
  });

  agent.on('ack', (data) => {
    console.log('[Event] Server acknowledged:', data);
  });

  agent.on('error', (err) => {
    console.error('[Event] Error occurred:', err);
  });

  try {
    await agent.init();
    console.log('Agent initialized with provided key');

    // Set identity
    agent.setIdentity({
      userId: 'admin@example.com',
      deviceId: 'workstation-001',
      organizationId: 'example.org',
    });

    // Add multiple servers for redundancy
    const servers = [
      {
        id: 'primary',
        publicKey: 'PRIMARY_SERVER_PUBLIC_KEY',
        host: 'nhp-primary.example.com',
        port: 62206,
      },
      {
        id: 'backup',
        publicKey: 'BACKUP_SERVER_PUBLIC_KEY',
        host: 'nhp-backup.example.com',
        port: 62206,
      },
    ];

    for (const server of servers) {
      agent.addServer(server);
      console.log(`Added server: ${server.id}`);
    }

    // Try primary server first, fall back to backup
    const resources = [
      { serverId: 'primary', host: 'nhp-primary.example.com' },
      { serverId: 'backup', host: 'nhp-backup.example.com' },
    ];

    let accessGranted = false;

    for (const { serverId, host } of resources) {
      console.log(`Trying ${serverId} server...`);

      try {
        const result = await agent.knockResource({
          resourceId: 'critical-service',
          serviceId: 'production',
          serverHost: host,
          serverPort: 62206,
        });

        if (result.success) {
          console.log(`Access granted via ${serverId}!`);
          console.log('Expires:', new Date(result.expiresAt!));
          console.log('Hosts:', result.resourceHosts);
          accessGranted = true;
          break;
        } else {
          console.warn(`${serverId} denied access:`, result.error);
        }
      } catch (err) {
        console.warn(`${serverId} failed:`, err);
        // Continue to next server
      }
    }

    if (!accessGranted) {
      console.error('All servers denied access');
    }

    // Demonstrate resource release
    await agent.exitResource({
      resourceId: 'critical-service',
      serviceId: 'production',
      serverHost: 'nhp-primary.example.com',
      serverPort: 62206,
    });
    console.log('Resource released');

  } catch (error) {
    console.error('Fatal error:', error);
  } finally {
    await agent.close();
    console.log('Agent closed');
  }
}

// Demonstrate SM2 key generation for GMSM
function generateSM2Keys() {
  const keys = generateSM2KeyPairBase64();
  console.log('\nSM2 Key Pair:');
  console.log('  Private (32 bytes):', keys.privateKey);
  console.log('  Public (64 bytes):', keys.publicKey);
}

main();
generateSM2Keys();
