/**
 * GMSM (Chinese Cryptography) Usage Example
 *
 * This example demonstrates using the GMSM cipher scheme
 * which implements Chinese National Cryptographic Standards:
 * - SM2 for key exchange (GB/T 32918-2016)
 * - SM3 for hashing (GB/T 32905-2016)
 * - SM4-GCM for encryption (GB/T 32907-2016)
 */

import { NHPAgent } from '@opennhp/agent';

async function main() {
  // Create agent with GMSM cipher scheme
  const agent = new NHPAgent({
    cipherScheme: 'gmsm',
    logLevel: 'info',
  });

  try {
    // Initialize agent - generates SM2 key pair
    await agent.init();
    console.log('Agent initialized with GMSM cipher scheme');
    console.log('SM2 Public key:', agent.getPublicKey());

    // Set identity
    agent.setIdentity({
      userId: 'user@example.cn',
      deviceId: 'device-id-here',
      organizationId: 'example.cn',
    });

    // Add server (must also support GMSM)
    agent.addServer({
      publicKey: 'YOUR_SM2_SERVER_PUBLIC_KEY_BASE64',
      host: 'nhp.example.cn',
      port: 62206,
    });

    // Knock on resource
    const result = await agent.knockResource({
      resourceId: 'protected-resource',
      serviceId: 'my-service',
      serverHost: 'nhp.example.cn',
      serverPort: 62206,
    });

    if (result.success) {
      console.log('Access granted with GMSM authentication!');
      console.log('Expires at:', new Date(result.expiresAt!));
    } else {
      console.error('Access denied:', result.error);
    }
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await agent.close();
  }
}

main();
