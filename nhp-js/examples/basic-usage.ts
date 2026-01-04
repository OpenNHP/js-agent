/**
 * Basic NHPAgent Usage Example
 *
 * This example demonstrates the fundamental usage of the NHPAgent SDK
 * for authenticating with an OpenNHP server.
 */

import { NHPAgent } from '@opennhp/agent';

async function main() {
  // Create agent with default settings (CURVE25519 cipher scheme)
  const agent = new NHPAgent({
    cipherScheme: 'curve25519',
    logLevel: 'info',
  });

  try {
    // Initialize agent - generates X25519 key pair
    await agent.init();
    console.log('Agent initialized');
    console.log('Public key:', agent.getPublicKey());

    // Set identity for knock requests
    agent.setIdentity({
      userId: 'user@example.com',
      deviceId: 'my-device-id',
      organizationId: 'example.org',
    });

    // Add server configuration
    // Replace with your actual NHP server details
    agent.addServer({
      publicKey: 'YOUR_SERVER_PUBLIC_KEY_BASE64',
      host: 'nhp.example.com',
      port: 62206,
    });

    // Knock on a resource to request access
    const result = await agent.knockResource({
      resourceId: 'protected-resource',
      serviceId: 'my-service',
      serverHost: 'nhp.example.com',
      serverPort: 62206,
    });

    if (result.success) {
      console.log('Access granted!');
      console.log('Expires at:', new Date(result.expiresAt!));
      console.log('Resource hosts:', result.resourceHosts);

      if (result.accessToken) {
        console.log('Access token:', result.accessToken);
      }
    } else {
      console.error('Access denied:', result.error);
      console.error('Error code:', result.errorCode);
    }
  } catch (error) {
    console.error('Error:', error);
  } finally {
    // Always cleanup
    await agent.close();
    console.log('Agent closed');
  }
}

main();
