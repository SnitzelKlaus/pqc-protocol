// TODO - Update to work with new project structure

// Example of using PQC Protocol in a browser via WebAssembly
import init, {
  WasmPqcSession,
  WasmPqcStreamSender,
  get_kyber_public_key_bytes,
  get_kyber_ciphertext_bytes,
  get_dilithium_public_key_bytes
} from '../pkg/pqc_protocol';

// Main function that runs after the WASM module is loaded
async function run() {
  // Initialize the WASM module
  await init();
  
  // Create DOM elements for the demo
  const logElement = document.getElementById('log') || document.body;
  
  function log(message) {
    const div = document.createElement('div');
    div.textContent = message;
    logElement.appendChild(div);
    console.log(message);
  }
  
  log('PQC Protocol Browser Example');
  log('===========================');
  
  try {
    // Simulate client and server in the browser
    await simulateProtocol(log);
  } catch (error) {
    log(`Error: ${error.message}`);
    console.error(error);
  }
}

// Simulation of client-server communication
async function simulateProtocol(log) {
  // Create client and server sessions
  log('Creating client and server sessions...');
  const clientSession = new WasmPqcSession();
  const serverSession = new WasmPqcSession();
  
  // Step 1: Key Exchange
  log('\nStep 1: Key Exchange');
  
  // Client initiates key exchange
  log('Client: Initiating key exchange...');
  const clientPublicKey = clientSession.init_key_exchange();
  log(`Client: Generated public key (${clientPublicKey.length} bytes)`);
  
  // Server accepts key exchange
  log('Server: Accepting key exchange...');
  const ciphertext = serverSession.accept_key_exchange(clientPublicKey);
  log(`Server: Generated ciphertext (${ciphertext.length} bytes)`);
  
  // Client processes key exchange response
  log('Client: Processing key exchange response...');
  clientSession.process_key_exchange(ciphertext);
  
  // Step 2: Authentication
  log('\nStep 2: Authentication');
  
  // Exchange verification keys
  log('Client: Sending verification key...');
  const clientVerificationKey = clientSession.get_local_verification_key();
  log(`Client: Verification key size: ${clientVerificationKey.length} bytes`);
  
  log('Server: Sending verification key...');
  const serverVerificationKey = serverSession.get_local_verification_key();
  log(`Server: Verification key size: ${serverVerificationKey.length} bytes`);
  
  // Set verification keys
  log('Client: Setting server\'s verification key...');
  clientSession.set_remote_verification_key(serverVerificationKey);
  
  log('Server: Setting client\'s verification key...');
  serverSession.set_remote_verification_key(clientVerificationKey);
  
  // Complete authentication
  log('Client: Completing authentication...');
  clientSession.complete_authentication();
  
  log('Server: Completing authentication...');
  serverSession.complete_authentication();
  
  log('Authentication complete! Secure channel established.');
  
  // Step 3: Data Exchange
  log('\nStep 3: Data Exchange');
  
  // Example data
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  
  const message = 'Hello, post-quantum secure world!';
  const messageBytes = encoder.encode(message);
  
  // Client sends message
  log(`Client: Sending message: "${message}"`);
  const encryptedMessage = clientSession.encrypt_and_sign(messageBytes);
  log(`Client: Encrypted message size: ${encryptedMessage.length} bytes`);
  
  // Server receives and decrypts message
  log('Server: Receiving and decrypting message...');
  const decryptedMessage = serverSession.verify_and_decrypt(encryptedMessage);
  log(`Server: Received message: "${decoder.decode(decryptedMessage)}"`);
  
  // Server sends response
  const response = 'Hello from the server! Your message was received successfully.';
  const responseBytes = encoder.encode(response);
  
  log(`Server: Sending response: "${response}"`);
  const encryptedResponse = serverSession.encrypt_and_sign(responseBytes);
  log(`Server: Encrypted response size: ${encryptedResponse.length} bytes`);
  
  // Client receives and decrypts response
  log('Client: Receiving and decrypting response...');
  const decryptedResponse = clientSession.verify_and_decrypt(encryptedResponse);
  log(`Client: Received response: "${decoder.decode(decryptedResponse)}"`);
  
  // Step 4: Streaming Large Data
  log('\nStep 4: Streaming Large Data');
  
  // Create a large data array (100KB)
  const largeData = new Uint8Array(100 * 1024);
  for (let i = 0; i < largeData.length; i++) {
    largeData[i] = i % 256;
  }
  
  // Create stream sender
  const streamSender = new WasmPqcStreamSender(16384); // 16KB chunks
  log(`Client: Streaming ${largeData.length} bytes in ${streamSender.get_chunk_size()}-byte chunks...`);
  
  // Stream data
  const encryptedChunks = streamSender.stream_data(clientSession, largeData);
  log(`Client: Data split into ${encryptedChunks.length} encrypted chunks`);
  
  // Server receives and processes chunks
  log('Server: Receiving and processing chunks...');
  let totalBytesReceived = 0;
  
  for (let i = 0; i < encryptedChunks.length; i++) {
    const chunk = encryptedChunks[i];
    const decryptedChunk = serverSession.verify_and_decrypt(chunk);
    totalBytesReceived += decryptedChunk.length;
    
    if (i % 2 === 0) {
      log(`Server: Processed chunk ${i+1}/${encryptedChunks.length}...`);
    }
  }
  
  log(`Server: Successfully received all chunks (${totalBytesReceived} bytes total)`);
  
  // Step 5: Session Close
  log('\nStep 5: Session Close');
  
  // Close sessions
  log('Client: Closing session...');
  const closeMessage = clientSession.close();
  log(`Client: Generated close message (${closeMessage.length} bytes)`);
  
  log('Server: Processing close message...');
  log('Server: Session closed');
  
  log('\nDemo complete! All steps of the PQC protocol were successfully demonstrated.');
}

// Run the demo when the page loads
window.addEventListener('DOMContentLoaded', run);