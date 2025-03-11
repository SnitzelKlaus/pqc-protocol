// TODO - Update to work with new project structure

using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PqcProtocol;

namespace PqcExample
{
    class Program
    {
        const int PORT = 8081;
        
        static async Task Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--server")
            {
                await RunServer();
            }
            else
            {
                await RunClient();
            }
        }
        
        static async Task RunServer()
        {
            Console.WriteLine("Starting PQC Protocol Server");
            
            var listener = new TcpListener(IPAddress.Loopback, PORT);
            listener.Start();
            
            Console.WriteLine($"Listening on 127.0.0.1:{PORT}");
            
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(() => HandleClient(client));
            }
        }
        
        static async Task HandleClient(TcpClient client)
        {
            try
            {
                Console.WriteLine($"Client connected: {client.Client.RemoteEndPoint}");
                
                using (client)
                using (NetworkStream stream = client.GetStream())
                using (var session = new PqcSession())
                {
                    // Read client's public key
                    byte[] lenBuffer = new byte[4];
                    await stream.ReadAsync(lenBuffer, 0, 4);
                    int pkLen = BitConverter.ToInt32(lenBuffer, 0);
                    
                    byte[] pkBuffer = new byte[pkLen];
                    await stream.ReadAsync(pkBuffer, 0, pkLen);
                    
                    // Accept key exchange
                    Console.WriteLine("Accepting key exchange...");
                    byte[] ciphertext = session.AcceptKeyExchange(pkBuffer);
                    
                    // Send ciphertext
                    byte[] ctLen = BitConverter.GetBytes(ciphertext.Length);
                    await stream.WriteAsync(ctLen, 0, ctLen.Length);
                    await stream.WriteAsync(ciphertext, 0, ciphertext.Length);
                    
                    // Exchange verification keys
                    Console.WriteLine("Exchanging verification keys...");
                    
                    // Read client's verification key
                    await stream.ReadAsync(lenBuffer, 0, 4);
                    int vkLen = BitConverter.ToInt32(lenBuffer, 0);
                    
                    byte[] vkBuffer = new byte[vkLen];
                    await stream.ReadAsync(vkBuffer, 0, vkLen);
                    
                    // Set remote verification key
                    session.SetRemoteVerificationKey(vkBuffer);
                    
                    // Send server's verification key
                    byte[] serverVk = session.GetLocalVerificationKey();
                    byte[] serverVkLen = BitConverter.GetBytes(serverVk.Length);
                    await stream.WriteAsync(serverVkLen, 0, serverVkLen.Length);
                    await stream.WriteAsync(serverVk, 0, serverVk.Length);
                    
                    // Complete authentication
                    session.CompleteAuthentication();
                    Console.WriteLine("Secure connection established!");
                    
                    // Main communication loop
                    int messageCount = 0;
                    int bytesReceived = 0;
                    
                    while (true)
                    {
                        // Read message length
                        if (await stream.ReadAsync(lenBuffer, 0, 4) == 0)
                        {
                            break;
                        }
                        
                        int msgLen = BitConverter.ToInt32(lenBuffer, 0);
                        byte[] message = new byte[msgLen];
                        await stream.ReadAsync(message, 0, msgLen);
                        
                        // Check if it's a close message (simple check based on message type)
                        if (message.Length > 1 && message[1] == 0x05) // Close message type
                        {
                            Console.WriteLine("Client requested to close the connection");
                            break;
                        }
                        
                        try
                        {
                            // Decrypt and verify
                            byte[] decrypted = session.VerifyAndDecrypt(message);
                            bytesReceived += decrypted.Length;
                            messageCount++;
                            
                            if (messageCount == 1)
                            {
                                // For the first message, print and send a response
                                string text = Encoding.UTF8.GetString(decrypted);
                                Console.WriteLine($"Received message: {text}");
                                
                                // Send response
                                byte[] response = Encoding.UTF8.GetBytes("Hello from the C# server! Your message was received.");
                                byte[] encrypted = session.EncryptAndSign(response);
                                
                                byte[] respLen = BitConverter.GetBytes(encrypted.Length);
                                await stream.WriteAsync(respLen, 0, respLen.Length);
                                await stream.WriteAsync(encrypted, 0, encrypted.Length);
                            }
                            else if (messageCount % 10 == 0)
                            {
                                // Just print progress for streaming data
                                Console.WriteLine($"Received {messageCount} messages ({bytesReceived} bytes total)");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to decrypt message: {ex.Message}");
                        }
                    }
                    
                    Console.WriteLine($"Connection closed. Received {messageCount} messages ({bytesReceived} bytes total)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }
        }
        
        static async Task RunClient()
        {
            Console.WriteLine("Starting PQC Protocol Client");
            
            try
            {
                using (var client = new TcpClient())
                using (var session = new PqcSession())
                {
                    Console.WriteLine("Connecting to server...");
                    await client.ConnectAsync(IPAddress.Loopback, PORT);
                    
                    using (NetworkStream stream = client.GetStream())
                    {
                        // Initialize key exchange
                        Console.WriteLine("Initiating key exchange...");
                        byte[] publicKey = session.InitKeyExchange();
                        
                        // Send public key
                        byte[] pkLen = BitConverter.GetBytes(publicKey.Length);
                        await stream.WriteAsync(pkLen, 0, pkLen.Length);
                        await stream.WriteAsync(publicKey, 0, publicKey.Length);
                        
                        // Receive ciphertext
                        byte[] lenBuffer = new byte[4];
                        await stream.ReadAsync(lenBuffer, 0, 4);
                        int ctLen = BitConverter.ToInt32(lenBuffer, 0);
                        
                        byte[] ctBuffer = new byte[ctLen];
                        await stream.ReadAsync(ctBuffer, 0, ctLen);
                        
                        // Process key exchange
                        Console.WriteLine("Processing key exchange response...");
                        session.ProcessKeyExchange(ctBuffer);
                        
                        // Exchange verification keys
                        Console.WriteLine("Exchanging verification keys...");
                        
                        // Send client's verification key
                        byte[] clientVk = session.GetLocalVerificationKey();
                        byte[] clientVkLen = BitConverter.GetBytes(clientVk.Length);
                        await stream.WriteAsync(clientVkLen, 0, clientVkLen.Length);
                        await stream.WriteAsync(clientVk, 0, clientVk.Length);
                        
                        // Receive server's verification key
                        await stream.ReadAsync(lenBuffer, 0, 4);
                        int vkLen = BitConverter.ToInt32(lenBuffer, 0);
                        
                        byte[] vkBuffer = new byte[vkLen];
                        await stream.ReadAsync(vkBuffer, 0, vkLen);
                        
                        // Set remote verification key
                        session.SetRemoteVerificationKey(vkBuffer);
                        
                        // Complete authentication
                        session.CompleteAuthentication();
                        Console.WriteLine("Secure connection established!");
                        
                        // Send a test message
                        string message = "Hello from the C# client! This is a post-quantum secure message.";
                        byte[] data = Encoding.UTF8.GetBytes(message);
                        Console.WriteLine($"Sending: {message}");
                        
                        byte[] encrypted = session.EncryptAndSign(data);
                        byte[] msgLen = BitConverter.GetBytes(encrypted.Length);
                        await stream.WriteAsync(msgLen, 0, msgLen.Length);
                        await stream.WriteAsync(encrypted, 0, encrypted.Length);
                        
                        // Receive response
                        await stream.ReadAsync(lenBuffer, 0, 4);
                        int respLen = BitConverter.ToInt32(lenBuffer, 0);
                        
                        byte[] respBuffer = new byte[respLen];
                        await stream.ReadAsync(respBuffer, 0, respLen);
                        
                        byte[] decrypted = session.VerifyAndDecrypt(respBuffer);
                        string response = Encoding.UTF8.GetString(decrypted);
                        Console.WriteLine($"Received: {response}");
                        
                        // Stream large data
                        Console.WriteLine("\nDemonstrating large data streaming...");
                        byte[] largeData = new byte[1_000_000]; // 1MB of data
                        for (int i = 0; i < largeData.Length; i++)
                        {
                            largeData[i] = (byte)(i % 256);
                        }
                        
                        var streamSender = new PqcStreamSender(session, 16384);
                        int chunkCount = 0;
                        
                        Console.WriteLine($"Streaming 1MB in {streamSender.ChunkSize}-byte chunks...");
                        foreach (byte[] chunk in streamSender.StreamData(largeData))
                        {
                            byte[] chunkLen = BitConverter.GetBytes(chunk.Length);
                            await stream.WriteAsync(chunkLen, 0, chunkLen.Length);
                            await stream.WriteAsync(chunk, 0, chunk.Length);
                            chunkCount++;
                            
                            if (chunkCount % 10 == 0)
                            {
                                Console.Write(".");
                            }
                        }
                        
                        Console.WriteLine($"\nSent {chunkCount} chunks ({largeData.Length} bytes total)");
                        
                        // Close session
                        Console.WriteLine("Closing session...");
                        byte[] closeMsg = session.Close();
                        byte[] closeLen = BitConverter.GetBytes(closeMsg.Length);
                        await stream.WriteAsync(closeLen, 0, closeLen.Length);
                        await stream.WriteAsync(closeMsg, 0, closeMsg.Length);
                        
                        Console.WriteLine("Session closed successfully");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}