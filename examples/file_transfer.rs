/*!
A more advanced example demonstrating a secure file transfer application
using the PQC Protocol.

This example shows how to:
1. Set up secure communication between a client and server
2. Transfer files securely with streaming
3. Handle errors and connection interruptions
4. Monitor progress and collect statistics
*/

use pqc_protocol::{
    api::{PqcClient, PqcServer},
    error::Result,
};

use std::{
    fs::{self, File},
    io::{self, Read, Write, Seek, SeekFrom},
    path::{Path, PathBuf},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
    sync::{Arc, Mutex},
    env,
};

const SERVER_ADDR: &str = "127.0.0.1:8091";
const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
const PROGRESS_UPDATE_INTERVAL: Duration = Duration::from_millis(100);

// File transfer statistics
#[derive(Debug, Clone, Default)]
struct TransferStats {
    total_bytes: u64,
    bytes_transferred: u64,
    start_time: Option<Instant>,
    chunks_transferred: u32,
    current_speed: f64, // bytes per second
}

impl TransferStats {
    fn new(total_bytes: u64) -> Self {
        Self {
            total_bytes,
            bytes_transferred: 0,
            start_time: None,
            chunks_transferred: 0,
            current_speed: 0.0,
        }
    }
    
    fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }
    
    fn update(&mut self, bytes: usize) {
        self.bytes_transferred += bytes as u64;
        self.chunks_transferred += 1;
        
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.current_speed = self.bytes_transferred as f64 / elapsed;
            }
        }
    }
    
    fn elapsed_secs(&self) -> f64 {
        self.start_time.map_or(0.0, |t| t.elapsed().as_secs_f64())
    }
    
    fn percent_complete(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0
    }
    
    fn avg_speed(&self) -> f64 {
        let elapsed = self.elapsed_secs();
        if elapsed > 0.0 {
            self.bytes_transferred as f64 / elapsed
        } else {
            0.0
        }
    }
}

// File transfer protocol messages
enum Message {
    RequestFile { path: String },
    FileInfo { size: u64, name: String },
    FileData { chunk: Vec<u8>, chunk_num: u32 },
    FileComplete,
    FileNotFound,
    Error { message: String },
}

impl Message {
    // Serialize message to bytes
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::RequestFile { path } => {
                let mut data = vec![1]; // Type code
                data.extend_from_slice(path.as_bytes());
                data
            },
            Message::FileInfo { size, name } => {
                let mut data = vec![2]; // Type code
                data.extend_from_slice(&size.to_be_bytes());
                data.extend_from_slice(name.as_bytes());
                data
            },
            Message::FileData { chunk, chunk_num } => {
                let mut data = vec![3]; // Type code
                data.extend_from_slice(&chunk_num.to_be_bytes());
                data.extend_from_slice(chunk);
                data
            },
            Message::FileComplete => vec![4], // Type code
            Message::FileNotFound => vec![5],  // Type code
            Message::Error { message } => {
                let mut data = vec![6]; // Type code
                data.extend_from_slice(message.as_bytes());
                data
            },
        }
    }
    
    // Deserialize message from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(pqc_protocol::error::Error::InvalidFormat("Empty message".into()));
        }
        
        match bytes[0] {
            1 => {
                let path = String::from_utf8_lossy(&bytes[1..]).to_string();
                Ok(Message::RequestFile { path })
            },
            2 => {
                if bytes.len() < 9 {
                    return Err(pqc_protocol::error::Error::InvalidFormat("FileInfo message too short".into()));
                }
                let mut size_bytes = [0u8; 8];
                size_bytes.copy_from_slice(&bytes[1..9]);
                let size = u64::from_be_bytes(size_bytes);
                let name = String::from_utf8_lossy(&bytes[9..]).to_string();
                Ok(Message::FileInfo { size, name })
            },
            3 => {
                if bytes.len() < 5 {
                    return Err(pqc_protocol::error::Error::InvalidFormat("FileData message too short".into()));
                }
                let mut chunk_num_bytes = [0u8; 4];
                chunk_num_bytes.copy_from_slice(&bytes[1..5]);
                let chunk_num = u32::from_be_bytes(chunk_num_bytes);
                let chunk = bytes[5..].to_vec();
                Ok(Message::FileData { chunk, chunk_num })
            },
            4 => Ok(Message::FileComplete),
            5 => Ok(Message::FileNotFound),
            6 => {
                let message = String::from_utf8_lossy(&bytes[1..]).to_string();
                Ok(Message::Error { message })
            },
            _ => Err(pqc_protocol::error::Error::InvalidFormat(format!("Unknown message type: {}", bytes[0]))),
        }
    }
}

// Run the file transfer server
fn run_server() -> Result<()> {
    println!("Starting file transfer server on {}...", SERVER_ADDR);
    let listener = TcpListener::bind(SERVER_ADDR)?;
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New client connected: {}", stream.peer_addr()?);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("Error handling client: {}", e);
                    }
                });
            },
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}

// Handle a client connection
fn handle_client(mut stream: TcpStream) -> Result<()> {
    // Set up the secure session
    let mut server = PqcServer::new()?;
    
    // Perform the key exchange and authentication
    setup_secure_server_session(&mut stream, &mut server)?;
    
    println!("Secure connection established. Waiting for file request...");
    
    // Wait for file request
    let mut request_data = Vec::new();
    let mut len_buf = [0u8; 4];
    
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_be_bytes(len_buf);
    
    request_data.resize(msg_len as usize, 0);
    stream.read_exact(&mut request_data)?;
    
    let decrypted = server.receive(&request_data)?;
    let message = Message::from_bytes(&decrypted)?;
    
    match message {
        Message::RequestFile { path } => {
            println!("Received request for file: {}", path);
            
            // Check if file exists
            let file_path = Path::new(&path);
            if !file_path.exists() || !file_path.is_file() {
                println!("File not found: {}", path);
                let not_found = Message::FileNotFound.to_bytes();
                let encrypted = server.send(&not_found)?;
                
                stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
                stream.write_all(&encrypted)?;
                return Ok(());
            }
            
            // Get file info
            let metadata = fs::metadata(&path)?;
            let file_size = metadata.len();
            let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            
            println!("Sending file: {} ({} bytes)", file_name, file_size);
            
            // Send file info
            let file_info = Message::FileInfo { 
                size: file_size, 
                name: file_name 
            }.to_bytes();
            
            let encrypted = server.send(&file_info)?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
            
            // Open the file
            let mut file = File::open(&path)?;
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let mut chunk_num = 0;
            
            // Stats for progress tracking
            let mut stats = TransferStats::new(file_size);
            stats.start();
            
            let stats_clone = Arc::new(Mutex::new(stats.clone()));
            let stats_ref = Arc::clone(&stats_clone);
            
            // Start a thread to periodically display progress
            let progress_thread = thread::spawn(move || {
                display_progress_thread(stats_ref);
            });
            
            // Send file in chunks
            loop {
                // Read a chunk from the file
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break; // End of file
                }
                
                // Update stats
                stats.update(bytes_read);
                let mut stats_guard = stats_clone.lock().unwrap();
                *stats_guard = stats.clone();
                drop(stats_guard);
                
                // Send chunk
                let file_data = Message::FileData {
                    chunk: buffer[..bytes_read].to_vec(),
                    chunk_num,
                }.to_bytes();
                
                let encrypted = server.send(&file_data)?;
                stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
                stream.write_all(&encrypted)?;
                
                chunk_num += 1;
            }
            
            // Send file complete message
            let complete = Message::FileComplete.to_bytes();
            let encrypted = server.send(&complete)?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
            
            // Wait for progress thread to finish
            progress_thread.join().unwrap();
            
            println!("\nFile transfer complete!");
            println!("Sent {} chunks ({} bytes) in {:.2} seconds", 
                     chunk_num, file_size, stats.elapsed_secs());
            println!("Average speed: {:.2} MB/s", stats.avg_speed() / (1024.0 * 1024.0));
        },
        _ => {
            let error = Message::Error {
                message: "Expected file request".to_string(),
            }.to_bytes();
            let encrypted = server.send(&error)?;
            stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
            stream.write_all(&encrypted)?;
        }
    }
    
    Ok(())
}

// Run the file transfer client
fn run_client(file_path: &str, save_dir: &str) -> Result<()> {
    println!("Connecting to server at {}...", SERVER_ADDR);
    let mut stream = TcpStream::connect(SERVER_ADDR)?;
    
    // Set up the secure session
    let mut client = PqcClient::new()?;
    
    // Perform the key exchange and authentication
    setup_secure_client_session(&mut stream, &mut client)?;
    
    println!("Secure connection established. Requesting file...");
    
    // Request the file
    let request = Message::RequestFile {
        path: file_path.to_string(),
    }.to_bytes();
    
    let encrypted = client.send(&request)?;
    stream.write_all(&(encrypted.len() as u32).to_be_bytes())?;
    stream.write_all(&encrypted)?;
    
    // Wait for server response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_be_bytes(len_buf);
    
    let mut response_data = vec![0u8; msg_len as usize];
    stream.read_exact(&mut response_data)?;
    
    let decrypted = client.receive(&response_data)?;
    let message = Message::from_bytes(&decrypted)?;
    
    match message {
        Message::FileInfo { size, name } => {
            println!("Server is sending file: {} ({} bytes)", name, size);
            
            // Create the output file
            let save_path = Path::new(save_dir).join(&name);
            let mut file = File::create(&save_path)?;
            
            // Stats for progress tracking
            let mut stats = TransferStats::new(size);
            stats.start();
            
            let stats_clone = Arc::new(Mutex::new(stats.clone()));
            let stats_ref = Arc::clone(&stats_clone);
            
            // Start a thread to periodically display progress
            let progress_thread = thread::spawn(move || {
                display_progress_thread(stats_ref);
            });
            
            // Receive file chunks
            let mut chunk_num = 0;
            
            loop {
                // Read message length
                stream.read_exact(&mut len_buf)?;
                let msg_len = u32::from_be_bytes(len_buf);
                
                let mut message_data = vec![0u8; msg_len as usize];
                stream.read_exact(&mut message_data)?;
                
                let decrypted = client.receive(&message_data)?;
                let message = Message::from_bytes(&decrypted)?;
                
                match message {
                    Message::FileData { chunk, chunk_num: received_chunk_num } => {
                        if received_chunk_num != chunk_num {
                            return Err(pqc_protocol::error::Error::Protocol(
                                format!("Expected chunk {}, got {}", chunk_num, received_chunk_num)
                            ));
                        }
                        
                        // Write chunk to file
                        file.write_all(&chunk)?;
                        
                        // Update stats
                        stats.update(chunk.len());
                        let mut stats_guard = stats_clone.lock().unwrap();
                        *stats_guard = stats.clone();
                        drop(stats_guard);
                        
                        chunk_num += 1;
                    },
                    Message::FileComplete => {
                        // File transfer complete
                        break;
                    },
                    Message::Error { message } => {
                        return Err(pqc_protocol::error::Error::Protocol(message));
                    },
                    _ => {
                        return Err(pqc_protocol::error::Error::Protocol(
                            format!("Unexpected message type during file transfer")
                        ));
                    }
                }
            }
            
            // Flush and close the file
            file.flush()?;
            
            // Wait for progress thread to finish
            progress_thread.join().unwrap();
            
            println!("\nFile transfer complete!");
            println!("Received {} chunks ({} bytes) in {:.2} seconds", 
                     chunk_num, stats.bytes_transferred, stats.elapsed_secs());
            println!("Average speed: {:.2} MB/s", stats.avg_speed() / (1024.0 * 1024.0));
            println!("File saved to: {}", save_path.display());
        },
        Message::FileNotFound => {
            println!("File not found on server: {}", file_path);
        },
        Message::Error { message } => {
            println!("Server error: {}", message);
        },
        _ => {
            return Err(pqc_protocol::error::Error::Protocol(
                format!("Unexpected message type in server response")
            ));
        }
    }
    
    Ok(())
}

// Helper function to set up a secure client session
fn setup_secure_client_session(stream: &mut TcpStream, client: &mut PqcClient) -> Result<()> {
    // Step 1: Send public key
    let public_key = client.connect()?;
    stream.write_all(&(public_key.len() as u32).to_be_bytes())?;
    stream.write_all(&public_key)?;
    
    // Step 2: Receive server's ciphertext and verification key
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let ct_len = u32::from_be_bytes(len_buf);
    
    let mut ciphertext = vec![0u8; ct_len as usize];
    stream.read_exact(&mut ciphertext)?;
    
    stream.read_exact(&mut len_buf)?;
    let vk_len = u32::from_be_bytes(len_buf);
    
    let mut server_vk = vec![0u8; vk_len as usize];
    stream.read_exact(&mut server_vk)?;
    
    // Step 3: Process response and send our verification key
    let client_vk = client.process_response(&ciphertext)?;
    stream.write_all(&(client_vk.len() as u32).to_be_bytes())?;
    stream.write_all(&client_vk)?;
    
    // Step 4: Complete authentication
    client.authenticate(&server_vk)?;
    
    Ok(())
}

// Helper function to set up a secure server session
fn setup_secure_server_session(stream: &mut TcpStream, server: &mut PqcServer) -> Result<()> {
    // Step 1: Receive client's public key
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let pk_len = u32::from_be_bytes(len_buf);
    
    let mut client_pk = vec![0u8; pk_len as usize];
    stream.read_exact(&mut client_pk)?;
    
    // Step 2: Process client's public key and send ciphertext and verification key
    let (ciphertext, server_vk) = server.accept(&client_pk)?;
    
    stream.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
    stream.write_all(&ciphertext)?;
    
    stream.write_all(&(server_vk.len() as u32).to_be_bytes())?;
    stream.write_all(&server_vk)?;
    
    // Step 3: Receive client's verification key
    stream.read_exact(&mut len_buf)?;
    let vk_len = u32::from_be_bytes(len_buf);
    
    let mut client_vk = vec![0u8; vk_len as usize];
    stream.read_exact(&mut client_vk)?;
    
    // Step 4: Complete authentication
    server.authenticate(&client_vk)?;
    
    Ok(())
}

// Thread to display progress updates
fn display_progress_thread(stats: Arc<Mutex<TransferStats>>) {
    loop {
        thread::sleep(PROGRESS_UPDATE_INTERVAL);
        
        let stats_guard = stats.lock().unwrap();
        let stats = stats_guard.clone();
        drop(stats_guard);
        
        if stats.percent_complete() >= 100.0 {
            break;
        }
        
        print!("\rProgress: {:.1}% ({:.2} MB / {:.2} MB) - {:.2} MB/s    ", 
            stats.percent_complete(),
            stats.bytes_transferred as f64 / (1024.0 * 1024.0),
            stats.total_bytes as f64 / (1024.0 * 1024.0),
            stats.current_speed / (1024.0 * 1024.0));
        io::stdout().flush().unwrap();
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage:");
        println!("  Server mode: {} --server", args[0]);
        println!("  Client mode: {} <file_to_request> [save_directory]", args[0]);
        return Ok(());
    }
    
    if args[1] == "--server" {
        run_server()
    } else {
        let file_path = &args[1];
        let save_dir = if args.len() > 2 { &args[2] } else { "." };
        
        run_client(file_path, save_dir)
    }
}