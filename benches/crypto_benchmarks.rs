use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use pqc_protocol::{
    session::{PqcSession, Role},
    streaming::PqcStreamSender,
    error::Result,
};

fn setup_secure_session() -> Result<(PqcSession, PqcSession)> {
    let mut client = PqcSession::new()?;
    let mut server = PqcSession::new()?;
    server.set_role(Role::Server);
    
    let client_public_key = client.init_key_exchange()?;
    let ciphertext = server.accept_key_exchange(&client_public_key)?;
    client.process_key_exchange(&ciphertext)?;
    
    client.set_remote_verification_key(server.local_verification_key().clone())?;
    server.set_remote_verification_key(client.local_verification_key().clone())?;
    
    client.complete_authentication()?;
    server.complete_authentication()?;
    
    Ok((client, server))
}

fn benchmark_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");
    
    group.bench_function("client_init", |b| {
        b.iter(|| {
            let mut client = PqcSession::new().unwrap();
            black_box(client.init_key_exchange().unwrap());
        });
    });
    
    group.bench_function("server_accept", |b| {
        b.iter_with_setup(
            || {
                let mut client = PqcSession::new().unwrap();
                let mut server = PqcSession::new().unwrap();
                server.set_role(Role::Server);
                let client_public_key = client.init_key_exchange().unwrap();
                (server, client_public_key)
            },
            |(mut server, client_public_key)| {
                black_box(server.accept_key_exchange(&client_public_key).unwrap());
            }
        );
    });
    
    group.bench_function("client_process", |b| {
        b.iter_with_setup(
            || {
                let mut client = PqcSession::new().unwrap();
                let mut server = PqcSession::new().unwrap();
                server.set_role(Role::Server);
                let client_public_key = client.init_key_exchange().unwrap();
                let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
                (client, ciphertext)
            },
            |(mut client, ciphertext)| {
                black_box(client.process_key_exchange(&ciphertext).unwrap());
            }
        );
    });
    
    group.bench_function("complete_exchange", |b| {
        b.iter(|| {
            let mut client = PqcSession::new().unwrap();
            let mut server = PqcSession::new().unwrap();
            server.set_role(Role::Server);
            
            let client_public_key = client.init_key_exchange().unwrap();
            let ciphertext = server.accept_key_exchange(&client_public_key).unwrap();
            black_box(client.process_key_exchange(&ciphertext).unwrap());
        });
    });
    
    group.finish();
}

fn benchmark_encrypt_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt");
    
    // Test with different sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let data = vec![0x42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter_with_setup(
                || setup_secure_session().unwrap(),
                |(mut client, _)| {
                    black_box(client.encrypt_and_sign(data).unwrap());
                }
            );
        });
        
        group.bench_with_input(BenchmarkId::new("decrypt", size), &data, |b, data| {
            b.iter_with_setup(
                || {
                    let (mut client, mut server) = setup_secure_session().unwrap();
                    let encrypted = client.encrypt_and_sign(data).unwrap();
                    (server, encrypted)
                },
                |(mut server, encrypted)| {
                    black_box(server.verify_and_decrypt(&encrypted).unwrap());
                }
            );
        });
        
        group.bench_with_input(BenchmarkId::new("roundtrip", size), &data, |b, data| {
            b.iter_with_setup(
                || setup_secure_session().unwrap(),
                |(mut client, mut server)| {
                    let encrypted = client.encrypt_and_sign(data).unwrap();
                    black_box(server.verify_and_decrypt(&encrypted).unwrap());
                }
            );
        });
    }
    
    group.finish();
}

fn benchmark_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming");
    
    // 1MB of data
    let data_size = 1024 * 1024;
    let data = vec![0x42u8; data_size];
    
    group.throughput(Throughput::Bytes(data_size as u64));
    
    // Test with different chunk sizes
    for chunk_size in [4096, 8192, 16384, 32768].iter() {
        group.bench_with_input(BenchmarkId::new("stream", chunk_size), chunk_size, |b, &chunk_size| {
            b.iter_with_setup(
                || {
                    let (mut client, _) = setup_secure_session().unwrap();
                    (client, data.clone())
                },
                |(mut client, data)| {
                    let mut sender = PqcStreamSender::new(&mut client, Some(chunk_size));
                    let chunks: Vec<_> = sender.stream_data(&data).collect::<Result<Vec<_>>>().unwrap();
                    black_box(chunks);
                }
            );
        });
    }
    
    group.finish();
}

fn benchmark_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");
    
    for size in [64, 256, 1024, 4096].iter() {
        let data = vec![0x42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("sign", size), &data, |b, data| {
            b.iter_with_setup(
                || PqcSession::new().unwrap(),
                |session| {
                    black_box(session.sign(data).unwrap());
                }
            );
        });
        
        group.bench_with_input(BenchmarkId::new("verify", size), &data, |b, data| {
            b.iter_with_setup(
                || {
                    let client = PqcSession::new().unwrap();
                    let server = PqcSession::new().unwrap();
                    let signature = client.sign(data).unwrap();
                    (server, client.local_verification_key().clone(), signature)
                },
                |(server, vk, signature)| {
                    server.set_remote_verification_key(vk.clone()).unwrap();
                    black_box(server.verify(data, &signature).unwrap());
                }
            );
        });
    }
    
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_key_exchange, benchmark_encrypt_decrypt, benchmark_streaming, benchmark_signature
);
criterion_main!(benches);