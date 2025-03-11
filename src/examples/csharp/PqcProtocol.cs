using System;
using System.Runtime.InteropServices;

namespace PqcProtocol
{
    /// <summary>
    /// Error codes for the PQC protocol
    /// </summary>
    public enum PqcErrorCode
    {
        Success = 0,
        InvalidArgument = -1,
        CryptoError = -2,
        AuthError = -3,
        SessionError = -4,
        IoError = -5,
        InternalError = -6
    }

    /// <summary>
    /// Post-Quantum Cryptography session class
    /// </summary>
    public class PqcSession : IDisposable
    {
        // Constants
        public const int KYBER_PUBLIC_KEY_BYTES = 1184;
        public const int KYBER_CIPHERTEXT_BYTES = 1088;
        public const int DILITHIUM_PUBLIC_KEY_BYTES = 1952;
        public const int DILITHIUM_SIGNATURE_BYTES = 3293;
        
        // Handle to the native session
        private IntPtr _handle;
        private bool _disposed = false;

        // Native DLL imports
        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr pqc_create_session();

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern void pqc_destroy_session(IntPtr handle);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_init_key_exchange(
            IntPtr handle,
            [Out] byte[] outPublicKey,
            ref uint outPublicKeyLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_process_key_exchange(
            IntPtr handle,
            [In] byte[] ciphertext,
            uint ciphertextLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_accept_key_exchange(
            IntPtr handle,
            [In] byte[] publicKey,
            uint publicKeyLen,
            [Out] byte[] outCiphertext,
            ref uint outCiphertextLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_encrypt_and_sign(
            IntPtr handle,
            [In] byte[] data,
            uint dataLen,
            [Out] byte[] outMessage,
            ref uint outMessageLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_verify_and_decrypt(
            IntPtr handle,
            [In] byte[] message,
            uint messageLen,
            [Out] byte[] outData,
            ref uint outDataLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_set_remote_verification_key(
            IntPtr handle,
            [In] byte[] key,
            uint keyLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_get_local_verification_key(
            IntPtr handle,
            [Out] byte[] outKey,
            ref uint outKeyLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_complete_authentication(IntPtr handle);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_generate_ack(
            IntPtr handle,
            uint seqNum,
            [Out] byte[] outAck,
            ref uint outAckLen);

        [DllImport("pqc_protocol", CallingConvention = CallingConvention.Cdecl)]
        private static extern int pqc_close(
            IntPtr handle,
            [Out] byte[] outClose,
            ref uint outCloseLen);

        /// <summary>
        /// Creates a new PQC session
        /// </summary>
        public PqcSession()
        {
            _handle = pqc_create_session();
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create PQC session");
            }
        }

        /// <summary>
        /// Initializes a key exchange (client side)
        /// </summary>
        /// <returns>Public key to send to the server</returns>
        public byte[] InitKeyExchange()
        {
            var publicKey = new byte[KYBER_PUBLIC_KEY_BYTES];
            uint publicKeyLen = (uint)publicKey.Length;

            var result = (PqcErrorCode)pqc_init_key_exchange(_handle, publicKey, ref publicKeyLen);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Key exchange initialization failed: {result}");
            }

            return publicKey;
        }

        /// <summary>
        /// Processes a key exchange response (client side)
        /// </summary>
        /// <param name="ciphertext">Ciphertext from the server</param>
        public void ProcessKeyExchange(byte[] ciphertext)
        {
            var result = (PqcErrorCode)pqc_process_key_exchange(_handle, ciphertext, (uint)ciphertext.Length);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Key exchange processing failed: {result}");
            }
        }

        /// <summary>
        /// Accepts a key exchange (server side)
        /// </summary>
        /// <param name="clientPublicKey">Client's public key</param>
        /// <returns>Ciphertext to send to the client</returns>
        public byte[] AcceptKeyExchange(byte[] clientPublicKey)
        {
            var ciphertext = new byte[KYBER_CIPHERTEXT_BYTES];
            uint ciphertextLen = (uint)ciphertext.Length;

            var result = (PqcErrorCode)pqc_accept_key_exchange(
                _handle, clientPublicKey, (uint)clientPublicKey.Length, ciphertext, ref ciphertextLen);
            
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Key exchange acceptance failed: {result}");
            }

            return ciphertext;
        }

        /// <summary>
        /// Gets the local verification key
        /// </summary>
        /// <returns>Verification key to share with the remote party</returns>
        public byte[] GetLocalVerificationKey()
        {
            var key = new byte[DILITHIUM_PUBLIC_KEY_BYTES];
            uint keyLen = (uint)key.Length;

            var result = (PqcErrorCode)pqc_get_local_verification_key(_handle, key, ref keyLen);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Failed to get local verification key: {result}");
            }

            return key;
        }

        /// <summary>
        /// Sets the remote verification key
        /// </summary>
        /// <param name="key">Verification key from the remote party</param>
        public void SetRemoteVerificationKey(byte[] key)
        {
            var result = (PqcErrorCode)pqc_set_remote_verification_key(_handle, key, (uint)key.Length);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Failed to set remote verification key: {result}");
            }
        }

        /// <summary>
        /// Completes the authentication process
        /// </summary>
        public void CompleteAuthentication()
        {
            var result = (PqcErrorCode)pqc_complete_authentication(_handle);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Authentication completion failed: {result}");
            }
        }

        /// <summary>
        /// Encrypts and signs data
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted and signed message</returns>
        public byte[] EncryptAndSign(byte[] data)
        {
            // Allocate buffer for encrypted message (data size + overhead)
            uint bufferSize = (uint)(data.Length + 1024); // Allow for header, authentication tag, and signature
            var message = new byte[bufferSize];
            
            var result = (PqcErrorCode)pqc_encrypt_and_sign(_handle, data, (uint)data.Length, message, ref bufferSize);
            
            if (result == PqcErrorCode.IoError)
            {
                // Buffer too small, resize and try again
                message = new byte[bufferSize];
                result = (PqcErrorCode)pqc_encrypt_and_sign(_handle, data, (uint)data.Length, message, ref bufferSize);
            }
            
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Encryption and signing failed: {result}");
            }

            // Resize to actual length
            Array.Resize(ref message, (int)bufferSize);
            return message;
        }

        /// <summary>
        /// Verifies and decrypts a message
        /// </summary>
        /// <param name="message">Encrypted and signed message</param>
        /// <returns>Decrypted data</returns>
        public byte[] VerifyAndDecrypt(byte[] message)
        {
            // Allocate buffer for decrypted data (message size - overhead)
            uint bufferSize = (uint)message.Length;
            var data = new byte[bufferSize];
            
            var result = (PqcErrorCode)pqc_verify_and_decrypt(_handle, message, (uint)message.Length, data, ref bufferSize);
            
            if (result == PqcErrorCode.IoError)
            {
                // Buffer too small, resize and try again
                data = new byte[bufferSize];
                result = (PqcErrorCode)pqc_verify_and_decrypt(_handle, message, (uint)message.Length, data, ref bufferSize);
            }
            
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Verification and decryption failed: {result}");
            }

            // Resize to actual length
            Array.Resize(ref data, (int)bufferSize);
            return data;
        }

        /// <summary>
        /// Generates an acknowledgment message
        /// </summary>
        /// <param name="seqNum">Sequence number to acknowledge</param>
        /// <returns>Acknowledgment message</returns>
        public byte[] GenerateAck(uint seqNum)
        {
            var ack = new byte[14]; // Header size (10) + uint (4)
            uint ackLen = (uint)ack.Length;
            
            var result = (PqcErrorCode)pqc_generate_ack(_handle, seqNum, ack, ref ackLen);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Acknowledgment generation failed: {result}");
            }

            return ack;
        }

        /// <summary>
        /// Closes the session
        /// </summary>
        /// <returns>Close message to send to the remote party</returns>
        public byte[] Close()
        {
            var close = new byte[10]; // Header size (10)
            uint closeLen = (uint)close.Length;
            
            var result = (PqcErrorCode)pqc_close(_handle, close, ref closeLen);
            if (result != PqcErrorCode.Success)
            {
                throw new Exception($"Session close failed: {result}");
            }

            return close;
        }

        /// <summary>
        /// Disposes resources
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases resources
        /// </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_handle != IntPtr.Zero)
                {
                    pqc_destroy_session(_handle);
                    _handle = IntPtr.Zero;
                }
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~PqcSession()
        {
            Dispose(false);
        }
    }

    /// <summary>
    /// Helper for streaming large data in chunks
    /// </summary>
    public class PqcStreamSender
    {
        private readonly PqcSession _session;
        private readonly int _chunkSize;

        /// <summary>
        /// Creates a new stream sender
        /// </summary>
        /// <param name="session">PQC session</param>
        /// <param name="chunkSize">Size of chunks to use (default: 16384)</param>
        public PqcStreamSender(PqcSession session, int chunkSize = 16384)
        {
            _session = session;
            _chunkSize = chunkSize;
        }

        /// <summary>
        /// Streams data in chunks
        /// </summary>
        /// <param name="data">Data to stream</param>
        /// <returns>Enumerable of encrypted chunks</returns>
        public IEnumerable<byte[]> StreamData(byte[] data)
        {
            for (int offset = 0; offset < data.Length; offset += _chunkSize)
            {
                int chunkSize = Math.Min(_chunkSize, data.Length - offset);
                byte[] chunk = new byte[chunkSize];
                Array.Copy(data, offset, chunk, 0, chunkSize);
                
                yield return _session.EncryptAndSign(chunk);
            }
        }

        /// <summary>
        /// Gets the chunk size
        /// </summary>
        public int ChunkSize => _chunkSize;
    }

    /// <summary>
    /// Helper for receiving streamed data
    /// </summary>
    public class PqcStreamReceiver
    {
        private readonly PqcSession _session;
        private List<byte> _buffer;

        /// <summary>
        /// Creates a new stream receiver
        /// </summary>
        /// <param name="session">PQC session</param>
        /// <param name="enableReassembly">Whether to enable reassembly of chunks</param>
        public PqcStreamReceiver(PqcSession session, bool enableReassembly = false)
        {
            _session = session;
            _buffer = enableReassembly ? new List<byte>() : null;
        }

        /// <summary>
        /// Processes a received chunk
        /// </summary>
        /// <param name="chunk">Encrypted chunk</param>
        /// <returns>Decrypted data</returns>
        public byte[] ProcessChunk(byte[] chunk)
        {
            byte[] data = _session.VerifyAndDecrypt(chunk);
            
            if (_buffer != null)
            {
                _buffer.AddRange(data);
            }
            
            return data;
        }

        /// <summary>
        /// Enables reassembly of chunks
        /// </summary>
        public void EnableReassembly()
        {
            if (_buffer == null)
            {
                _buffer = new List<byte>();
            }
        }

        /// <summary>
        /// Disables reassembly of chunks
        /// </summary>
        public void DisableReassembly()
        {
            _buffer = null;
        }

        /// <summary>
        /// Gets the reassembled data
        /// </summary>
        /// <returns>Reassembled data, or null if reassembly is disabled</returns>
        public byte[] GetReassembledData()
        {
            return _buffer?.ToArray();
        }

        /// <summary>
        /// Takes ownership of the reassembled data and clears the buffer
        /// </summary>
        /// <returns>Reassembled data, or null if reassembly is disabled</returns>
        public byte[] TakeReassembledData()
        {
            if (_buffer == null)
            {
                return null;
            }
            
            byte[] data = _buffer.ToArray();
            _buffer.Clear();
            return data;
        }
    }
}