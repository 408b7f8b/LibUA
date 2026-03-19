using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using LibUA.Core;

namespace LibUA
{
    public class Client : IDisposable
    {
        // Message type, message size, secure channel ID, security token ID
        private const int MessageEncodedBlockStart = 16;
        private const int ChunkHeaderOverhead = 4 * 6;
        private const int TLPaddingOverhead = 1024;

        public delegate void ConnectionClosed();
        public event ConnectionClosed OnConnectionClosed = null;

        public const int ListenerInterval = 100;

        public readonly string Target;
        public readonly int Port;
        public readonly string Path;

        public readonly int Timeout;

        protected SLChannel config = null;
        private int MaximumMessageSize;
        private Semaphore cs = null;
        private Semaphore csDispatching = null;
        private Semaphore csWaitForSecure = null;
        private uint nextRequestHandle = 0;

        protected TcpClient tcp = null;

        protected Thread thread = null;
        private bool threadAbort = false;
        private long totalBytesSent = 0, totalBytesRecv = 0;
        private System.Timers.Timer renewTimer = null;

        private class RecvHandler
        {
            public MemoryBuffer RecvBuf { get; set; }
            public NodeId Type { get; set; }
            public ResponseHeader Header { get; set; }
        }

        private Dictionary<Tuple<uint, uint>, RecvHandler> recvQueue = null;
        private Dictionary<Tuple<uint, uint>, ManualResetEvent> recvNotify = null;
        private volatile StatusCode recvHandlerStatus;
        private volatile bool nextPublish = false;
        private HashSet<uint> publishReqs = null;
        private readonly ConcurrentQueue<(uint subscriptionId, uint sequenceNumber)> pendingAcknowledgements = new();

        public int MaxOutstandingPublishRequests { get; set; } = 2;
        private readonly Lock syncLock = new();
        private readonly Lock recvQueueLock = new();
        private readonly Lock recvNotifyLock = new();
        private readonly Lock publishReqsLock = new();

        public virtual X509Certificate2 ApplicationCertificate
        {
            get { return null; }
        }

        public virtual RSA ApplicationPrivateKey
        {
            get { return null; }
        }

        public long TotalBytesSent
        {
            get { return totalBytesSent; }
        }

        public long TotalBytesRecv
        {
            get { return totalBytesRecv; }
        }

        public uint? TokenLifetime
        {
            get { return config?.TokenLifetime; }
        }

        public bool IsConnected
        {
            get
            {
                lock (syncLock)
                {
                    return tcp != null && tcp.Connected;
                }
            }
        }

        public bool CanReconnect
        {
            get { return !IsConnected && config?.AuthToken is not null; }
        }

        /// <summary>
        /// Certificate validation options. Set before connecting to enable validation.
        /// Default: null (no validation, backward compatible).
        /// </summary>
        public UASecurity.CertificateValidationOptions CertificateValidation { get; set; }

        /// <summary>
        /// Send buffer size proposed in the Hello message. Some PLCs (e.g., Siemens S7-1500)
        /// require 8192 and reject the default 65536. Set before calling Connect().
        /// Default: 65536.
        /// </summary>
        public uint HelloSendBufferSize { get; set; } = 1 << 16;

        /// <summary>
        /// Receive buffer size proposed in the Hello message. Some PLCs (e.g., Siemens S7-1500)
        /// require 8192 and reject the default 65536. Set before calling Connect().
        /// Default: 65536.
        /// </summary>
        public uint HelloRecvBufferSize { get; set; } = 1 << 16;

        /// <summary>
        /// Registry for custom DataType definitions. Populated by LoadDataTypeDefinition() or LoadDataTypesForNamespace().
        /// Used to automatically decode ExtensionObjects with custom structured types.
        /// </summary>
        public LibUA.ValueTypes.DataTypeRegistry TypeRegistry { get; } = new LibUA.ValueTypes.DataTypeRegistry();

        public Client(string Target, int Port, int Timeout, int MaximumMessageSize = 1 << 18)
            : this(Target, Port, null, Timeout, MaximumMessageSize)
        {

        }

        public Client(string Target, int Port, string Path, int Timeout, int MaximumMessageSize = 1 << 18)
        {
            this.Target = Target;
            this.Port = Port;
            this.Path = Path;
            this.Timeout = Timeout;
            this.MaximumMessageSize = MaximumMessageSize;
        }

        public StatusCode OpenSecureChannel(MessageSecurityMode messageSecurityMode, SecurityPolicy securityPolicy, byte[] serverCert)
        {
            config.SecurityPolicy = securityPolicy;
            config.MessageSecurityMode = messageSecurityMode;
            config.RemoteCertificateString = serverCert;

            try
            {
                config.RemoteCertificate = new X509Certificate2(serverCert);
            }
            catch (CryptographicException)
            {
                return StatusCode.BadCertificateInvalid;
            }

            try
            {
                return OpenSecureChannelInternal(false);
            }
            finally
            {
                csWaitForSecure.Release();
            }
        }

        public StatusCode RenewSecureChannel()
        {
            try
            {
                return OpenSecureChannelInternal(true);
            }
            finally
            {
                csWaitForSecure.Release();
            }
        }

        private StatusCode OpenSecureChannelInternal(bool renew)
        {
            SecurityTokenRequestType requestType = renew ?
                SecurityTokenRequestType.Renew : SecurityTokenRequestType.Issue;

            try
            {
                cs.WaitOne();

                using var sendBuf = new MemoryBuffer(MaximumMessageSize);

                if (requestType == SecurityTokenRequestType.Issue)
                {
                    config.ChannelID = 0;
                }

                bool succeeded = true;
                succeeded &= sendBuf.Encode((uint)(MessageType.Open) | ((uint)'F' << 24));
                succeeded &= sendBuf.Encode((uint)0);
                succeeded &= sendBuf.Encode(config.ChannelID);
                succeeded &= sendBuf.EncodeUAString(Types.SLSecurityPolicyUris[(int)config.SecurityPolicy]);
                if (config.SecurityPolicy == SecurityPolicy.None)
                {
                    succeeded &= sendBuf.EncodeUAByteString(null);
                    succeeded &= sendBuf.EncodeUAByteString(null);
                }
                else
                {
                    var certStr = ApplicationCertificate.Export(X509ContentType.Cert);
                    // OPC UA Part 6, 6.7.2.3: Thumbprint uses SHA-1 (20 bytes) regardless of security policy
                    var serverCertThumbprint = UASecurity.SHACalculate(config.RemoteCertificateString, SecurityPolicy.Basic128Rsa15);

                    succeeded &= sendBuf.EncodeUAByteString(certStr);
                    succeeded &= sendBuf.EncodeUAByteString(serverCertThumbprint);
                }

                int asymCryptFrom = sendBuf.Position;

                if (requestType == SecurityTokenRequestType.Issue)
                {
                    // OPC UA Part 6, 6.7.2: Initial sequence number should be random
                    config.LocalSequence = new SLSequence()
                    {
                        SequenceNumber = (uint)(System.Security.Cryptography.RandomNumberGenerator.GetInt32(1, 1024)),
                        RequestId = 1,
                    };
                }

                succeeded &= sendBuf.Encode(config.LocalSequence.SequenceNumber);
                succeeded &= sendBuf.Encode(config.LocalSequence.RequestId);

                succeeded &= sendBuf.Encode(new NodeId(RequestCode.OpenSecureChannelRequest));

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                UInt32 clientProtocolVersion = 0;
                UInt32 securityTokenRequestType = (uint)requestType;
                UInt32 messageSecurityMode = (uint)config.MessageSecurityMode;
                byte[] clientNonce = null;
                UInt32 reqLifetime = 300 * 1000;

                if (config.SecurityPolicy != SecurityPolicy.None)
                {
                    int nonceSize = UASecurity.NonceLengthForSecurityPolicy(config.SecurityPolicy);
                    clientNonce = UASecurity.GenerateRandomBytes(nonceSize);
                }

                succeeded &= sendBuf.Encode(reqHeader);
                succeeded &= sendBuf.Encode(clientProtocolVersion);
                succeeded &= sendBuf.Encode(securityTokenRequestType);
                succeeded &= sendBuf.Encode(messageSecurityMode);
                succeeded &= sendBuf.EncodeUAByteString(clientNonce);
                succeeded &= sendBuf.Encode(reqLifetime);

                config.LocalNonce = clientNonce;

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                if (config.SecurityPolicy == SecurityPolicy.None)
                {
                    MarkPositionAsSize(sendBuf);
                }
                else
                {
                    var padMethod = UASecurity.PaddingMethodForSecurityPolicy(config.SecurityPolicy);
                    int sigSize = UASecurity.CalculateSignatureSize(ApplicationCertificate);

                    if (config.RemoteCertificate.GetRSAPublicKey().KeySize <= 2048)
                    {
                        int padSize = UASecurity.CalculatePaddingSize(config.RemoteCertificate, config.SecurityPolicy, sendBuf.Position - asymCryptFrom + 1, sigSize);
                        if (padSize > 0)
                        {
                            byte paddingValue = (byte)(padSize & 0xFF);

                            var appendPadding = new byte[padSize + 1];
                            for (int i = 0; i <= padSize; i++) { appendPadding[i] = paddingValue; }
                            sendBuf.Append(appendPadding);
                        }
                    }
                    else
                    {
                        int padSize = UASecurity.CalculatePaddingSize(config.RemoteCertificate, config.SecurityPolicy, sendBuf.Position - asymCryptFrom + 2, sigSize);
                        if (padSize > 0)
                        {
                            byte paddingValue = (byte)(padSize & 0xFF);

                            var appendPadding = new byte[padSize + 2];
                            for (int i = 0; i <= padSize; i++) { appendPadding[i] = paddingValue; }
                            appendPadding[padSize + 1] = (byte)(padSize >> 8);
                            sendBuf.Append(appendPadding);
                        }
                    }

                    int respSize = sendBuf.Position + sigSize;

                    respSize = asymCryptFrom + UASecurity.CalculateEncryptedSize(config.RemoteCertificate, respSize - asymCryptFrom, padMethod);
                    MarkPositionAsSize(sendBuf, (UInt32)respSize);

                    var msgSign = UASecurity.Sign(new ArraySegment<byte>(sendBuf.Buffer, 0, sendBuf.Position),
                        ApplicationPrivateKey, config.SecurityPolicy);
                    sendBuf.Append(msgSign);

                    var packed = UASecurity.Encrypt(
                        new ArraySegment<byte>(sendBuf.Buffer, asymCryptFrom, sendBuf.Position - asymCryptFrom),
                        config.RemoteCertificate, UASecurity.UseOaepForSecurityPolicy(config.SecurityPolicy));

                    sendBuf.Position = asymCryptFrom;
                    sendBuf.Append(packed);

                    if (sendBuf.Position != respSize)
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Open, 0);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                tcp.Client.Send(sendBuf.Buffer, sendBuf.Position, SocketFlags.None);
                Interlocked.Add(ref totalBytesSent, sendBuf.Position);

                config.LocalSequence.SequenceNumber++;
                uint reqId = config.LocalSequence.RequestId++;

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    var key = new Tuple<uint, uint>((uint)MessageType.Open, 0);
                    if (!recvQueue.TryGetValue(key, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(key);
                }

                if (!recvHandler.RecvBuf.Decode(out uint secureChannelId)) { return StatusCode.BadDecodingError; }

                if (!recvHandler.RecvBuf.DecodeUAString(out string securityPolicyUri)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.DecodeUAByteString(out byte[] senderCertificate)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.DecodeUAByteString(out byte[] recvCertThumbprint)) { return StatusCode.BadDecodingError; }

                try
                {
                    if (securityPolicyUri != Types.SLSecurityPolicyUris[(int)config.SecurityPolicy])
                    {
                        return StatusCode.BadSecurityPolicyRejected;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    return StatusCode.BadSecurityPolicyRejected;
                }

                // Check in the middle for buffer decrypt
                if (config.SecurityPolicy != SecurityPolicy.None)
                {
                    try
                    {

                        config.RemoteCertificate = new X509Certificate2(senderCertificate);

                        // Use full validation if configured, otherwise backward-compatible null check
                        if (CertificateValidation != null)
                        {
                            var validationResult = UASecurity.ValidateCertificate(config.RemoteCertificate, CertificateValidation);
                            if (validationResult != StatusCode.Good)
                            {
                                return validationResult;
                            }
                        }
                        else if (!UASecurity.VerifyCertificate(config.RemoteCertificate))
                        {
                            return StatusCode.BadCertificateInvalid;
                        }
                    }
                    catch (CryptographicException)
                    {
                        return StatusCode.BadCertificateInvalid;
                    }

                    var appCertStr = ApplicationCertificate.Export(X509ContentType.Cert);
                    if (!UASecurity.SHAVerify(appCertStr, recvCertThumbprint, SecurityPolicy.Basic128Rsa15))
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }

                    var asymDecBuf = UASecurity.Decrypt(
                        new ArraySegment<byte>(recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position),
                        ApplicationCertificate, ApplicationPrivateKey, UASecurity.UseOaepForSecurityPolicy(config.SecurityPolicy));

                    int minPlainSize = Math.Min(asymDecBuf.Length, recvHandler.RecvBuf.Capacity - recvHandler.RecvBuf.Position);
                    Array.Copy(asymDecBuf, 0, recvHandler.RecvBuf.Buffer, recvHandler.RecvBuf.Position, minPlainSize);
                }

                if (!recvHandler.RecvBuf.Decode(out uint respSequenceNumber)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out uint respRequestId)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out NodeId messageType)) { return StatusCode.BadDecodingError; }

                if (!messageType.EqualsNumeric(0, (uint)RequestCode.OpenSecureChannelResponse))
                {
                    return StatusCode.BadSecureChannelClosed;
                }

                if (!renew)
                {
                    config.RemoteSequence = new SLSequence()
                    {
                        RequestId = respRequestId,
                        SequenceNumber = respSequenceNumber
                    };
                }

                if (!recvHandler.RecvBuf.Decode(out ResponseHeader _)) { return StatusCode.BadDecodingError; }

                if (!recvHandler.RecvBuf.Decode(out uint _)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out uint channelId)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out uint tokenId)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out ulong createAtTimestamp)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.Decode(out uint respLifetime)) { return StatusCode.BadDecodingError; }
                if (!recvHandler.RecvBuf.DecodeUAByteString(out byte[] serverNonce)) { return StatusCode.BadDecodingError; }

                if (renew)
                {
                    config.PrevChannelID = config.ChannelID;
                    config.PrevTokenID = config.TokenID;
                }

                config.ChannelID = channelId;
                config.TokenID = tokenId;
                config.TokenCreatedAt = DateTimeOffset.FromFileTime((long)createAtTimestamp);
                if (config.TokenLifetime == 0)
                {
                    config.TokenLifetime = respLifetime;
                }
                config.RemoteNonce = serverNonce;

                if (config.SecurityPolicy == SecurityPolicy.None)
                {
                    config.LocalKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
                    config.RemoteKeysets = new SLChannel.Keyset[2] { new SLChannel.Keyset(), new SLChannel.Keyset() };
                }
                else
                {
                    int symKeySize = UASecurity.SymmetricKeySizeForSecurityPolicy(config.SecurityPolicy);

                    int sigKeySize = UASecurity.SymmetricSignatureKeySizeForSecurityPolicy(config.SecurityPolicy);
                    int symBlockSize = UASecurity.SymmetricBlockSizeForSecurityPolicy(config.SecurityPolicy);

                    var clientHash = UASecurity.PSHA(
                        config.RemoteNonce,
                        config.LocalNonce,
                        sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

                    var newLocalKeyset = new SLChannel.Keyset(
                        (new ArraySegment<byte>(clientHash, 0, sigKeySize)).ToArray(),
                        (new ArraySegment<byte>(clientHash, sigKeySize, symKeySize)).ToArray(),
                        (new ArraySegment<byte>(clientHash, sigKeySize + symKeySize, symBlockSize)).ToArray());

                    var serverHash = UASecurity.PSHA(
                        config.LocalNonce,
                        config.RemoteNonce,
                        sigKeySize + symKeySize + symBlockSize, config.SecurityPolicy);

                    var newRemoteKeyset = new SLChannel.Keyset(
                        (new ArraySegment<byte>(serverHash, 0, sigKeySize)).ToArray(),
                        (new ArraySegment<byte>(serverHash, sigKeySize, symKeySize)).ToArray(),
                        (new ArraySegment<byte>(serverHash, sigKeySize + symKeySize, symBlockSize)).ToArray());

                    //Console.WriteLine("Local nonce: {0}", string.Join("", config.LocalNonce.Select(v => v.ToString("X2"))));
                    //Console.WriteLine("Remote nonce: {0}", string.Join("", config.RemoteNonce.Select(v => v.ToString("X2"))));

                    //Console.WriteLine("RSymSignKey: {0}", string.Join("", newRemoteKeyset.SymSignKey.Select(v => v.ToString("X2"))));
                    //Console.WriteLine("RSymEncKey: {0}", string.Join("", newRemoteKeyset.SymEncKey.Select(v => v.ToString("X2"))));
                    //Console.WriteLine("RSymIV: {0}", string.Join("", newRemoteKeyset.SymIV.Select(v => v.ToString("X2"))));

                    //Console.WriteLine("LSymSignKey: {0}", string.Join("", newLocalKeyset.SymSignKey.Select(v => v.ToString("X2"))));
                    //Console.WriteLine("LSymEncKey: {0}", string.Join("", newLocalKeyset.SymEncKey.Select(v => v.ToString("X2"))));
                    //Console.WriteLine("LSymIV: {0}", string.Join("", newLocalKeyset.SymIV.Select(v => v.ToString("X2"))));

                    if (config.LocalKeysets == null)
                    {
                        config.LocalKeysets = new SLChannel.Keyset[2] { newLocalKeyset, new SLChannel.Keyset() };
                        config.RemoteKeysets = new SLChannel.Keyset[2] { newRemoteKeyset, new SLChannel.Keyset() };
                    }
                    else
                    {
                        config.LocalKeysets = new SLChannel.Keyset[2] { newLocalKeyset, config.LocalKeysets[0] };
                        config.RemoteKeysets = new SLChannel.Keyset[2] { newRemoteKeyset, config.RemoteKeysets[0] };
                    }
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();

                if (!renew)
                {
                    CheckPostCall();
                }
            }
        }

        public StatusCode CloseSecureChannel()
        {
            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false, MessageType.Close);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = new NodeId((uint)0),
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CloseSecureChannelRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        private StatusCode EncodeMessageHeader(MemoryBuffer sendBuf, bool needsEstablishedSL = true, MessageType messageType = MessageType.Message)
        {
            if (config.SLState != ConnectionState.Established && needsEstablishedSL)
            {
                return StatusCode.BadSecureChannelClosed;
            }

            bool succeeded = true;
            succeeded &= sendBuf.Encode((uint)(messageType) | ((uint)'F' << 24));
            succeeded &= sendBuf.Encode((uint)0);
            succeeded &= sendBuf.Encode(config.ChannelID);
            succeeded &= sendBuf.Encode(config.TokenID);
            succeeded &= sendBuf.Encode(config.LocalSequence.SequenceNumber);
            succeeded &= sendBuf.Encode(config.LocalSequence.RequestId);

            if (!succeeded)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            config.LocalSequence.SequenceNumber++;
            config.LocalSequence.RequestId++;

            return StatusCode.Good;
        }

        public StatusCode GetEndpoints(out EndpointDescription[] endpointDescs, string[] localeIDs)
        {
            endpointDescs = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.GetEndpointsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.EncodeUAString(GetEndpointString());
                // LocaleIds
                succeeded &= sendBuf.EncodeUAString(localeIDs);
                // ProfileUris
                succeeded &= sendBuf.Encode((UInt32)0);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.GetEndpointsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numEndpointDescs);

                endpointDescs = new EndpointDescription[numEndpointDescs];
                for (int i = 0; i < numEndpointDescs && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out endpointDescs[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode FindServers(out ApplicationDescription[] results, string[] localeIDs)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.FindServersRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.EncodeUAString(GetEndpointString());
                // LocaleIds
                succeeded &= sendBuf.EncodeUAString(localeIDs);
                // ProfileIds
                succeeded &= sendBuf.Encode((UInt32)0);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.FindServersResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numDescs);

                results = new ApplicationDescription[numDescs];
                for (int i = 0; i < numDescs && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        private StatusCode MessageSecureAndSend(SLChannel config, MemoryBuffer respBuf)
        {
            // TL header, sequence header
            const int ChunkHeaderOverhead = 4 * 6;
            const int seqPosition = 4 * 4;

            int chunkSize = (int)config.TL.TransportConfig.RecvBufferSize - ChunkHeaderOverhead - TLPaddingOverhead;
            //int chunkSize = 2048 - ChunkHeaderOverhead - TLPaddingOverhead;
            int numChunks = (respBuf.Position - ChunkHeaderOverhead + chunkSize - 1) / chunkSize;

            if (numChunks > 1 && config.TL.TransportConfig.MaxChunkCount > 0 &&
                numChunks > config.TL.TransportConfig.MaxChunkCount)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            if (numChunks > 1)
            {
                //Console.WriteLine("{0} -> {1} chunks", respBuf.Position, numChunks);
                using var chunk = new MemoryBuffer(chunkSize + ChunkHeaderOverhead + TLPaddingOverhead);
                for (int i = 0; i < numChunks; i++)
                {
                    bool isFinal = i == numChunks - 1;

                    chunk.Rewind();
                    int offset = i * chunkSize;
                    int curSize = isFinal ?
                        respBuf.Position - ChunkHeaderOverhead - offset :
                        chunkSize;

                    chunk.Append(respBuf.Buffer, 0, ChunkHeaderOverhead);
                    if (i > 0)
                    {
                        chunk.Encode(config.LocalSequence.SequenceNumber, seqPosition);
                        config.LocalSequence.SequenceNumber++;
                    }

                    chunk.Buffer[3] = isFinal ? (byte)'F' : (byte)'C';
                    chunk.Append(respBuf.Buffer, ChunkHeaderOverhead + offset, curSize);

                    if (config.MessageSecurityMode == MessageSecurityMode.None)
                    {
                        MarkPositionAsSize(chunk);
                    }
                    else
                    {
                        var secureRes = UASecurity.SecureSymmetric(chunk, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

                        if (!Types.StatusCodeIsGood((uint)secureRes))
                        {
                            return secureRes;
                        }
                    }

                    tcp.Client.Send(chunk.Buffer, chunk.Position, SocketFlags.None);
                    Interlocked.Add(ref totalBytesSent, chunk.Position);
                }
            }
            else
            {
                if (config.MessageSecurityMode == MessageSecurityMode.None)
                {
                    MarkPositionAsSize(respBuf);
                }
                else
                {
                    var secureRes = UASecurity.SecureSymmetric(respBuf, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets[0], config.SecurityPolicy, config.MessageSecurityMode);

                    if (!Types.StatusCodeIsGood((uint)secureRes))
                    {
                        return secureRes;
                    }
                }

                if (!IsConnected)
                {
                    return StatusCode.BadConnectionClosed;
                }

                tcp.Client.Send(respBuf.Buffer, respBuf.Position, SocketFlags.None);
                Interlocked.Add(ref totalBytesSent, respBuf.Position);
            }

            return StatusCode.Good;
        }

        public StatusCode Connect()
        {
            return Connect(false);
        }

        public StatusCode Connect(bool reuseSession)
        {
            if (IsConnected)
            {
                throw new InvalidOperationException("Disconnect before connecting again.");
            }

            cs = new Semaphore(1, 1);

            try
            {
                cs.WaitOne();

                totalBytesSent = 0;
                totalBytesRecv = 0;

                try
                {
                    tcp = new TcpClient();
                    var ar = tcp.BeginConnect(Target, Port, null, null);

                    // Wait for completion or timeout
                    var success = ar.AsyncWaitHandle.WaitOne(Timeout * 1000);
                    if (!success)
                    {
                        tcp.Close();
                        throw new SocketException();
                    }

                    // Ensure connection is completed
                    tcp.EndConnect(ar);
                }
                catch (SocketException)
                {
                    return StatusCode.BadConnectionRejected;
                }

                csDispatching = new Semaphore(1, 1);
                csWaitForSecure = new Semaphore(0, 1);

                nextRequestHandle = 0;

                tcp.NoDelay = true;
                tcp.Client.NoDelay = true;
                tcp.ReceiveTimeout = Timeout * 1000;
                tcp.SendTimeout = Timeout * 1000;

                // If session should be reused, and we have an AuthToken, reuse the config:
                if (reuseSession && config?.AuthToken is not null)
                {
                    config.Endpoint = tcp.Client.RemoteEndPoint as IPEndPoint;
                    config.SLState = ConnectionState.Opening;
                }
                else
                {
                    config = new SLChannel
                    {
                        Endpoint = tcp.Client.RemoteEndPoint as IPEndPoint,
                        SLState = ConnectionState.Opening
                    };
                }

                recvQueue = new Dictionary<Tuple<uint, uint>, RecvHandler>();
                recvNotify = new Dictionary<Tuple<uint, uint>, ManualResetEvent>();
                publishReqs = new HashSet<uint>();

                recvHandlerStatus = StatusCode.Good;

                threadAbort = false;
                thread = new Thread(new ParameterizedThreadStart(ThreadTarget));
                thread.Start(this);

                var ret = SendHello();
                if (ret != StatusCode.Good)
                {
                    return ret;
                }

                return ret;
            }
            finally
            {
                cs.Release();
            }
        }

        private StatusCode SendHello()
        {
            using var sendBuf = new MemoryBuffer(MaximumMessageSize);

            config.TL = new TLConnection
            {
                TransportConfig = new TLConfiguration()
                {
                    ProtocolVersion = 0,
                    SendBufferSize = HelloSendBufferSize,
                    RecvBufferSize = HelloRecvBufferSize,
                    MaxMessageSize = (uint)MaximumMessageSize,
                    MaxChunkCount = 0, // 0 = no limit per OPC UA Part 6
                }
            };

            bool succeeded = true;
            succeeded &= sendBuf.Encode((uint)(MessageType.Hello) | ((uint)'F' << 24));
            succeeded &= sendBuf.Encode((uint)0);
            succeeded &= sendBuf.Encode(config.TL.TransportConfig.ProtocolVersion);
            succeeded &= sendBuf.Encode(config.TL.TransportConfig.RecvBufferSize);
            succeeded &= sendBuf.Encode(config.TL.TransportConfig.SendBufferSize);
            succeeded &= sendBuf.Encode(config.TL.TransportConfig.MaxMessageSize);
            succeeded &= sendBuf.Encode(config.TL.TransportConfig.MaxChunkCount);
            succeeded &= sendBuf.EncodeUAString(GetEndpointString());

            if (!succeeded)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            MarkPositionAsSize(sendBuf);

            var recvKey = new Tuple<uint, uint>((uint)MessageType.Acknowledge, 0);
            var recvEv = new ManualResetEvent(false);
            lock (recvNotifyLock)
            {
                recvNotify[recvKey] = recvEv;
            }

            tcp.Client.Send(sendBuf.Buffer, sendBuf.Position, SocketFlags.None);
            Interlocked.Add(ref totalBytesSent, sendBuf.Position);

            bool signalled = recvEv.WaitOne(Timeout * 1000);

            lock (recvNotifyLock)
            {
                recvNotify.Remove(recvKey);
            }

            if (recvHandlerStatus != StatusCode.Good)
            {
                return recvHandlerStatus;
            }

            if (!signalled)
            {
                return StatusCode.BadRequestTimeout;
            }

            RecvHandler recvHandler;
            lock (recvQueueLock)
            {
                var key = new Tuple<uint, uint>((uint)MessageType.Acknowledge, 0);
                if (!recvQueue.TryGetValue(key, out recvHandler))
                {
                    return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                }

                recvQueue.Remove(key);
            }

            config.TL.TransportConfig = new TLConfiguration();
            if (!recvHandler.RecvBuf.Decode(out config.TL.TransportConfig.ProtocolVersion)) { return StatusCode.BadDecodingError; }
            if (!recvHandler.RecvBuf.Decode(out config.TL.TransportConfig.RecvBufferSize)) { return StatusCode.BadDecodingError; }
            if (!recvHandler.RecvBuf.Decode(out config.TL.TransportConfig.SendBufferSize)) { return StatusCode.BadDecodingError; }
            if (!recvHandler.RecvBuf.Decode(out config.TL.TransportConfig.MaxMessageSize)) { return StatusCode.BadDecodingError; }
            if (!recvHandler.RecvBuf.Decode(out config.TL.TransportConfig.MaxChunkCount)) { return StatusCode.BadDecodingError; }

            // OPC UA Part 6: MaxMessageSize=0 means no limit
            if (config.TL.TransportConfig.MaxMessageSize > 0)
            {
                MaximumMessageSize = (int)Math.Min(config.TL.TransportConfig.MaxMessageSize, MaximumMessageSize);
            }

            //if (!signalled)
            //{
            //	RemovePendingRequest(RequestId);

            //	// Clear if received between Wait and Remove
            //	if (semRecvMsg.WaitOne(0))
            //	{
            //		// Clean up message
            //		RemovePendingRequest(RequestId);
            //	}

            //	return DXPStatusCode.BadNoResponse;
            //}

            return StatusCode.Good;
        }

        private string GetEndpointString()
        {
            string endpointString;
            if (string.IsNullOrWhiteSpace(Path))
            {
                endpointString = string.Format("opc.tcp://{0}:{1}", Target, config.Endpoint.Port.ToString());
            }
            else
            {
                endpointString = string.Format("opc.tcp://{0}:{1}/{2}", Target, config.Endpoint.Port.ToString(), Path);
            }

            return endpointString;
        }

        protected void MarkPositionAsSize(MemoryBuffer mb, UInt32 position)
        {
            int restorePos = mb.Position;
            mb.Position = 4;
            mb.Encode(position);
            mb.Position = restorePos;
        }

        // Skip MessageType and ChunkType, write MessageSize
        protected void MarkPositionAsSize(MemoryBuffer mb)
        {
            UInt32 pos = (UInt32)mb.Position;
            mb.Position = 4;
            mb.Encode(pos);
            mb.Position = (int)pos;
        }

        public void Dispose()
        {
            Disconnect();
        }

        public StatusCode Disconnect()
        {
            nextPublish = false;

            System.Timers.Timer timerToStop = null;
            lock (syncLock)
            {
                if (renewTimer != null)
                {
                    timerToStop = renewTimer;
                    renewTimer = null;
                }
            }

            if (timerToStop != null)
            {
                timerToStop.Stop();
            }

            if (thread != null)
            {
                if (config.SessionIdToken != null)
                {
                    CloseSession();
                }
                if (config.ChannelID > 0)
                {
                    CloseSecureChannel();
                }

                threadAbort = true;

                thread.Join();
                thread = null;
            }

            return StatusCode.Good;
        }

        private void CloseConnection()
        {
            try
            {
                if (tcp != null)
                {
                    tcp.Client.Shutdown(SocketShutdown.Both);
                    tcp.Close();

                    OnConnectionClosed?.Invoke();
                }
            }
            catch (SocketException)
            {
                // Disconnected
            }
            finally
            {
                tcp = null;
            }
        }

        ~Client() { Dispose(); }

        private static void ThreadTarget(object args)
        {
            (args as Client).ThreadTarget();
        }

        private void ThreadTarget()
        {
            var socket = tcp.Client;

            int recvAccumSize = 0;
            var recvBuffer = new byte[MaximumMessageSize];

            while (IsConnected)
            {
                if (threadAbort)
                {
                    break;
                }

                var checkRead = new List<Socket> { socket };
                var checkError = new List<Socket> { socket };
                Socket.Select(checkRead, null, checkError, ListenerInterval * 1000);

                if (checkError.Count > 0)
                {
                    break;
                }

                if (checkRead.Count == 0)
                {
                    continue;
                }

                int bytesAvailable = MaximumMessageSize - recvAccumSize;

                int bytesRead;
                if (bytesAvailable > 0)
                {
                    try
                    {
                        bytesRead = socket.Receive(recvBuffer, recvAccumSize, bytesAvailable, SocketFlags.None);
                    }
                    catch (SocketException)
                    {
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }

                    if (bytesRead == 0)
                    {
                        // Disconnected
                        break;
                    }

                    Interlocked.Add(ref totalBytesRecv, bytesRead);
                }
                else
                {
                    break;
                }

                recvAccumSize += bytesRead;
                if (recvAccumSize > MaximumMessageSize)
                {
                    break;
                }

                while (recvAccumSize > 0)
                {
                    csDispatching.WaitOne();
                    int consumedSize = -1;

                    try
                    {
                        //var sw = new System.Diagnostics.Stopwatch();
                        //sw.Start();
                        consumedSize = Consume(config, new MemoryBuffer(recvBuffer, recvAccumSize));
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                    {
                        recvHandlerStatus = StatusCode.BadDecodingError;
                        consumedSize = -1;
                    }
                    finally
                    {
                        csDispatching.Release();
                    }

                    if (consumedSize == -1)
                    {
                        // Handler failed
                        recvAccumSize = -1;
                        break;
                    }
                    else if (consumedSize == 0)
                    {
                        // Not enough to read a message
                        break;
                    }
                    else if (consumedSize >= recvAccumSize)
                    {
                        if (consumedSize > recvAccumSize)
                        {
                            throw new InvalidOperationException(string.Format("Consumed {0} but accumulated message size is {1}", consumedSize, recvAccumSize));
                        }

                        recvAccumSize = 0;
                    }
                    else
                    {
                        int newSize = recvAccumSize - consumedSize;

                        var newRecvBuffer = new byte[MaximumMessageSize];
                        Array.Copy(recvBuffer, consumedSize, newRecvBuffer, 0, newSize);
                        recvBuffer = newRecvBuffer;

                        recvAccumSize = newSize;
                    }
                }

                CheckPostCall();

                // Cannot receive more or process existing
                if (recvAccumSize == -1 || recvAccumSize >= MaximumMessageSize)
                {
                    break;
                }
            }

            CloseConnection();

            //if (DXPStatusCode.IsGood(connStatus))
            //{
            //	connStatus = DXPStatusCode.BadNotConnected;
            //}

            // Fail any pending calls with connStatus
            //semRecvMsg.Release();

            lock (recvNotifyLock)
            {
                foreach (var kvp in recvNotify)
                {
                    kvp.Value.Set();
                }
            }

            lock (recvQueueLock)
            {
                foreach (var kvp in recvQueue)
                {
                    if (recvNotify.TryGetValue(kvp.Key, out ManualResetEvent ev))
                    {
                        ev.Set();
                    }
                }
            }
        }

        private void CheckPostCall()
        {
            if (nextPublish)
            {
                if (PublishRequest() != StatusCode.GoodCallAgain)
                {
                    nextPublish = false;
                }
            }
        }

        private bool ChunkReconstruct(MemoryBuffer buf, List<uint> chunkLengths)
        {
            if (buf.Capacity < ChunkHeaderOverhead)
            {
                return false;
            }

            uint totalLength = 0;
            for (int i = 0; i < chunkLengths.Count; i++)
            {
                if (i == 0)
                {
                    totalLength += chunkLengths[i];
                }
                else
                {
                    if (chunkLengths[i] < ChunkHeaderOverhead)
                    {
                        return false;
                    }

                    totalLength += chunkLengths[i] - ChunkHeaderOverhead;
                }
            }

            uint readOffset = 0, writeOffset = ChunkHeaderOverhead;
            for (int i = 0; i < chunkLengths.Count; i++)
            {
                uint len = chunkLengths[i];

                if (i > 0)
                {
                    Array.Copy(buf.Buffer, (int)(readOffset + ChunkHeaderOverhead), buf.Buffer, (int)writeOffset, (int)(len - ChunkHeaderOverhead));
                }

                readOffset += len;
                writeOffset += len - ChunkHeaderOverhead;
            }

            buf.Buffer[3] = (byte)'F';
            MarkPositionAsSize(buf, totalLength);

            return true;
        }

        private MemoryBuffer ChunkReconstructSecured(MemoryBuffer buf, List<uint> chunkLengths, SLChannel config)
        {
            if (buf.Capacity < ChunkHeaderOverhead)
            {
                return null;
            }

            using MemoryBuffer tmpBuf = new MemoryBuffer(buf.Capacity);
            MemoryBuffer recvBuf = new MemoryBuffer(buf.Capacity);

            uint readOffset = 0;
            int decodedDecrTotal = 0;
            for (int i = 0; i < chunkLengths.Count; i++)
            {
                uint len = chunkLengths[i];
                Array.Copy(buf.Buffer, readOffset, tmpBuf.Buffer, 0, (int)len);

                tmpBuf.Position = 3;
                var unsecureRes = (uint)UASecurity.UnsecureSymmetric(tmpBuf, config.TokenID, config.PrevTokenID, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out int decrSize);
                if (!Types.StatusCodeIsGood(unsecureRes))
                {
                    return null;
                }

                decodedDecrTotal += decrSize;

                if (i == 0)
                {
                    Array.Copy(tmpBuf.Buffer, 0, recvBuf.Buffer, 0, ChunkHeaderOverhead);
                    recvBuf.Buffer[3] = (byte)'F';
                    recvBuf.Position = ChunkHeaderOverhead;
                }

                recvBuf.Append(tmpBuf.Buffer, ChunkHeaderOverhead, (int)(decrSize - ChunkHeaderOverhead));
                readOffset += len;
            }

            MarkPositionAsSize(recvBuf);

            return recvBuf;
        }

        private List<uint> ChunkCalculateSizes(MemoryBuffer memBuf)
        {
            var chunkLengths = new List<uint>();

            uint offset = 0;
            while (true)
            {
                // Incomplete with no final
                if (memBuf.Capacity < offset + ChunkHeaderOverhead)
                {
                    return null;
                }

                byte chunkType = memBuf.Buffer[offset + 3];
                if (chunkType == 'A')
                {
                    // OPC 10000-6, 6.7.2.4: Abort — discard message
                    return new List<uint>();
                }
                if (chunkType != 'C' && chunkType != 'F')
                {
                    // Invalid chunk type
                    return null;
                }

                bool isFinal = chunkType == (byte)'F';
                if (!memBuf.Decode(out uint chunkLength, (int)offset + 4))
                {
                    return null;
                }

                chunkLengths.Add(chunkLength);
                offset += chunkLength;

                // Final chunk is incomplete
                if (memBuf.Capacity < offset)
                {
                    return null;
                }

                if (isFinal)
                {
                    break;
                }
            }

            return chunkLengths;
        }

        private int Consume(SLChannel config, MemoryBuffer recvBuf)
        {
            // No message type and size
            if (recvBuf.Capacity < 8)
            {
                return 0;
            }

            uint messageType = (uint)recvBuf.Buffer[0] | (uint)(recvBuf.Buffer[1] << 8) | (uint)(recvBuf.Buffer[2] << 16);

            uint messageSize;
            if (recvBuf.Buffer[3] == 'F')
            {
                messageSize =
                    (uint)recvBuf.Buffer[4] | (uint)(recvBuf.Buffer[5] << 8) |
                    (uint)(recvBuf.Buffer[6] << 16) | (uint)(recvBuf.Buffer[7] << 24);

                if (config != null && config.TL != null &&
                    config.TL.TransportConfig.MaxMessageSize > 0 &&
                    messageSize > config.TL.TransportConfig.MaxMessageSize)
                {
                    recvHandlerStatus = StatusCode.BadResponseTooLarge;
                    return -1;
                }

                if (messageSize > recvBuf.Capacity)
                {
                    return 0;
                }

                if (messageType == (uint)MessageType.Message ||
                    messageType == (uint)MessageType.Close)
                {
                    if (config.MessageSecurityMode > MessageSecurityMode.None &&
                        config.LocalKeysets != null && config.RemoteKeysets != null)
                    {
                        int restorePos = recvBuf.Position;

                        recvBuf.Position = 3;
                        var unsecureRes = (uint)UASecurity.UnsecureSymmetric(recvBuf, config.TokenID, config.PrevTokenID, MessageEncodedBlockStart, config.LocalKeysets[0], config.RemoteKeysets, config.SecurityPolicy, config.MessageSecurityMode, out _);

                        recvBuf.Position = restorePos;

                        if (!Types.StatusCodeIsGood(unsecureRes))
                        {
                            return -1;
                        }
                    }
                }
            }
            else if (recvBuf.Buffer[3] == 'C')
            {
                var chunkSizes = ChunkCalculateSizes(recvBuf);
                if (chunkSizes == null)
                {
                    return 0;
                }

                if (chunkSizes.Count == 0)
                {
                    // Abort chunk received
                    recvHandlerStatus = StatusCode.BadRequestInterrupted;
                    return recvBuf.Capacity;
                }

                if (config.MessageSecurityMode > MessageSecurityMode.None &&
                    config.LocalKeysets != null && config.RemoteKeysets != null)
                {
                    recvBuf = ChunkReconstructSecured(recvBuf, chunkSizes, config);

                    if (recvBuf == null)
                    {
                        recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                        return -1;
                    }
                }
                else
                {
                    if (!ChunkReconstruct(recvBuf, chunkSizes))
                    {
                        recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                        return -1;
                    }
                }

                messageSize = 0;
                foreach (var chunkSize in chunkSizes) { messageSize += chunkSize; }

                if (messageSize > recvBuf.Capacity)
                {
                    return 0;
                }
            }
            else
            {
                recvHandlerStatus = StatusCode.BadMessageNotAvailable;
                return -1;
            }

            recvBuf.Position = 8;

            if (messageType == (uint)MessageType.Acknowledge)
            {
                lock (recvQueueLock)
                {
                    var key = new Tuple<uint, uint>(messageType, 0);
                    recvQueue[key] = new RecvHandler()
                    {
                        Header = null,
                        RecvBuf = recvBuf.Duplicate(),
                        Type = NodeId.Zero
                    };

                    if (recvNotify.TryGetValue(key, out ManualResetEvent ev))
                    {
                        ev.Set();
                    }
                }
            }
            else if (messageType == (uint)MessageType.Open)
            {
                messageSize =
                    (uint)recvBuf.Buffer[4] | (uint)(recvBuf.Buffer[5] << 8) |
                    (uint)(recvBuf.Buffer[6] << 16) | (uint)(recvBuf.Buffer[7] << 24);

                if (messageSize > recvBuf.Capacity)
                {
                    return 0;
                }

                ManualResetEvent ev = null;
                lock (recvQueueLock)
                {
                    var key = new Tuple<uint, uint>(messageType, 0);
                    recvQueue[key] = new RecvHandler()
                    {
                        Header = null,
                        RecvBuf = recvBuf.Duplicate((int)messageSize),
                        Type = NodeId.Zero
                    };

                    if (recvNotify.TryGetValue(key, out ev))
                    {
                        ev.Set();
                    }
                }

                // Wait for secure channel renew response to be
                // processed before handling other messages
                if (ev != null)
                {
                    csWaitForSecure.WaitOne();
                }
            }
            else if (messageType == (uint)MessageType.Error)
            {
                recvHandlerStatus = StatusCode.BadCommunicationError;

                try
                {
                    if (recvBuf.Decode(out uint status))
                    {
                        recvHandlerStatus = (StatusCode)status;
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    // Status decode failed — keep default BadCommunicationError
                }

                // Signal all waiting requests so they can observe the error
                lock (recvNotifyLock)
                {
                    foreach (var ev in recvNotify.Values)
                    {
                        ev.Set();
                    }
                }

                return -1;
            }
            else
            {

                bool succeeded = true;
                succeeded &= recvBuf.Decode(out uint _);
                succeeded &= recvBuf.Decode(out uint _);
                succeeded &= recvBuf.Decode(out uint securitySeqNum);
                succeeded &= recvBuf.Decode(out uint _);

                // OPC 10000-6: Validate sequence number
                uint expectedSeq = config.RemoteSequence.SequenceNumber + 1;
                if (expectedSeq > 4294966271u) expectedSeq = 1; // Wrap-around per spec

                if (securitySeqNum != expectedSeq && config.RemoteSequence.SequenceNumber != 0)
                {
                    // Backward jump > 1000 indicates replay attack
                    if (securitySeqNum < config.RemoteSequence.SequenceNumber &&
                        config.RemoteSequence.SequenceNumber - securitySeqNum < 4294000000u)
                    {
                        recvHandlerStatus = StatusCode.BadSecurityChecksFailed;
                        return -1;
                    }
                }
                config.RemoteSequence.SequenceNumber = securitySeqNum;

                succeeded &= recvBuf.Decode(out NodeId typeId);

                succeeded &= recvBuf.Decode(out ResponseHeader respHeader);

                if (!succeeded)
                {
                    recvHandlerStatus = StatusCode.BadDecodingError;
                    return -1;
                }

                if (publishReqs.Contains(respHeader.RequestHandle))
                {
                    try
                    {
                        ConsumeNotification(new RecvHandler()
                        {
                            Header = respHeader,
                            RecvBuf = recvBuf.Duplicate(),
                            Type = typeId
                        });
                    }
                    finally
                    {
                        publishReqs.Remove(respHeader.RequestHandle);
                        nextPublish = true;
                    }
                }
                else
                {
                    lock (recvQueueLock)
                    {
                        var recvKey = new Tuple<uint, uint>(messageType, respHeader.RequestHandle);
                        recvQueue[recvKey] = new RecvHandler()
                        {
                            Header = respHeader,
                            RecvBuf = recvBuf.Duplicate(),
                            Type = typeId
                        };

                        if (recvNotify.TryGetValue(recvKey, out ManualResetEvent ev))
                        {
                            ev.Set();
                        }
                    }
                }
            }

            return (int)messageSize;
        }

        public StatusCode ActivateSession(object identityToken, string[] localeIDs)
        {
            try
            {
                cs.WaitOne();

                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.ActivateSessionRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                // Calculate challenge:
                var strRemoteCert = config.RemoteCertificateString;
                var challenge = new byte[(strRemoteCert?.Length ?? 0)
                    + (config.RemoteNonce?.Length ?? 0)];
                var offset = 0;
                if (strRemoteCert != null)
                {
                    Array.Copy(strRemoteCert, 0, challenge, offset, strRemoteCert.Length);
                    offset += strRemoteCert.Length;
                }

                if (config.RemoteNonce != null)
                {
                    Array.Copy(config.RemoteNonce, 0, challenge, offset, config.RemoteNonce.Length);
                    offset += config.RemoteNonce.Length;
                }

                if (config.MessageSecurityMode == MessageSecurityMode.None)
                {
                    // ClientSignatureAlgorithm
                    succeeded &= sendBuf.EncodeUAString((string)null);
                    // ClientSignature
                    succeeded &= sendBuf.EncodeUAByteString(null);
                }
                else
                {
                    if (challenge.Length == 0)
                    {
                        return StatusCode.BadSessionClosed;
                    }

                    var algorithm = UASecurity.SignatureAlgorithmForSecurityPolicy(config.SecurityPolicy);
                    var thumbprint = UASecurity.Sign(new ArraySegment<byte>(challenge),
                        ApplicationPrivateKey, config.SecurityPolicy);

                    succeeded &= sendBuf.EncodeUAString(algorithm);
                    succeeded &= sendBuf.EncodeUAByteString(thumbprint);
                }

                // ClientSoftwareCertificates: Array of SignedSoftwareCertificate
                succeeded &= sendBuf.Encode((UInt32)0);

                // LocaleIds: Array of String
                succeeded &= sendBuf.EncodeUAString(localeIDs);

                if (identityToken is UserIdentityAnonymousToken token)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.AnonymousIdentityToken_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);

                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.EncodeUAString(token.PolicyId);
                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else if (identityToken is UserIdentityUsernameToken usernameToken)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.UserNameIdentityToken_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);

                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.EncodeUAString(usernameToken.PolicyId);
                    succeeded &= sendBuf.EncodeUAString(usernameToken.Username);

                    try
                    {
                        var passwordSrc = usernameToken.PasswordHash;
                        int padSize = UASecurity.CalculatePaddingSizePolicyUri(config.RemoteCertificate,
                            usernameToken.Algorithm, 4 + passwordSrc.Length,
                            (config.RemoteNonce == null ? 0 : config.RemoteNonce.Length));
                        var rndBytes = UASecurity.GenerateRandomBytes(padSize);

                        byte[] crypted = new byte[4 + passwordSrc.Length + padSize +
                            (config.RemoteNonce == null ? 0 : config.RemoteNonce.Length)];

                        int rawSize = passwordSrc.Length +
                            (config.RemoteNonce == null ? 0 : config.RemoteNonce.Length);

                        crypted[0] = (byte)(rawSize & 0xFF);
                        crypted[1] = (byte)((rawSize >> 8) & 0xFF);
                        crypted[2] = (byte)((rawSize >> 16) & 0xFF);
                        crypted[3] = (byte)((rawSize >> 24) & 0xFF);

                        Array.Copy(passwordSrc, 0, crypted, 4, passwordSrc.Length);

                        offset = 4 + passwordSrc.Length;

                        if (config.RemoteNonce != null)
                        {
                            Array.Copy(config.RemoteNonce, 0, crypted, offset, config.RemoteNonce.Length);
                            offset += config.RemoteNonce.Length;
                        }
                        else
                        {
                            Array.Copy(rndBytes, 0, crypted, offset, rndBytes.Length);
                            offset += rndBytes.Length;
                        }
                        switch (usernameToken.Algorithm)
                        {
                            case Types.SignatureAlgorithmRsa15:
                            case Types.SignatureAlgorithmRsaOaep:
                            case Types.SignatureAlgorithmRsaOaep256:
                                crypted = UASecurity.Encrypt(
                                    new ArraySegment<byte>(crypted),
                                    config.RemoteCertificate, UASecurity.UseOaepForSecuritySigPolicyUri(usernameToken.Algorithm));
                                break;

                            default:
                                throw new NotSupportedException(string.Format("Identity token algorithm '{0}' is not supported", usernameToken.Algorithm));
                        }

                        succeeded &= sendBuf.EncodeUAByteString(crypted);
                        succeeded &= sendBuf.EncodeUAString(usernameToken.Algorithm);
                    }
                    catch (CryptographicException)
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else if (identityToken is UserIdentityX509IdentityToken x509Token)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.X509IdentityToken_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);

                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.EncodeUAString(x509Token.PolicyId);
                    succeeded &= sendBuf.EncodeUAByteString(x509Token.CertificateData);
                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else
                {
                    throw new NotSupportedException(string.Format("Identity token of type '{0}' is not supported", identityToken.GetType().Name));
                }

                if (identityToken is UserIdentityX509IdentityToken x509IdentityToken)
                {
                    if (challenge.Length == 0)
                    {
                        return StatusCode.BadSessionClosed;
                    }

                    var algorithm = UASecurity.SignatureAlgorithmForSecurityPolicy(config.SecurityPolicy);
                    var thumbprint = UASecurity.Sign(new ArraySegment<byte>(challenge),
                        x509IdentityToken.PrivateKey, config.SecurityPolicy);

                    succeeded &= sendBuf.EncodeUAString(algorithm);
                    succeeded &= sendBuf.EncodeUAByteString(thumbprint);
                }
                else
                {
                    // userTokenAlgorithm
                    succeeded &= sendBuf.EncodeUAString((string)null);
                    // userTokenSignature
                    succeeded &= sendBuf.EncodeUAByteString(null);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ActivateSessionResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] serverNonce);
                config.RemoteNonce = serverNonce;

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                renewTimer?.Stop();

                renewTimer = new System.Timers.Timer(0.7 * config.TokenLifetime);
                renewTimer.Elapsed += (sender, e) =>
                {
                    var res = RenewSecureChannel();
                    if (!Types.StatusCodeIsGood((uint)res))
                    {
                        recvHandlerStatus = res;
                        Disconnect();
                    }
                };
                renewTimer.Start();

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        private static StatusCode CheckServiceFaultResponse(RecvHandler recvHandler)
        {
            if (recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ServiceFault) &&
                recvHandler.Header != null && Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
            {
                return (StatusCode)recvHandler.Header.ServiceResult;
            }

            // Check if the ResponseHeader indicates a non-good ServiceResult
            if (recvHandler.Header != null &&
                Types.StatusCodeIsBad(recvHandler.Header.ServiceResult) &&
                Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
            {
                return (StatusCode)recvHandler.Header.ServiceResult;
            }

            return StatusCode.BadUnknownResponse;
        }

        public StatusCode CreateSession(ApplicationDescription appDesc, string sessionName, int requestedSessionTimeout)
        {
            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateSessionRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(appDesc);
                // ServerUri
                succeeded &= sendBuf.EncodeUAString((string)null);
                succeeded &= sendBuf.EncodeUAString(GetEndpointString());
                succeeded &= sendBuf.EncodeUAString(sessionName);

                // Generate a fresh nonce for CreateSession (must differ from OpenSecureChannel nonce)
                byte[] sessionNonce = null;
                if (config.SecurityPolicy != SecurityPolicy.None)
                {
                    int nonceSize = UASecurity.NonceLengthForSecurityPolicy(config.SecurityPolicy);
                    sessionNonce = UASecurity.GenerateRandomBytes(nonceSize);
                }
                config.LocalNonce = sessionNonce;
                succeeded &= sendBuf.EncodeUAByteString(config.LocalNonce);
                if (ApplicationCertificate == null)
                {
                    succeeded &= sendBuf.EncodeUAByteString(null);
                }
                else
                {
                    succeeded &= sendBuf.EncodeUAByteString(ApplicationCertificate.Export(X509ContentType.Cert));
                }
                succeeded &= sendBuf.Encode((Double)(1000 * requestedSessionTimeout));
                succeeded &= sendBuf.Encode((UInt32)MaximumMessageSize);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateSessionResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.Decode(out NodeId sessionIdToken);
                succeeded &= recvHandler.RecvBuf.Decode(out NodeId authToken);
                succeeded &= recvHandler.RecvBuf.Decode(out double revisedSessionTimeout);

                config.SessionTimeout = (uint)(revisedSessionTimeout);

                config.SessionIdToken = sessionIdToken;
                config.AuthToken = authToken;

                succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] serverNonce);
                succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] serverCert);

                config.RemoteNonce = serverNonce;
                try
                {
                    config.RemoteCertificate = new X509Certificate2(serverCert);
                }
                catch (CryptographicException)
                {
                    return StatusCode.BadSecurityChecksFailed;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode CloseSession(bool deleteSubscriptions = true)
        {
            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CloseSessionRequest));
                succeeded &= sendBuf.Encode(reqHeader);
                succeeded &= sendBuf.Encode(deleteSubscriptions);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CloseSessionResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Read(ArraySegment<ReadValueId> Ids, ArraySegment<DataValue> results)
        {
            if (Ids.Count == 0)
            {
                return StatusCode.Good;
            }

            if (Ids.Count != results.Count)
            {
                throw new ArgumentException(string.Format("Number of results ({0}) must match number of Ids ({1}).", results.Count, Ids.Count), nameof(results));
            }

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.ReadRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                // maxAge
                succeeded &= sendBuf.Encode((double)0);
                // LocaleIds
                succeeded &= sendBuf.Encode((uint)TimestampsToReturn.Both);
                succeeded &= sendBuf.Encode((uint)Ids.Count);
                for (int i = 0; i < Ids.Count; i++)
                {
                    succeeded &= sendBuf.Encode(Ids[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ReadResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    if (results[i] == null)
                    {
                        results[i] = new DataValue();
                    }

                    succeeded &= recvHandler.RecvBuf.Decode(results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != Ids.Count)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Read(ReadValueId[] Ids, out DataValue[] results)
        {
            results = new DataValue[Ids.Length];
            return Read(Ids, results);
        }

        public StatusCode Write(ArraySegment<WriteValue> Ids, ArraySegment<uint> results)
        {
            if (Ids.Count == 0)
            {
                return StatusCode.Good;
            }

            if (Ids.Count != results.Count)
            {
                throw new ArgumentException(string.Format("Number of results ({0}) must match number of Ids ({1}).", results.Count, Ids.Count), nameof(results));
            }

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.WriteRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)Ids.Count);
                for (int i = 0; i < Ids.Count; i++)
                {
                    succeeded &= sendBuf.Encode(Ids[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.WriteResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                uint v;
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out v);
                    results[i] = v;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != Ids.Count)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Write(WriteValue[] Ids, out uint[] results)
        {
            results = new uint[Ids.Length];
            return Write(Ids, results);
        }

        /// <summary>
        /// Converts a value to the target VariantType, handling common mismatches
        /// (e.g., C# int → Int64 when server expects Int64).
        /// </summary>
        private static object ConvertToVariantType(object value, VariantType targetType)
        {
            if (value == null) return null;

            try
            {
                return targetType switch
                {
                    VariantType.Boolean => Convert.ToBoolean(value),
                    VariantType.SByte => Convert.ToSByte(value),
                    VariantType.Byte => Convert.ToByte(value),
                    VariantType.Int16 => Convert.ToInt16(value),
                    VariantType.UInt16 => Convert.ToUInt16(value),
                    VariantType.Int32 => Convert.ToInt32(value),
                    VariantType.UInt32 => Convert.ToUInt32(value),
                    VariantType.Int64 => Convert.ToInt64(value),
                    VariantType.UInt64 => Convert.ToUInt64(value),
                    VariantType.Float => Convert.ToSingle(value),
                    VariantType.Double => Convert.ToDouble(value),
                    VariantType.String => Convert.ToString(value),
                    _ => value,
                };
            }
            catch (Exception ex) when (ex is InvalidCastException or OverflowException or FormatException)
            {
                return value;
            }
        }

        // OPC UA DataType NodeId → VariantType mapping for built-in types
        private static readonly Dictionary<uint, VariantType> DataTypeToVariantType = new()
        {
            { 1, VariantType.Boolean },
            { 2, VariantType.SByte },
            { 3, VariantType.Byte },
            { 4, VariantType.Int16 },
            { 5, VariantType.UInt16 },
            { 6, VariantType.Int32 },
            { 7, VariantType.UInt32 },
            { 8, VariantType.Int64 },
            { 9, VariantType.UInt64 },
            { 10, VariantType.Float },
            { 11, VariantType.Double },
            { 12, VariantType.String },
            { 13, VariantType.DateTime },
            { 14, VariantType.Guid },
            { 15, VariantType.ByteString },
        };

        /// <summary>
        /// Write values with automatic DataType matching.
        /// Reads the DataType attribute of each target node and converts the value
        /// to the expected VariantType before writing.
        /// </summary>
        public StatusCode WriteWithTypeCheck(WriteValue[] writeValues, out uint[] results)
        {
            results = null;

            // Read DataType attribute for each target node
            var readIds = new ReadValueId[writeValues.Length];
            for (int i = 0; i < writeValues.Length; i++)
            {
                readIds[i] = new ReadValueId(writeValues[i].NodeId, NodeAttribute.DataType, null, new QualifiedName(0, null));
            }

            var readRes = Read(readIds, out DataValue[] dataTypes);
            if (!Types.StatusCodeIsGood((uint)readRes))
            {
                // Fallback to regular Write without type check
                return Write(writeValues, out results);
            }

            // Convert values to match server's expected DataType
            var convertedValues = new WriteValue[writeValues.Length];
            for (int i = 0; i < writeValues.Length; i++)
            {
                var wv = writeValues[i];
                var converted = wv;

                if (dataTypes[i]?.Value is NodeId dataTypeNodeId &&
                    dataTypeNodeId.NamespaceIndex == 0 &&
                    DataTypeToVariantType.TryGetValue(dataTypeNodeId.NumericIdentifier, out var targetType))
                {
                    var currentType = Coding.GetVariantTypeFromInstance(wv.Value?.Value);
                    if (currentType != targetType && wv.Value?.Value != null)
                    {
                        var convertedVal = ConvertToVariantType(wv.Value.Value, targetType);
                        converted = new WriteValue(wv.NodeId, wv.AttributeId, wv.IndexRange,
                            new DataValue(convertedVal, wv.Value.StatusCode, wv.Value.SourceTimestamp, wv.Value.ServerTimestamp));
                    }
                }

                convertedValues[i] = converted;
            }

            return Write(convertedValues, out results);
        }

        // ══════════════════════════════════════════════════════════════════
        //  Custom DataType discovery (OPC UA Part 3/5)
        // ══════════════════════════════════════════════════════════════════

        /// <summary>
        /// Load the StructureDefinition for a specific DataType node.
        /// Uses the DataTypeDefinition attribute (OPC UA 1.04+).
        /// Registers the result in TypeRegistry for automatic decoding.
        /// </summary>
        public StatusCode LoadDataTypeDefinition(NodeId dataTypeNodeId, out ValueTypes.StructureDefinition definition)
        {
            definition = null;

            // 1. Read DataTypeDefinition attribute (AttributeId=26)
            //    Some servers use AttributeId 23 (DataTypeDefinition per 1.04 spec is id 26)
            //    Try the standard value attribute first — some servers expose it as Value of the encoding node
            var readRes = Read(new ReadValueId[]
            {
                new(dataTypeNodeId, (NodeAttribute)26, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            // 2. Browse for Default Binary encoding node
            NodeId encodingNodeId = null;
            var browseRes = Browse(new BrowseDescription[]
            {
                new(dataTypeNodeId, BrowseDirection.Forward,
                    new NodeId(0, 38), // HasEncoding reference type
                    false, 0, BrowseResultMask.All)
            }, 10, out BrowseResult[] browseResults);

            if (Types.StatusCodeIsGood((uint)browseRes) && browseResults?.Length > 0 && browseResults[0].Refs != null)
            {
                foreach (var r in browseResults[0].Refs)
                {
                    if (r.BrowseName.Name == "Default Binary")
                    {
                        encodingNodeId = r.TargetId;
                        break;
                    }
                }
            }

            // 3. Try to decode the DataTypeDefinition
            if (Types.StatusCodeIsGood((uint)readRes) && dvs?.Length > 0 && dvs[0]?.Value != null)
            {
                // The DataTypeDefinition comes as ExtensionObject containing StructureDefinition
                if (dvs[0].Value is ExtensionObject eo && eo.Body != null)
                {
                    var bodyBuf = new MemoryBuffer(eo.Body);
                    definition = DecodeStructureDefinition(bodyBuf);
                }
                // Some servers return the definition directly as a decoded object
                else if (dvs[0].Value is ValueTypes.StructureDefinition sd)
                {
                    definition = sd;
                }
            }

            if (definition != null)
            {
                if (encodingNodeId != null)
                    definition.DefaultEncodingId = encodingNodeId;

                TypeRegistry.Register(encodingNodeId, dataTypeNodeId, definition);
                return StatusCode.Good;
            }

            return StatusCode.BadNotSupported;
        }

        /// <summary>
        /// Load all custom DataType definitions for a given namespace index.
        /// Browses from the Structure DataType (i=22) and reads DataTypeDefinition for each subtype.
        /// </summary>
        public StatusCode LoadDataTypesForNamespace(ushort namespaceIndex)
        {
            int loaded = 0;

            // Browse subtypes of Structure (i=22)
            var queue = new Queue<NodeId>();
            queue.Enqueue(new NodeId(0, 22)); // Structure base type

            var visited = new HashSet<string>();

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                string key = $"{current.NamespaceIndex}:{current.NumericIdentifier}";
                if (visited.Contains(key)) continue;
                visited.Add(key);

                // Browse subtypes (HasSubtype reference, forward)
                var browseRes = Browse(new BrowseDescription[]
                {
                    new(current, BrowseDirection.Forward,
                        new NodeId(0, 45), // HasSubtype
                        false, 0, BrowseResultMask.All)
                }, 1000, out BrowseResult[] results);

                if (!Types.StatusCodeIsGood((uint)browseRes) || results == null || results.Length == 0)
                    continue;

                if (results[0].Refs == null) continue;

                foreach (var r in results[0].Refs)
                {
                    if (r.TargetId == null) continue;
                    queue.Enqueue(r.TargetId);

                    // Only load types from the requested namespace
                    if (r.TargetId.NamespaceIndex != namespaceIndex)
                        continue;

                    LoadDataTypeDefinition(r.TargetId, out _);
                    loaded++;
                }
            }

            return loaded > 0 ? StatusCode.Good : StatusCode.GoodNoData;
        }

        /// <summary>
        /// Try to decode an ExtensionObject using the TypeRegistry.
        /// Returns a StructuredValue if the type is known, null otherwise.
        /// </summary>
        public ValueTypes.StructuredValue TryDecodeExtensionObject(ExtensionObject eo)
        {
            if (eo?.Body == null || eo.TypeId == null) return null;

            if (!TypeRegistry.TryGetByEncodingId(eo.TypeId, out var def))
                return null;

            var buf = new MemoryBuffer(eo.Body);
            return ValueTypes.StructuredTypeCodec.Decode(buf, def, TypeRegistry);
        }

        private static ValueTypes.StructureDefinition DecodeStructureDefinition(MemoryBuffer buf)
        {
            var def = new ValueTypes.StructureDefinition();

            if (!buf.Decode(out NodeId defaultEncodingId)) return null;
            def.DefaultEncodingId = defaultEncodingId;

            if (!buf.Decode(out NodeId baseDataType)) return null;
            def.BaseDataType = baseDataType;

            if (!buf.Decode(out int structureType)) return null;
            def.StructureType = (ValueTypes.StructureType)structureType;

            if (!buf.Decode(out int numFields)) return null;
            if (numFields < 0) numFields = 0;

            def.Fields = new ValueTypes.StructureField[numFields];
            for (int i = 0; i < numFields; i++)
            {
                var field = new ValueTypes.StructureField();

                if (!buf.DecodeUAString(out string name)) return null;
                field.Name = name;

                if (!buf.Decode(out LocalizedText desc)) return null;
                field.Description = desc;

                if (!buf.Decode(out NodeId dataType)) return null;
                field.DataType = dataType;

                if (!buf.Decode(out int valueRank)) return null;
                field.ValueRank = valueRank;

                if (!buf.Decode(out int numDims)) return null;
                if (numDims > 0)
                {
                    field.ArrayDimensions = new uint[numDims];
                    for (int j = 0; j < numDims; j++)
                    {
                        if (!buf.Decode(out field.ArrayDimensions[j])) return null;
                    }
                }

                if (!buf.Decode(out uint maxStringLen)) return null;
                field.MaxStringLength = maxStringLen;

                if (!buf.Decode(out bool isOptional)) return null;
                field.IsOptional = isOptional;

                def.Fields[i] = field;
            }

            return def;
        }

        public StatusCode AddNodes(AddNodesItem[] addNodesItems, out AddNodesResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.AddNodesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)addNodesItems.Length);
                for (int i = 0; i < addNodesItems.Length; i++)
                {
                    succeeded &= sendBuf.Encode(addNodesItems[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.AddNodesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new AddNodesResult[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != addNodesItems.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode DeleteNodes(DeleteNodesItem[] deleteNodesItems, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteNodesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)deleteNodesItems.Length);
                for (int i = 0; i < deleteNodesItems.Length; i++)
                {
                    succeeded &= sendBuf.Encode(deleteNodesItems[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteNodesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new uint[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != deleteNodesItems.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode AddReferences(AddReferencesItem[] addReferencesItems, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.AddReferencesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)addReferencesItems.Length);
                for (int i = 0; i < addReferencesItems.Length; i++)
                {
                    succeeded &= sendBuf.Encode(addReferencesItems[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.AddReferencesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new uint[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != addReferencesItems.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode DeleteReferences(DeleteReferencesItem[] deleteReferencesItems, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteReferencesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)deleteReferencesItems.Length);
                for (int i = 0; i < deleteReferencesItems.Length; i++)
                {
                    succeeded &= sendBuf.Encode(deleteReferencesItems[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteReferencesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new uint[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != deleteReferencesItems.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Browse(BrowseDescription[] requests, uint requestedMaxReferencesPerNode, out BrowseResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.BrowseRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                // ViewId
                succeeded &= sendBuf.Encode(NodeId.Zero);
                // View timestamp
                succeeded &= sendBuf.Encode((UInt64)0);
                // View version
                succeeded &= sendBuf.Encode((UInt32)0);

                succeeded &= sendBuf.Encode((UInt32)requestedMaxReferencesPerNode);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.BrowseResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new BrowseResult[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    ReferenceDescription[] refDescs;

                    succeeded &= recvHandler.RecvBuf.Decode(out uint status);
                    succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] contPoint);
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRefDesc);

                    if (numRefDesc == uint.MaxValue) { numRefDesc = 0; }
                    refDescs = new ReferenceDescription[numRefDesc];
                    for (int j = 0; j < refDescs.Length; j++)
                    {
                        succeeded &= recvHandler.RecvBuf.Decode(out refDescs[j]);
                    }

                    results[i] = new BrowseResult(status, contPoint, refDescs);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                if (numRecv != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode BrowseNext(IList<byte[]> contPoints, bool releaseContinuationPoints, out BrowseResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.BrowseNextRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(releaseContinuationPoints);
                succeeded &= sendBuf.Encode((UInt32)contPoints.Count);
                for (int i = 0; i < contPoints.Count; i++)
                {
                    succeeded &= sendBuf.EncodeUAByteString(contPoints[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.BrowseNextResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                if (!releaseContinuationPoints)
                {
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                    results = new BrowseResult[numRecv];
                    for (int i = 0; i < numRecv && succeeded; i++)
                    {
                        ReferenceDescription[] refDescs;

                        succeeded &= recvHandler.RecvBuf.Decode(out uint status);
                        succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] contPoint);
                        succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRefDesc);

                        refDescs = new ReferenceDescription[numRefDesc];
                        for (int j = 0; j < refDescs.Length; j++)
                        {
                            succeeded &= recvHandler.RecvBuf.Decode(out refDescs[j]);
                        }

                        results[i] = new BrowseResult(status, contPoint, refDescs);
                    }

                    if (!succeeded)
                    {
                        return StatusCode.BadDecodingError;
                    }

                    if (numRecv != contPoints.Count)
                    {
                        return StatusCode.GoodResultsMayBeIncomplete;
                    }
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode HistoryRead(object historyReadDetails, TimestampsToReturn timestampsToReturn, bool releaseContinuationPoints, HistoryReadValueId[] requests, out HistoryReadResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.HistoryReadRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                if (historyReadDetails is ReadRawModifiedDetails details)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadRawModifiedDetails_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);
                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.Encode(details.IsReadModified);
                    succeeded &= sendBuf.Encode((Int64)details.StartTime.ToFileTime());
                    succeeded &= sendBuf.Encode((Int64)details.EndTime.ToFileTime());
                    succeeded &= sendBuf.Encode((UInt32)details.NumValuesPerNode);
                    succeeded &= sendBuf.Encode(details.ReturnBounds);

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else if (historyReadDetails is ReadProcessedDetails processedDetails)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadProcessedDetails_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);
                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.Encode(processedDetails.StartTime.ToFileTime());
                    succeeded &= sendBuf.Encode(processedDetails.EndTime.ToFileTime());
                    succeeded &= sendBuf.Encode(processedDetails.ProcessingInterval);

                    succeeded &= sendBuf.Encode((UInt32)processedDetails.AggregateTypes.Length);
                    for (int i = 0; i < processedDetails.AggregateTypes.Length; i++)
                    {
                        succeeded &= sendBuf.Encode(processedDetails.AggregateTypes[i]);
                    }

                    succeeded &= sendBuf.Encode(processedDetails.Configuration);

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else if (historyReadDetails is ReadAtTimeDetails timeDetails)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadAtTimeDetails_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);
                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.Encode(timeDetails.ReqTimes.Length);
                    for (int i = 0; i < timeDetails.ReqTimes.Length; i++)
                    {
                        succeeded &= sendBuf.Encode(timeDetails.ReqTimes[i].ToFileTime());
                    }

                    succeeded &= sendBuf.Encode(timeDetails.UseSimpleBounds);

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else if (historyReadDetails is ReadEventDetails eventDetails)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.ReadEventDetails_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);
                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.Encode(eventDetails.NumValuesPerNode);
                    succeeded &= sendBuf.Encode(eventDetails.StartTime.ToFileTime());
                    succeeded &= sendBuf.Encode(eventDetails.EndTime.ToFileTime());
                    succeeded &= sendBuf.Encode(new EventFilter(eventDetails.SelectClauses, null), false);

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }
                else
                {
                    throw new NotSupportedException(string.Format("History read details of type '{0}' is not supported", historyReadDetails.GetType().Name));
                }

                succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);
                succeeded &= sendBuf.Encode(releaseContinuationPoints);
                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i].NodeId);
                    succeeded &= sendBuf.EncodeUAString(requests[i].IndexRange);
                    succeeded &= sendBuf.Encode(requests[i].DataEncoding);
                    succeeded &= sendBuf.EncodeUAByteString(requests[i].ContinuationPoint);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.HistoryReadResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                if (!releaseContinuationPoints)
                {
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                    results = new HistoryReadResult[numRecv];
                    for (int i = 0; i < numRecv && succeeded; i++)
                    {


                        succeeded &= recvHandler.RecvBuf.Decode(out uint status);
                        succeeded &= recvHandler.RecvBuf.DecodeUAByteString(out byte[] contPoint);
                        succeeded &= recvHandler.RecvBuf.Decode(out NodeId type);
                        succeeded &= recvHandler.RecvBuf.Decode(out byte eoBodyMask);

                        // OPC UA Part 6, 5.2.2.15: eoBodyMask == 0 means null/empty ExtensionObject (no history data)
                        if (eoBodyMask == 0)
                        {
                            results[i] = new HistoryReadResult(status, contPoint, Array.Empty<DataValue>());
                        }
                        else if (eoBodyMask == 1)
                        {
                            succeeded &= recvHandler.RecvBuf.Decode(out uint eoSize);

                            if (type.EqualsNumeric(0, (uint)UAConst.HistoryData_Encoding_DefaultBinary))
                            {
                                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numDvs);
                                DataValue[] dvs = new DataValue[numDvs];
                                for (int j = 0; j < numDvs; j++)
                                {
                                    succeeded &= recvHandler.RecvBuf.Decode(out dvs[j]);
                                }

                                results[i] = new HistoryReadResult(status, contPoint, dvs);
                            }
                            else if (type.EqualsNumeric(0, (uint)UAConst.HistoryEvent_Encoding_DefaultBinary))
                            {
                                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numDvs);

                                DataValue[] dvs = new DataValue[numDvs];
                                for (int j = 0; succeeded && j < numDvs; j++)
                                {
                                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numFields);
                                    object[] fields = new object[numFields];
                                    for (int k = 0; succeeded && k < numFields; k++)
                                    {
                                        succeeded &= recvHandler.RecvBuf.VariantDecode(out fields[k]);
                                    }

                                    dvs[j] = new DataValue(fields);
                                }

                                results[i] = new HistoryReadResult(status, contPoint, dvs);
                            }
                            else
                            {
                                return StatusCode.BadDataEncodingInvalid;
                            }
                        }
                        else
                        {
                            return StatusCode.BadDataEncodingInvalid;
                        }
                    }

                    if (!succeeded)
                    {
                        return StatusCode.BadDecodingError;
                    }

                    if (numRecv != requests.Length)
                    {
                        return StatusCode.GoodResultsMayBeIncomplete;
                    }
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode HistoryUpdate(HistoryUpdateData[] requests, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.HistoryUpdateRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(new NodeId(UAConst.UpdateDataDetails_Encoding_DefaultBinary));
                    succeeded &= sendBuf.Encode((byte)1);
                    int eoStartPos = sendBuf.Position;
                    succeeded &= sendBuf.Encode((UInt32)0);

                    succeeded &= sendBuf.Encode(requests[i].NodeId);
                    succeeded &= sendBuf.Encode((UInt32)requests[i].PerformUpdate);
                    succeeded &= sendBuf.Encode((UInt32)requests[i].Value.Length);

                    for (int j = 0; j < requests[i].Value.Length; j++)
                    {
                        succeeded &= sendBuf.Encode(requests[i].Value[j]);
                    }

                    succeeded &= sendBuf.Encode((UInt32)(sendBuf.Position - eoStartPos - 4), eoStartPos);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.HistoryUpdateResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new uint[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (numRecv != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode TranslateBrowsePathsToNodeIds(BrowsePath[] requests, out BrowsePathResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.TranslateBrowsePathsToNodeIdsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.TranslateBrowsePathsToNodeIdsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new BrowsePathResult[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (numRecv != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Call(CallMethodRequest[] requests, out CallMethodResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CallRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i].ObjectId);
                    succeeded &= sendBuf.Encode(requests[i].MethodId);
                    succeeded &= sendBuf.Encode((UInt32)requests[i].InputArguments.Length);
                    for (int j = 0; j < requests[i].InputArguments.Length; j++)
                    {
                        succeeded &= sendBuf.VariantEncode(requests[i].InputArguments[j]);
                    }
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CallResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRecv);

                results = new CallMethodResult[numRecv];
                for (int i = 0; i < numRecv && succeeded; i++)
                {
                    UInt32[] resultStatus;
                    object[] outputs;

                    succeeded &= recvHandler.RecvBuf.Decode(out uint status);

                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                    if (numResults == uint.MaxValue)
                    {
                        numResults = 0;
                    }
                    resultStatus = new UInt32[numResults];
                    for (int j = 0; j < numResults; j++)
                    {
                        succeeded &= recvHandler.RecvBuf.Decode(out resultStatus[j]);
                    }

                    // Skip DiagnosticInfo array
                    succeeded &= recvHandler.RecvBuf.Decode(out DiagnosticInfo[] _);

                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numOutputs);
                    if (numOutputs == uint.MaxValue)
                    {
                        numOutputs = 0;
                    }
                    outputs = new object[numOutputs];
                    for (int j = 0; j < numOutputs; j++)
                    {
                        succeeded &= recvHandler.RecvBuf.VariantDecode(out outputs[j]);
                    }

                    results[i] = new CallMethodResult(status, resultStatus, outputs);
                }

                if (numRecv != requests.Length)
                {
                    return StatusCode.GoodResultsMayBeIncomplete;
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        // ══════════════════════════════════════════════════════════════════
        //  Alarms & Conditions convenience methods (OPC UA Part 9)
        //  These wrap the Call service for standard Condition methods.
        // ══════════════════════════════════════════════════════════════════

        /// <summary>
        /// Acknowledge a condition/alarm. EventId and Comment from the event notification.
        /// </summary>
        public StatusCode AcknowledgeCondition(NodeId conditionId, byte[] eventId, string comment = null)
        {
            // Acknowledge MethodId = ConditionType.Acknowledge (i=9111)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9111), new object[]
                {
                    eventId,
                    new LocalizedText(comment ?? "")
                })
            }, out _);
        }

        /// <summary>
        /// Confirm a condition/alarm.
        /// </summary>
        public StatusCode ConfirmCondition(NodeId conditionId, byte[] eventId, string comment = null)
        {
            // Confirm MethodId = ConditionType.Confirm (i=9113)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9113), new object[]
                {
                    eventId,
                    new LocalizedText(comment ?? "")
                })
            }, out _);
        }

        /// <summary>
        /// Add a comment to a condition.
        /// </summary>
        public StatusCode AddConditionComment(NodeId conditionId, byte[] eventId, string comment)
        {
            // AddComment MethodId = ConditionType.AddComment (i=9029)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9029), new object[]
                {
                    eventId,
                    new LocalizedText(comment)
                })
            }, out _);
        }

        /// <summary>
        /// Enable a condition.
        /// </summary>
        public StatusCode EnableCondition(NodeId conditionId)
        {
            // Enable MethodId = ConditionType.Enable (i=9027)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9027), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Disable a condition.
        /// </summary>
        public StatusCode DisableCondition(NodeId conditionId)
        {
            // Disable MethodId = ConditionType.Disable (i=9028)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9028), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Request a ConditionRefresh for a subscription. Forces server to resend current state of all conditions.
        /// </summary>
        public StatusCode ConditionRefresh(uint subscriptionId)
        {
            // ConditionRefresh MethodId = ConditionType.ConditionRefresh (i=3875)
            return Call(new CallMethodRequest[]
            {
                new(new NodeId(0, (uint)UAConst.ConditionType), new NodeId(0, 3875), new object[]
                {
                    subscriptionId
                })
            }, out _);
        }

        /// <summary>
        /// Shelve an alarm with a timed duration.
        /// </summary>
        public StatusCode TimedShelve(NodeId alarmId, double shelvingTime)
        {
            // TimedShelve on the ShelvedStateMachine — browse to find the actual method node
            // Standard MethodId for ShelvedStateMachineType.TimedShelve (i=2949)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 2949), new object[] { shelvingTime })
            }, out _);
        }

        /// <summary>
        /// One-shot shelve an alarm (shelved until manually unshelved).
        /// </summary>
        public StatusCode OneShotShelve(NodeId alarmId)
        {
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 2948), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Unshelve a shelved alarm.
        /// </summary>
        public StatusCode Unshelve(NodeId alarmId)
        {
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 2947), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Respond to a DialogConditionType prompt.
        /// </summary>
        public StatusCode RespondToDialog(NodeId conditionId, int selectedResponse)
        {
            // DialogConditionType.Respond (i=9069)
            return Call(new CallMethodRequest[]
            {
                new(conditionId, new NodeId(0, 9069), new object[] { selectedResponse })
            }, out _);
        }

        /// <summary>
        /// Silence an alarm (suppress audible notification). OPC UA 1.04+.
        /// </summary>
        public StatusCode SilenceAlarm(NodeId alarmId)
        {
            // AlarmConditionType.Silence (i=16402)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16402), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Suppress an alarm (hide from operator view). OPC UA 1.04+.
        /// </summary>
        public StatusCode SuppressAlarm(NodeId alarmId)
        {
            // AlarmConditionType.Suppress (i=16403)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16403), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Unsuppress a previously suppressed alarm. OPC UA 1.04+.
        /// </summary>
        public StatusCode UnsuppressAlarm(NodeId alarmId)
        {
            // AlarmConditionType.Unsuppress (i=16404)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16404), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Remove alarm from service (maintenance mode). OPC UA 1.04+.
        /// </summary>
        public StatusCode RemoveAlarmFromService(NodeId alarmId)
        {
            // AlarmConditionType.RemoveFromService (i=16405)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16405), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Place alarm back in service after maintenance. OPC UA 1.04+.
        /// </summary>
        public StatusCode PlaceAlarmInService(NodeId alarmId)
        {
            // AlarmConditionType.PlaceInService (i=16406)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16406), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Reset a latched alarm. OPC UA 1.04+.
        /// </summary>
        public StatusCode ResetAlarm(NodeId alarmId)
        {
            // AlarmConditionType.Reset (i=16407)
            return Call(new CallMethodRequest[]
            {
                new(alarmId, new NodeId(0, 16407), Array.Empty<object>())
            }, out _);
        }

        /// <summary>
        /// Request a ConditionRefresh2 with MonitoredItem filter. OPC UA 1.04+.
        /// More efficient than ConditionRefresh — only refreshes matching conditions.
        /// </summary>
        public StatusCode ConditionRefresh2(uint subscriptionId, uint monitoredItemId)
        {
            // ConditionType.ConditionRefresh2 (i=12917)
            return Call(new CallMethodRequest[]
            {
                new(new NodeId(0, (uint)UAConst.ConditionType), new NodeId(0, 12917), new object[]
                {
                    subscriptionId,
                    monitoredItemId
                })
            }, out _);
        }

        /// <summary>
        /// Creates an EventFilter for comprehensive Alarm & Condition monitoring.
        /// Includes all standard fields per OPC UA Part 9.
        /// </summary>
        public static EventFilter CreateAlarmEventFilter()
        {
            return new EventFilter(new SimpleAttributeOperand[]
            {
                // Core event fields
                new(new[] { new QualifiedName("EventId") }),
                new(new[] { new QualifiedName("EventType") }),
                new(new[] { new QualifiedName("SourceNode") }),
                new(new[] { new QualifiedName("SourceName") }),
                new(new[] { new QualifiedName("Time") }),
                new(new[] { new QualifiedName("ReceiveTime") }),
                new(new[] { new QualifiedName("Message") }),
                new(new[] { new QualifiedName("Severity") }),
                // Condition fields
                new(new[] { new QualifiedName("ConditionName") }),
                new(new[] { new QualifiedName("ConditionClassId") }),
                new(new[] { new QualifiedName("ConditionClassName") }),
                new(new[] { new QualifiedName("BranchId") }),
                new(new[] { new QualifiedName("Retain") }),
                new(new[] { new QualifiedName("Comment") }),
                new(new[] { new QualifiedName("Comment"), new QualifiedName("SourceTimestamp") }),
                new(new[] { new QualifiedName("ClientUserId") }),
                // State fields
                new(new[] { new QualifiedName("EnabledState"), new QualifiedName("Id") }),
                new(new[] { new QualifiedName("AckedState"), new QualifiedName("Id") }),
                new(new[] { new QualifiedName("ConfirmedState"), new QualifiedName("Id") }),
                new(new[] { new QualifiedName("ActiveState"), new QualifiedName("Id") }),
                new(new[] { new QualifiedName("ActiveState"), new QualifiedName("EffectiveDisplayName") }),
                new(new[] { new QualifiedName("SuppressedState"), new QualifiedName("Id") }),
                new(new[] { new QualifiedName("ShelvingState"), new QualifiedName("CurrentState") }),
                // Alarm-specific fields
                new(new[] { new QualifiedName("LastSeverity") }),
                new(new[] { new QualifiedName("Quality") }),
                new(new[] { new QualifiedName("Quality"), new QualifiedName("SourceTimestamp") }),
            }, null);
        }

        /// <summary>
        /// Index constants for the fields returned by CreateAlarmEventFilter().
        /// Use these to access specific fields in the event notification array.
        /// </summary>
        public static class AlarmField
        {
            public const int EventId = 0;
            public const int EventType = 1;
            public const int SourceNode = 2;
            public const int SourceName = 3;
            public const int Time = 4;
            public const int ReceiveTime = 5;
            public const int Message = 6;
            public const int Severity = 7;
            public const int ConditionName = 8;
            public const int ConditionClassId = 9;
            public const int ConditionClassName = 10;
            public const int BranchId = 11;
            public const int Retain = 12;
            public const int Comment = 13;
            public const int CommentSourceTimestamp = 14;
            public const int ClientUserId = 15;
            public const int EnabledStateId = 16;
            public const int AckedStateId = 17;
            public const int ConfirmedStateId = 18;
            public const int ActiveStateId = 19;
            public const int ActiveStateDisplayName = 20;
            public const int SuppressedStateId = 21;
            public const int ShelvingState = 22;
            public const int LastSeverity = 23;
            public const int Quality = 24;
            public const int QualitySourceTimestamp = 25;
        }

        public StatusCode RegisterNodes(NodeId[] nodesToRegister, out NodeId[] registeredNodeIds)
        {
            registeredNodeIds = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.RegisterNodesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)nodesToRegister.Length);
                for (int i = 0; i < nodesToRegister.Length; i++)
                {
                    succeeded &= sendBuf.Encode(nodesToRegister[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.RegisterNodesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                registeredNodeIds = new NodeId[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out registeredNodeIds[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode UnregisterNodes(NodeId[] nodesToUnregister)
        {
            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.UnregisterNodesRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)nodesToUnregister.Length);
                for (int i = 0; i < nodesToUnregister.Length; i++)
                {
                    succeeded &= sendBuf.Encode(nodesToUnregister[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.UnregisterNodesResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode SetMonitoringMode(uint subscriptionId, MonitoringMode monitoringMode, uint[] monitoredItemIds, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.SetMonitoringModeRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(subscriptionId);
                succeeded &= sendBuf.Encode((UInt32)monitoringMode);
                succeeded &= sendBuf.Encode((UInt32)monitoredItemIds.Length);
                for (int i = 0; i < monitoredItemIds.Length; i++)
                {
                    succeeded &= sendBuf.Encode(monitoredItemIds[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.SetMonitoringModeResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new uint[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode CreateSubscription(double RequestedPublishingInterval, UInt32 MaxNotificationsPerPublish, bool PublishingEnabled, byte Priority, out uint result)
        {
            result = 0xFFFFFFFFu;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateSubscriptionRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(RequestedPublishingInterval);
                succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
                succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
                succeeded &= sendBuf.Encode(MaxNotificationsPerPublish);
                succeeded &= sendBuf.Encode(PublishingEnabled);
                succeeded &= sendBuf.Encode(Priority);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateSubscriptionResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.Decode(out result);

                succeeded &= recvHandler.RecvBuf.Decode(out double revisedPublishInterval);
                succeeded &= recvHandler.RecvBuf.Decode(out uint revisedLifetimeCount);
                succeeded &= recvHandler.RecvBuf.Decode(out uint revisedMaxKeepAliveCount);

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }

            // Send publish requests up to the limit
            while (true)
            {
                int count;
                lock (publishReqsLock) { count = publishReqs.Count; }
                if (count >= MaxOutstandingPublishRequests) break;
                var res = PublishRequest();
                if (res != StatusCode.Good) return res;
            }

            return StatusCode.Good;
        }

        public StatusCode ModifySubscription(uint subscriptionId, double RequestedPublishingInterval, UInt32 MaxNotificationsPerPublish, bool PublishingEnabled, byte Priority, out uint result)
        {
            result = 0;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.ModifySubscriptionRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(subscriptionId);

                succeeded &= sendBuf.Encode(RequestedPublishingInterval);
                succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
                succeeded &= sendBuf.Encode((UInt32)0xFFFFFFFFu);
                succeeded &= sendBuf.Encode(MaxNotificationsPerPublish);
                succeeded &= sendBuf.Encode(PublishingEnabled);
                succeeded &= sendBuf.Encode(Priority);

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ModifySubscriptionResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.Decode(out double revisedPublishInterval);
                succeeded &= recvHandler.RecvBuf.Decode(out uint revisedLifetimeCount);
                succeeded &= recvHandler.RecvBuf.Decode(out uint revisedMaxKeepAliveCount);

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                result = recvHandler.Header.ServiceResult;
                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode DeleteSubscription(uint[] subscriptionIds, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteSubscriptionsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)subscriptionIds.Length);
                for (int i = 0; i < subscriptionIds.Length; i++)
                {
                    succeeded &= sendBuf.Encode(subscriptionIds[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteSubscriptionsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new uint[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode TransferSubscriptions(uint[] subscriptionIds, bool sendInitialValues, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good) return headerRes;

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.TransferSubscriptionsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)subscriptionIds.Length);
                for (int i = 0; i < subscriptionIds.Length; i++)
                    succeeded &= sendBuf.Encode(subscriptionIds[i]);
                succeeded &= sendBuf.Encode(sendInitialValues);

                if (!succeeded) return StatusCode.BadEncodingLimitsExceeded;

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock) { recvNotify[recvKey] = recvEv; }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good) return sendRes;

                bool signalled = recvEv.WaitOne(Timeout * 1000);
                lock (recvNotifyLock) { recvNotify.Remove(recvKey); }
                if (!signalled) return StatusCode.BadRequestTimeout;

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.TransferSubscriptionsResponse))
                    return CheckServiceFaultResponse(recvHandler);

                if (recvHandler.Header != null && Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new uint[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    // TransferResult: StatusCode + AvailableSequenceNumbers[]
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numSeqNums);
                    for (int j = 0; j < numSeqNums; j++)
                        succeeded &= recvHandler.RecvBuf.Decode(out uint _);
                }

                if (!succeeded) return StatusCode.BadDecodingError;
                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode SetTriggering(uint subscriptionId, uint triggeringItemId, uint[] linksToAdd, uint[] linksToRemove, out uint[] addResults, out uint[] removeResults)
        {
            addResults = null;
            removeResults = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good) return headerRes;

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.SetTriggeringRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(subscriptionId);
                succeeded &= sendBuf.Encode(triggeringItemId);

                succeeded &= sendBuf.Encode((UInt32)(linksToAdd?.Length ?? 0));
                if (linksToAdd != null)
                    for (int i = 0; i < linksToAdd.Length; i++)
                        succeeded &= sendBuf.Encode(linksToAdd[i]);

                succeeded &= sendBuf.Encode((UInt32)(linksToRemove?.Length ?? 0));
                if (linksToRemove != null)
                    for (int i = 0; i < linksToRemove.Length; i++)
                        succeeded &= sendBuf.Encode(linksToRemove[i]);

                if (!succeeded) return StatusCode.BadEncodingLimitsExceeded;

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock) { recvNotify[recvKey] = recvEv; }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good) return sendRes;

                bool signalled = recvEv.WaitOne(Timeout * 1000);
                lock (recvNotifyLock) { recvNotify.Remove(recvKey); }
                if (!signalled) return StatusCode.BadRequestTimeout;

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.SetTriggeringResponse))
                    return CheckServiceFaultResponse(recvHandler);

                if (recvHandler.Header != null && Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numAdd);
                addResults = new uint[numAdd];
                for (int i = 0; i < numAdd; i++)
                    succeeded &= recvHandler.RecvBuf.Decode(out addResults[i]);

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numRemove);
                removeResults = new uint[numRemove];
                for (int i = 0; i < numRemove; i++)
                    succeeded &= recvHandler.RecvBuf.Decode(out removeResults[i]);

                if (!succeeded) return StatusCode.BadDecodingError;
                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode Republish(uint subscriptionId, uint retransmitSequenceNumber, out uint notificationSequenceNumber, out DateTimeOffset publishTime)
        {
            notificationSequenceNumber = 0;
            publishTime = DateTimeOffset.MinValue;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good) return headerRes;

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(832)); // RepublishRequest
                succeeded &= sendBuf.Encode(reqHeader);
                succeeded &= sendBuf.Encode(subscriptionId);
                succeeded &= sendBuf.Encode(retransmitSequenceNumber);

                if (!succeeded) return StatusCode.BadEncodingLimitsExceeded;

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock) { recvNotify[recvKey] = recvEv; }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good) return sendRes;

                bool signalled = recvEv.WaitOne(Timeout * 1000);
                lock (recvNotifyLock) { recvNotify.Remove(recvKey); }
                if (!signalled) return StatusCode.BadRequestTimeout;

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, 835)) // RepublishResponse
                    return CheckServiceFaultResponse(recvHandler);

                if (recvHandler.Header != null && Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                // NotificationMessage: SequenceNumber + PublishTime + NotificationData[]
                succeeded &= recvHandler.RecvBuf.Decode(out notificationSequenceNumber);
                succeeded &= recvHandler.RecvBuf.Decode(out ulong publishTimeTick);
                try { publishTime = DateTimeOffset.FromFileTime((long)publishTimeTick); } catch { }

                if (!succeeded) return StatusCode.BadDecodingError;
                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode SetPublishingMode(bool PublishingEnabled, uint[] requestIds, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.SetPublishingModeRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode(PublishingEnabled);
                succeeded &= sendBuf.Encode((UInt32)requestIds.Length);
                for (int i = 0; i < requestIds.Length; i++)
                {
                    succeeded &= sendBuf.Encode((UInt32)requestIds[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.SetPublishingModeResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new uint[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode CreateMonitoredItems(uint subscriptionId, TimestampsToReturn timestampsToReturn, MonitoredItemCreateRequest[] requests, out MonitoredItemCreateResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.CreateMonitoredItemsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)subscriptionId);
                succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.CreateMonitoredItemsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new MonitoredItemCreateResult[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode ModifyMonitoredItems(uint subscriptionId, TimestampsToReturn timestampsToReturn, MonitoredItemModifyRequest[] requests, out MonitoredItemModifyResult[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.ModifyMonitoredItemsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)subscriptionId);
                succeeded &= sendBuf.Encode((UInt32)timestampsToReturn);

                succeeded &= sendBuf.Encode((UInt32)requests.Length);
                for (int i = 0; i < requests.Length; i++)
                {
                    succeeded &= sendBuf.Encode(requests[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.ModifyMonitoredItemsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new MonitoredItemModifyResult[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        public StatusCode DeleteMonitoredItems(uint subscriptionId, uint[] monitorIds, out uint[] results)
        {
            results = null;

            try
            {
                cs.WaitOne();
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.DeleteMonitoredItemsRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                succeeded &= sendBuf.Encode((UInt32)subscriptionId);
                succeeded &= sendBuf.Encode((UInt32)monitorIds.Length);
                for (int i = 0; i < monitorIds.Length; i++)
                {
                    succeeded &= sendBuf.Encode(monitorIds[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                var recvKey = new Tuple<uint, uint>((uint)MessageType.Message, reqHeader.RequestHandle);
                var recvEv = new ManualResetEvent(false);
                lock (recvNotifyLock)
                {
                    recvNotify[recvKey] = recvEv;
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                bool signalled = recvEv.WaitOne(Timeout * 1000);

                lock (recvNotifyLock)
                {
                    recvNotify.Remove(recvKey);
                }

                if (!signalled)
                {
                    return StatusCode.BadRequestTimeout;
                }

                RecvHandler recvHandler = null;
                lock (recvQueueLock)
                {
                    if (!recvQueue.TryGetValue(recvKey, out recvHandler))
                    {
                        return recvHandlerStatus == StatusCode.Good ? StatusCode.BadUnexpectedError : recvHandlerStatus;
                    }

                    recvQueue.Remove(recvKey);
                }

                if (!recvHandler.Type.EqualsNumeric(0, (uint)RequestCode.DeleteMonitoredItemsResponse))
                {
                    return CheckServiceFaultResponse(recvHandler);
                }

                // Check ServiceResult before decoding body
                if (recvHandler.Header != null &&
                    Types.StatusCodeIsBad(recvHandler.Header.ServiceResult))
                {
                    if (Enum.IsDefined(typeof(StatusCode), recvHandler.Header.ServiceResult))
                        return (StatusCode)recvHandler.Header.ServiceResult;
                    return StatusCode.BadUnexpectedError;
                }

                succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numResults);
                results = new uint[numResults];
                for (int i = 0; i < numResults; i++)
                {
                    succeeded &= recvHandler.RecvBuf.Decode(out results[i]);
                }

                if (!succeeded)
                {
                    return StatusCode.BadDecodingError;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
                CheckPostCall();
            }
        }

        private void ConsumeNotification(RecvHandler recvHandler)
        {
            bool succeeded = true;
            succeeded &= recvHandler.RecvBuf.Decode(out uint subscrId);
            // AvailableSequenceNumbers
            succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numSeqNums);
            for (int i = 0; i < numSeqNums; i++) { succeeded &= recvHandler.RecvBuf.Decode(out uint _); }

            succeeded &= recvHandler.RecvBuf.Decode(out bool moreNotifications);
            succeeded &= recvHandler.RecvBuf.Decode(out uint notificationSequenceNumber);

            succeeded &= recvHandler.RecvBuf.Decode(out ulong publishTimeTick);
            DateTimeOffset publishTime;
            try
            {
                publishTime = DateTimeOffset.FromFileTime((long)publishTimeTick);
            }
            catch (ArgumentOutOfRangeException)
            {
                // Invalid file time value — publishTime remains default
            }

            succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numNotificationData);
            for (int i = 0; succeeded && i < numNotificationData; i++)
            {

                succeeded &= recvHandler.RecvBuf.Decode(out NodeId typeId);
                succeeded &= recvHandler.RecvBuf.Decode(out byte bodyType);
                succeeded &= recvHandler.RecvBuf.Decode(out uint _);

                if (bodyType != 1)
                {
                    break;
                }

                if (typeId.EqualsNumeric(0, (uint)UAConst.DataChangeNotification_Encoding_DefaultBinary))
                {
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numDv);

                    if (numDv > 0)
                    {
                        DataValue[] notifications = new DataValue[numDv];
                        uint[] clientHandles = new uint[numDv];
                        for (int j = 0; succeeded && j < numDv; j++)
                        {
                            succeeded &= recvHandler.RecvBuf.Decode(out clientHandles[j]);
                            succeeded &= recvHandler.RecvBuf.Decode(out notifications[j]);
                        }

                        if (!succeeded)
                        {
                            break;
                        }

                        NotifyDataChangeNotifications(subscrId, clientHandles, notifications);
                    }
                }
                else if (typeId.EqualsNumeric(0, (uint)UAConst.EventNotificationList_Encoding_DefaultBinary))
                {
                    succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numDv);

                    if (numDv > 0)
                    {
                        object[][] notifications = new object[numDv][];
                        uint[] clientHandles = new uint[numDv];
                        for (int j = 0; succeeded && j < numDv; j++)
                        {
                            succeeded &= recvHandler.RecvBuf.Decode(out clientHandles[j]);

                            succeeded &= recvHandler.RecvBuf.DecodeArraySize(out uint numFields);
                            notifications[j] = new object[numFields];
                            for (int k = 0; succeeded && k < numFields; k++)
                            {
                                succeeded &= recvHandler.RecvBuf.VariantDecode(out notifications[j][k]);
                            }
                        }

                        if (!succeeded)
                        {
                            break;
                        }

                        NotifyEventNotifications(subscrId, clientHandles, notifications);
                    }
                }
                else
                {
                    break;
                }
            }

            // Track acknowledgement for next PublishRequest
            if (succeeded)
            {
                pendingAcknowledgements.Enqueue((subscrId, notificationSequenceNumber));
            }
        }

        public virtual void NotifyEventNotifications(uint subscrId, uint[] clientHandles, object[][] notifications)
        {
        }

        public virtual void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
        {
        }

        private StatusCode PublishRequest()
        {
            if (!cs.WaitOne(0))
            {
                return StatusCode.GoodCallAgain;
            }

            try
            {
                using var sendBuf = new MemoryBuffer(MaximumMessageSize);
                var headerRes = EncodeMessageHeader(sendBuf, false);
                if (headerRes != StatusCode.Good)
                {
                    return headerRes;
                }

                var reqHeader = new RequestHeader()
                {
                    RequestHandle = nextRequestHandle++,
                    Timestamp = DateTime.UtcNow,
                    AuthToken = config.AuthToken,
                };

                bool succeeded = true;
                succeeded &= sendBuf.Encode(new NodeId(RequestCode.PublishRequest));
                succeeded &= sendBuf.Encode(reqHeader);

                // SubscriptionAcknowledgements
                var acks = new List<(uint subId, uint seqNum)>();
                while (pendingAcknowledgements.TryDequeue(out var ack)) { acks.Add(ack); }
                succeeded &= sendBuf.Encode((UInt32)acks.Count);
                foreach (var (subId, seqNum) in acks)
                {
                    succeeded &= sendBuf.Encode(subId);
                    succeeded &= sendBuf.Encode(seqNum);
                }

                if (!succeeded)
                {
                    return StatusCode.BadEncodingLimitsExceeded;
                }

                lock (publishReqsLock)
                {
                    publishReqs.Add(reqHeader.RequestHandle);
                }

                var sendRes = MessageSecureAndSend(config, sendBuf);
                if (sendRes != StatusCode.Good)
                {
                    return sendRes;
                }

                return StatusCode.Good;
            }
            finally
            {
                cs.Release();
            }
        }
    }
}
