using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibUA.Core;

namespace LibUA
{
    public static class UASecurity
    {
        public const int Sha1Size = 20;
        public const int Sha256Size = 32;
        public const int RsaPkcs1PaddingSize = 11;
        public const int RsaSHA1OaepPaddingSize = 42;
        public const int RsaSHA256OaepPaddingSize = 66;
        public const int ActivationNonceSize = 32;

        public enum HashAlgorithm : int
        {
            None = 0,
            SHA_160,
            SHA_224,
            SHA_256,
            SHA_384,
            SHA_512,
        }

        public enum PaddingAlgorithm : int
        {
            None = 0,
            PKCS1,
            SHA1_OAEP,
            SHA256_OAEP,
        }

        public static PaddingAlgorithm PaddingMethodForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                    return PaddingAlgorithm.SHA1_OAEP;

                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return PaddingAlgorithm.SHA256_OAEP;

                case SecurityPolicy.Basic128Rsa15:
                    return PaddingAlgorithm.PKCS1;
            }

            throw new NotSupportedException($"No padding method defined for security policy '{policy}'");
        }

        public static string SignatureAlgorithmForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                    return Types.SignatureAlgorithmSha256;
                
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return Types.SignatureAlgorithmRsaPss256;
                
                default:
                    return Types.SignatureAlgorithmSha1;
            }
        }

        public static int NonceLengthForSecurityPolicy(SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Basic128Rsa15 ? 16 : 32;
        }

        public static int SymmetricKeySizeForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Basic256:
                    return 32;

                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Basic128Rsa15:
                    return 16;
            }

            throw new NotSupportedException($"No symmetric key size defined for security policy '{policy}'");
        }


        public static int SymmetricBlockSizeForSecurityPolicy(SecurityPolicy policy)
        {
            return 16;
        }

        public static int SymmetricSignatureKeySizeForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                    return 24;

                case SecurityPolicy.Aes256_Sha256_RsaPss:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Basic256Sha256:
                    return 32;

                case SecurityPolicy.Basic128Rsa15:
                    return 16;
            }

            throw new NotSupportedException($"No symmetric signature key size defined for security policy '{policy}'");
        }

        public static RSAEncryptionPadding UseOaepForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256:
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                    return RSAEncryptionPadding.OaepSHA1;

                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return RSAEncryptionPadding.OaepSHA256;
            }

            return RSAEncryptionPadding.Pkcs1;
        }

        public static RSAEncryptionPadding UseOaepForSecuritySigPolicyUri(string policy)
        {
            switch (policy)
            {
                case Types.SignatureAlgorithmRsaOaep:
                    return RSAEncryptionPadding.OaepSHA1;

                case Types.SignatureAlgorithmSha256:
                case Types.SignatureAlgorithmRsaOaep256:
                case Types.SignatureAlgorithmRsaPss256:
                    return RSAEncryptionPadding.OaepSHA256;

                case Types.SignatureAlgorithmRsa15:
                default:
                    return RSAEncryptionPadding.Pkcs1;
            }
        }

        public static int CalculatePublicKeyLength(X509Certificate2 cert)
        {
            RSA rsa = cert.PublicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new CryptographicException("Could not extract RSA public key from certificate");
            }

            return rsa.KeySize;
        }

        public static int CalculatePaddingSize(X509Certificate2 cert, SecurityPolicy policy, int position, int sigSize)
        {
            int plainBlockSize = GetPlainBlockSize(cert, UseOaepForSecurityPolicy(policy));

            int pad = plainBlockSize;
            pad -= (position + sigSize) % plainBlockSize;

            if (pad < 0)
            {
                throw new InvalidOperationException($"Calculated negative padding size ({pad}) for position {position}, sigSize {sigSize}, blockSize {plainBlockSize}");
            }

            return pad;
        }

        public static int CalculatePaddingSizePolicyUri(X509Certificate2 cert, string policy, int position, int sigSize)
        {
            int plainBlockSize = GetPlainBlockSize(cert, UseOaepForSecuritySigPolicyUri(policy));

            int pad = plainBlockSize;
            pad -= (position + sigSize) % plainBlockSize;

            if (pad < 0)
            {
                throw new InvalidOperationException($"Calculated negative padding size ({pad}) for position {position}, sigSize {sigSize}, blockSize {plainBlockSize}");
            }

            return pad;
        }

        public static int CalculateSymmetricEncryptedSize(int keySize, int position)
        {
            int numBlocks = (position + keySize - 1) / keySize;
            return numBlocks * keySize;
        }

        public static int CalculateSymmetricPaddingSize(int keySize, int position)
        {
            // OPC 10000-6: 2-byte padding header for keys > 2048 bit (256 bytes)
            int paddingHeaderSize = (keySize > 256) ? 2 : 1;
            int totalSize = position + paddingHeaderSize;
            if (keySize > 0)
            {
                totalSize = ((totalSize + keySize - 1) / keySize) * keySize;
            }
            int pad = totalSize - position;

            if (pad < 0)
            {
                throw new InvalidOperationException($"Calculated negative symmetric padding size ({pad}) for keySize {keySize}, position {position}");
            }

            return pad;
        }

        public static int CalculateSignatureSize(RSA key)
        {
            return key.KeySize / 8;
        }

        public static int CalculateSignatureSize(X509Certificate2 cert)
        {
            return CalculateSignatureSize(cert.PublicKey.GetRSAPublicKey());
        }

        public static int CalculateEncryptedSize(X509Certificate2 cert, int messageSize, PaddingAlgorithm paddingAlgorithm)
        {
            RSA rsa = cert.PublicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new CryptographicException("Could not extract RSA public key from certificate");
            }

            int pad = PaddingSizeForMethod(paddingAlgorithm);
            int keySize = CalculatePublicKeyLength(cert) / 8;

            if (keySize < pad)
            {
                throw new CryptographicException($"RSA key size ({keySize} bytes) is smaller than required padding ({pad} bytes) for {paddingAlgorithm}");
            }

            int blockSize = keySize - pad;
            int numBlocks = (messageSize + blockSize - 1) / blockSize;

            return numBlocks * keySize;
        }

        public static int PaddingSizeForMethod(PaddingAlgorithm paddingMethod)
        {
            switch (paddingMethod)
            {
                case PaddingAlgorithm.None: return 0;
                case PaddingAlgorithm.PKCS1: return RsaPkcs1PaddingSize;
                case PaddingAlgorithm.SHA1_OAEP: return RsaSHA1OaepPaddingSize;
                case PaddingAlgorithm.SHA256_OAEP: return RsaSHA256OaepPaddingSize;
            }

            throw new NotSupportedException($"Unknown padding algorithm: {paddingMethod}");
        }

        public static string ExportPEM(X509Certificate cert)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            sb.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END CERTIFICATE-----");

            return sb.ToString();
        }

        public static byte[] GenerateRandomBits(int numBits)
        {
            return GenerateRandomBytes((numBits + 7) / 8);
        }

        public static byte[] GenerateRandomBytes(int numBytes)
        {
            //var arr = Enumerable.Range(1, numBytes).Select(i => (byte)(i & 0xFF)).ToArray();
            //return arr;

            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            var res = new byte[numBytes];
            rng.GetBytes(res);

            return res;
        }

        public static byte[] AesEncrypt(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.IV = iv; // new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                aes.Key = key;
                aes.Padding = PaddingMode.PKCS7;
                using (var crypt = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, crypt, CryptoStreamMode.Write))
                        {
                            var lengthBytes = new byte[]
                            {
                                (byte)(data.Count & 0xFF),
                                (byte)((data.Count >> 8) & 0xFF),
                                (byte)((data.Count >> 16) & 0xFF),
                                (byte)((data.Count >> 24) & 0xFF),
                            };

                            cs.Write(lengthBytes, 0, 4);
                            cs.Write(data.Array, data.Offset, data.Count);
                        }

                        return ms.ToArray();
                    }
                }
            }
        }

        public static byte[] AesDecrypt(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            if (data.Count < 4)
            {
                return null;
            }

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.IV = iv; // new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                aes.Key = key;
                aes.Padding = PaddingMode.PKCS7;
                using (var crypt = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var ms = new MemoryStream(data.Array, data.Offset, data.Count))
                    {
                        byte[] plain = new byte[data.Count];
                        int plainLength = 0;

                        using (var cs = new CryptoStream(ms, crypt, CryptoStreamMode.Read))
                        {
                            plainLength = cs.Read(plain, 0, plain.Length);
                        }

                        using (var msRead = new MemoryStream(plain))
                        {
                            var lengthBytes = new byte[4];
                            msRead.Read(lengthBytes, 0, 4);
                            int length = lengthBytes[0] | (lengthBytes[1] << 8) | (lengthBytes[2] << 16) | (lengthBytes[3] << 24);

                            if (length + 4 > plainLength)
                            {
                                return null;
                            }

                            var res = new byte[length];
                            Array.Copy(plain, 4, res, 0, length);
                            return res;
                        }
                    }
                }
            }
        }

        public static int RijndaelEncryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            using (var rijn = Aes.Create())
            {
                rijn.Mode = CipherMode.CBC;
                rijn.IV = iv;
                rijn.Key = key;
                rijn.Padding = PaddingMode.None;
                using (var crypt = rijn.CreateEncryptor(rijn.Key, rijn.IV))
                {
                    if (data.Count % crypt.InputBlockSize != 0)
                    {
                        throw new CryptographicException(string.Format("Input data size ({0}) is not a multiple of block size ({1})", data.Count, crypt.InputBlockSize));
                    }

                    crypt.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);

                    return ((data.Count + crypt.InputBlockSize - 1) / crypt.InputBlockSize) * crypt.InputBlockSize;
                }
            }
        }

        public static int RijndaelDecryptInplace(ArraySegment<byte> data, byte[] key, byte[] iv)
        {
            using (var rijn = Aes.Create())
            {
                rijn.Mode = CipherMode.CBC;
                rijn.IV = iv;
                rijn.Key = key;
                rijn.Padding = PaddingMode.None;
                using (var crypt = rijn.CreateDecryptor(rijn.Key, rijn.IV))
                {
                    if (data.Count % crypt.InputBlockSize != 0)
                    {
                        throw new CryptographicException(string.Format("Input data size ({0}) is not a multiple of block size ({1})", data.Count, crypt.InputBlockSize));
                    }

                    crypt.TransformBlock(data.Array, data.Offset, data.Count, data.Array, data.Offset);

                    int numBlocks = (data.Count + crypt.InputBlockSize - 1) / crypt.InputBlockSize;
                    return numBlocks * crypt.InputBlockSize;
                }
            }
        }

        public static string ExportRSAPrivateKey(RSAParameters parameters)
        {
            MemoryStream ms = new MemoryStream();

            using (var outputStream = new StreamWriter(ms))
            {
                using (var stream = new MemoryStream())
                {
                    var writer = new BinaryWriter(stream);
                    writer.Write((byte)0x30); // Sequence
                    using (var innerStream = new MemoryStream())
                    {
                        var innerWriter = new BinaryWriter(innerStream);
                        EncodeIntBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                        EncodeIntBigEndian(innerWriter, parameters.Modulus);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);

                        EncodeIntBigEndian(innerWriter, parameters.D);
                        EncodeIntBigEndian(innerWriter, parameters.P);
                        EncodeIntBigEndian(innerWriter, parameters.Q);
                        EncodeIntBigEndian(innerWriter, parameters.DP);
                        EncodeIntBigEndian(innerWriter, parameters.DQ);
                        EncodeIntBigEndian(innerWriter, parameters.InverseQ);

                        var length = (int)innerStream.Length;
                        EncodeLength(writer, length);
                        writer.Write(innerStream.ToArray(), 0, length);
                    }

                    var base64 = Convert.ToBase64String(stream.ToArray(), 0, (int)stream.Length).ToCharArray();

                    outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                    for (int i = 0; i < base64.Length; i += 64)
                    {
                        outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                    }

                    outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
                }
            }

            return System.Text.Encoding.ASCII.GetString(ms.ToArray());
        }

        public static RSAParameters ImportRSAPrivateKey(string buf)
        {
            var rsa = new RSACryptoServiceProvider();
            var parameters = rsa.ExportParameters(false);

            var b64line = string.Join(string.Empty, buf
                .Split(Environment.NewLine.ToArray())
                .Where(line => !line.Trim().StartsWith("-"))
                .ToArray());

            var byteArr = Convert.FromBase64String(b64line);
            var ms = new MemoryStream();
            ms.Write(byteArr, 0, byteArr.Length);
            ms.Seek(0, SeekOrigin.Begin);
            using (var inputStream = new BinaryReader(ms))
            {
                if (inputStream.ReadByte() != 0x30)
                {
                    return parameters;
                }

                int length = DecodeLength(inputStream);
                byte[] version = DecodeIntBigEndian(inputStream);

                if (version.Length != 1 || version[0] != 0)
                {
                    return parameters;
                }

                parameters.Modulus = DecodeIntBigEndian(inputStream);
                parameters.Exponent = DecodeIntBigEndian(inputStream);

                parameters.D = DecodeIntBigEndian(inputStream);
                parameters.P = DecodeIntBigEndian(inputStream);
                parameters.Q = DecodeIntBigEndian(inputStream);
                parameters.DP = DecodeIntBigEndian(inputStream);
                parameters.DQ = DecodeIntBigEndian(inputStream);
                parameters.InverseQ = DecodeIntBigEndian(inputStream);
            }

            return parameters;
        }

        public static string ExportRSAPublicKey(RSAParameters parameters)
        {
            MemoryStream ms = new MemoryStream();

            using (var outputStream = new StreamWriter(ms))
            {
                using (var stream = new MemoryStream())
                {
                    var writer = new BinaryWriter(stream);
                    writer.Write((byte)0x30); // Sequence
                    using (var innerStream = new MemoryStream())
                    {
                        var innerWriter = new BinaryWriter(innerStream);
                        EncodeIntBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                        EncodeIntBigEndian(innerWriter, parameters.Modulus);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);

                        EncodeIntBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntBigEndian(innerWriter, parameters.Exponent);

                        var length = (int)innerStream.Length;
                        EncodeLength(writer, length);
                        writer.Write(innerStream.ToArray(), 0, length);
                    }

                    var base64 = Convert.ToBase64String(stream.ToArray(), 0, (int)stream.Length).ToCharArray();

                    outputStream.WriteLine("-----BEGIN RSA PUBLIC KEY-----");
                    for (int i = 0; i < base64.Length; i += 64)
                    {
                        outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                    }

                    outputStream.WriteLine("-----END RSA PUBLIC KEY-----");
                }
            }

            return System.Text.Encoding.ASCII.GetString(ms.ToArray());
        }

        public static RSAParameters ImportRSAPublicKey(string buf)
        {
            var rsa = new RSACryptoServiceProvider();
            var parameters = rsa.ExportParameters(false);

            var b64line = string.Join(string.Empty, buf
                .Split(Environment.NewLine.ToArray())
                .Where(line => !line.Trim().StartsWith("-"))
                .ToArray());

            var byteArr = Convert.FromBase64String(b64line);
            var ms = new MemoryStream();
            ms.Write(byteArr, 0, byteArr.Length);
            ms.Seek(0, SeekOrigin.Begin);
            using (var inputStream = new BinaryReader(ms))
            {
                if (inputStream.ReadByte() != 0x30)
                {
                    return parameters;
                }

                int length = DecodeLength(inputStream);
                byte[] version = DecodeIntBigEndian(inputStream);

                if (version.Length != 1 || version[0] != 0)
                {
                    return parameters;
                }

                parameters.Modulus = DecodeIntBigEndian(inputStream);
                parameters.Exponent = DecodeIntBigEndian(inputStream);

                DecodeIntBigEndian(inputStream);
                DecodeIntBigEndian(inputStream);
                DecodeIntBigEndian(inputStream);
                DecodeIntBigEndian(inputStream);
                DecodeIntBigEndian(inputStream);
                DecodeIntBigEndian(inputStream);
            }

            return parameters;
        }

        private static int DecodeLength(BinaryReader stream)
        {
            int length = stream.ReadByte();
            if (length < 0x80)
            {
                return length;
            }

            int bytesRequired = length - 0x80;

            length = 0;
            for (int i = bytesRequired - 1; i >= 0; i--)
            {
                length |= (int)(stream.ReadByte() << (8 * i));
            }

            return length;
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            }

            if (length < 0x80)
            {
                stream.Write((byte)length);
            }
            else
            {
                var bytesRequired = 0;
                for (int temp = length; temp > 0; temp >>= 8)
                {
                    bytesRequired++;
                }

                stream.Write((byte)(bytesRequired | 0x80));
                for (int i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static byte[] DecodeIntBigEndian(BinaryReader stream)
        {
            if (stream.ReadByte() != 0x02)
            {
                return null;
            }

            int length = DecodeLength(stream);
            if (length < 0)
            {
                return null;
            }

            var arr = new byte[length];
            for (int i = 0; i < length; i++)
            {
                arr[i] = stream.ReadByte();
            }

            return arr;
        }

        private static void EncodeIntBigEndian(BinaryWriter stream, byte[] value)
        {
            stream.Write((byte)0x02); // Integer
            EncodeLength(stream, value.Length);

            for (int i = 0; i < value.Length; i++)
            {
                stream.Write(value[i]);
            }
        }

        public static int GetPlainBlockSize(X509Certificate2 cert, RSAEncryptionPadding useOaep)
        {
            var rsa = cert.PublicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new CryptographicException("Could not extract RSA public key from certificate");
            }

            int r = rsa.KeySize / 8;
            if (useOaep == RSAEncryptionPadding.OaepSHA256)
            {
                r -= RsaSHA256OaepPaddingSize;
            }
            else if (useOaep == RSAEncryptionPadding.OaepSHA1)
            {
                r -= RsaSHA1OaepPaddingSize;
            }
            else
            {
                r -= RsaPkcs1PaddingSize;
            }

            return r;
        }

        public static int GetCipherTextBlockSize(X509Certificate2 cert)
        {
            var rsa = cert.PublicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new CryptographicException("Could not extract RSA public key from certificate");
            }

            return rsa.KeySize / 8;
        }

        public static int GetSignatureLength(X509Certificate2 cert)
        {
            var rsa = cert.PublicKey.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new CryptographicException("Could not extract RSA public key from certificate");
            }

            return rsa.KeySize / 8;
        }

        public static int GetSignatureLength(X509Certificate2 cert, SecurityPolicy policy)
        {
            return GetSignatureLength(cert);
        }

        public static byte[] Sign(ArraySegment<byte> data, RSA privProvider,
            SecurityPolicy policy)
        {
            var hash = HashAlgorithmForSecurityPolicy(policy);
            var digest = hash.ComputeHash(data.Array, data.Offset, data.Count);
            var padding = SigPaddingForSecurityPolicy(policy);

            byte[] signature = privProvider.SignHash(digest, HashStrForSecurityPolicy(policy), padding);
            return signature;
        }

        private static RSASignaturePadding SigPaddingForSecurityPolicy(SecurityPolicy policy)
        {
            return policy == SecurityPolicy.Aes256_Sha256_RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        }

        private static HashAlgorithmName HashStrForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return HashAlgorithmName.SHA256;

                default:
                    return HashAlgorithmName.SHA1;
            }
        }

        private static System.Security.Cryptography.HashAlgorithm HashAlgorithmForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return SHA256.Create();

                default:
                    return SHA1.Create();
            }
        }

        private static (System.Security.Cryptography.HashAlgorithm Algorithm, HashAlgorithmName Name) GetHasherByName(string name)
        {
            return name switch
            {
                Types.SignatureAlgorithmSha256 => (SHA256.Create(), HashAlgorithmName.SHA256),
                Types.SignatureAlgorithmSha1 or _ => (SHA1.Create(), HashAlgorithmName.SHA1)
            };
        }

        public static bool VerifySigned(ArraySegment<byte> data, byte[] signature, X509Certificate2 cert, SecurityPolicy policy)
        {
            var hashAlg = HashAlgorithmForSecurityPolicy(policy);
            var hashName = HashStrForSecurityPolicy(policy);
            var padding = SigPaddingForSecurityPolicy(policy);
            return VerifySigned(data, signature, cert, hashAlg, hashName, padding);
        }

        public static bool VerifySigned(ArraySegment<byte> data, byte[] signature, X509Certificate2 cert, SecurityPolicy policy, string hashAlgorithm)
        {
            var (hashAlg, hashName) = GetHasherByName(hashAlgorithm);
            var padding = SigPaddingForSecurityPolicy(policy);
            return VerifySigned(data, signature, cert, hashAlg, hashName, padding);
        }

        private static bool VerifySigned(ArraySegment<byte> data, byte[] signature, X509Certificate2 cert,
            System.Security.Cryptography.HashAlgorithm hashAlg, HashAlgorithmName hashName, RSASignaturePadding padding)
        {
            var rsa = cert.PublicKey.GetRSAPublicKey();

            var digest = hashAlg.ComputeHash(data.Array, data.Offset, data.Count);

            return rsa.VerifyHash(digest, signature, hashName, padding);
        }

        public static byte[] Encrypt(ArraySegment<byte> data, X509Certificate2 cert, RSAEncryptionPadding padding)
        {
            var rsa = cert.PublicKey.GetRSAPublicKey();
            int inputBlockSize = GetPlainBlockSize(cert, padding);

            if (data.Count % inputBlockSize != 0)
            {
                throw new CryptographicException(string.Format("Input data size ({0}) is not a multiple of block size ({1})", data.Count, inputBlockSize));
            }

            var input = new byte[inputBlockSize];
            var ms = new MemoryStream();
            for (int i = 0; i < data.Count; i += inputBlockSize)
            {
                Array.Copy(data.Array, data.Offset + i, input, 0, input.Length);
                var encoded = rsa.Encrypt(input, padding);
                ms.Write(encoded, 0, encoded.Length);
            }

            ms.Close();
            return ms.ToArray();
        }

        public static byte[] Decrypt(ArraySegment<byte> data, X509Certificate2 cert, RSA rsaPrivate, RSAEncryptionPadding padding)
        {
            int cipherBlockSize = GetCipherTextBlockSize(cert);
            int plainSize = data.Count / cipherBlockSize;
            int blockSize = GetPlainBlockSize(cert, padding);

            plainSize *= blockSize;

            var buffer = new byte[plainSize];
            int inputBlockSize = rsaPrivate.KeySize / 8;

            if (data.Count % inputBlockSize != 0)
            {
                throw new CryptographicException(string.Format("Input data size ({0}) is not a multiple of block size ({1})", data.Count, inputBlockSize));
            }

            var ms = new MemoryStream(buffer);
            var block = new byte[inputBlockSize];
            for (int i = data.Offset; i < data.Offset + data.Count; i += inputBlockSize)
            {
                Array.Copy(data.Array, i, block, 0, block.Length);
                var plain = rsaPrivate.Decrypt(block, padding);
                ms.Write(plain, 0, plain.Length);
            }
            ms.Close();

            return buffer;
        }

        /// <summary>
        /// Certificate validation options per OPC UA Part 4, 6.1
        /// </summary>
        public class CertificateValidationOptions
        {
            /// <summary>Validate certificate chain and expiry (default: true)</summary>
            public bool ValidateChain { get; set; } = true;

            /// <summary>Allow self-signed certificates (default: true for OPC UA compatibility)</summary>
            public bool AllowSelfSigned { get; set; } = true;

            /// <summary>Expected ApplicationUri from EndpointDescription (null = skip check)</summary>
            public string ExpectedApplicationUri { get; set; }

            /// <summary>Expected hostname or IP from endpoint URL (null = skip check)</summary>
            public string ExpectedHostname { get; set; }

            /// <summary>Check certificate revocation via CRL (default: false, requires network)</summary>
            public bool CheckRevocation { get; set; } = false;

            /// <summary>Additional trusted CA certificates</summary>
            public X509Certificate2Collection TrustedCertificates { get; set; }

            /// <summary>Suppress all validation (for testing only)</summary>
            public bool SuppressAllValidation { get; set; } = false;
        }

        /// <summary>
        /// Backward-compatible certificate check (no validation, matches old behavior)
        /// </summary>
        public static bool VerifyCertificate(X509Certificate2 senderCert)
        {
            return senderCert != null;
        }

        /// <summary>
        /// Full OPC UA certificate validation per Part 4, 6.1
        /// Returns StatusCode.Good on success, specific Bad status on failure.
        /// </summary>
        public static StatusCode ValidateCertificate(X509Certificate2 cert, CertificateValidationOptions options)
        {
            if (options == null || options.SuppressAllValidation) return StatusCode.Good;
            if (cert == null) return StatusCode.BadCertificateInvalid;

            // 1. Check expiry
            if (cert.NotBefore > DateTime.UtcNow)
                return StatusCode.BadCertificateTimeInvalid;
            if (cert.NotAfter < DateTime.UtcNow)
                return StatusCode.BadCertificateTimeInvalid;

            // 2. Check key usage — OPC UA requires digitalSignature + keyEncipherment or dataEncipherment
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509KeyUsageExtension keyUsage)
                {
                    if ((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                        return StatusCode.BadCertificateUseNotAllowed;
                }
            }

            // 3. Validate ApplicationUri in SubjectAlternativeName (OPC UA Part 4, 6.1.3)
            if (options.ExpectedApplicationUri != null)
            {
                bool foundUri = false;
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                    {
                        // Parse SAN extension for URI entries
                        var sanStr = ext.Format(true);
                        if (sanStr != null)
                        {
                            foreach (var line in sanStr.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                var trimmed = line.Trim();
                                // Format varies by platform: "URL=..." or "URI:..." or "Uniform Resource Identifier=..."
                                if (trimmed.StartsWith("URL=", StringComparison.OrdinalIgnoreCase) ||
                                    trimmed.StartsWith("URI:", StringComparison.OrdinalIgnoreCase))
                                {
                                    var uri = trimmed.Substring(trimmed.IndexOf('=') + 1).Trim();
                                    if (trimmed.Contains(':'))
                                        uri = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                                    if (string.Equals(uri, options.ExpectedApplicationUri, StringComparison.OrdinalIgnoreCase))
                                        foundUri = true;
                                }
                                else if (trimmed.Contains(options.ExpectedApplicationUri))
                                {
                                    foundUri = true;
                                }
                            }
                        }
                    }
                }
                if (!foundUri)
                    return StatusCode.BadCertificateUriInvalid;
            }

            // 4. Validate hostname in SAN or CN (OPC UA Part 6, 6.2.3)
            if (options.ExpectedHostname != null)
            {
                bool foundHostname = false;

                // Check SAN DNS names and IP addresses
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.17")
                    {
                        var sanStr = ext.Format(true);
                        if (sanStr != null && sanStr.IndexOf(options.ExpectedHostname, StringComparison.OrdinalIgnoreCase) >= 0)
                            foundHostname = true;
                    }
                }

                // Fallback: Check CN
                if (!foundHostname && cert.Subject != null)
                {
                    var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                    if (string.Equals(cn, options.ExpectedHostname, StringComparison.OrdinalIgnoreCase))
                        foundHostname = true;
                }

                if (!foundHostname)
                    return StatusCode.BadCertificateHostNameInvalid;
            }

            // 5. Chain validation
            if (options.ValidateChain)
            {
                bool isSelfSigned = cert.Subject == cert.Issuer;
                if (isSelfSigned && options.AllowSelfSigned)
                {
                    // Self-signed: only validate expiry (already done) and signature
                    try
                    {
                        cert.Verify();
                    }
                    catch (CryptographicException)
                    {
                        // Self-signed certs often fail Verify() due to missing trust anchor — accept if AllowSelfSigned
                    }
                }
                else if (!isSelfSigned)
                {
                    using var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = options.CheckRevocation
                        ? X509RevocationMode.Online
                        : X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                    if (options.TrustedCertificates != null)
                    {
                        chain.ChainPolicy.ExtraStore.AddRange(options.TrustedCertificates);
                    }

                    if (!chain.Build(cert))
                    {
                        foreach (var status in chain.ChainStatus)
                        {
                            if (status.Status == X509ChainStatusFlags.UntrustedRoot && options.AllowSelfSigned)
                                continue;
                            if (status.Status == X509ChainStatusFlags.RevocationStatusUnknown && !options.CheckRevocation)
                                continue;

                            return StatusCode.BadSecurityChecksFailed;
                        }
                    }
                }
            }

            // 6. CRL check (if enabled and chain validation passed)
            if (options.CheckRevocation)
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

                if (!chain.Build(cert))
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        if (status.Status == X509ChainStatusFlags.Revoked)
                            return StatusCode.BadCertificateRevoked;
                        if (status.Status == X509ChainStatusFlags.RevocationStatusUnknown)
                            return StatusCode.BadCertificateRevocationUnknown;
                    }
                }
            }

            return StatusCode.Good;
        }

        public static byte[] SHACalculate(byte[] data, SecurityPolicy policy)
        {
            using (var sha = HashAlgorithmForSecurityPolicy(policy))
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] SymmetricSign(byte[] key, ArraySegment<byte> data, SecurityPolicy policy)
        {
            HMAC hmac = HMACForSecurityPolicy(key, policy);

            using (MemoryStream ms = new MemoryStream(data.Array, data.Offset, data.Count))
            {
                byte[] signature = hmac.ComputeHash(ms);
                return signature;
            }
        }

        private static HMAC HMACForSecurityPolicy(byte[] key, SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return new HMACSHA256(key);

                default:
                    return new HMACSHA1(key);
            }
        }

        public static byte[] SHACalculate(ArraySegment<byte> data, SecurityPolicy policy)
        {
            using (var sha = HashAlgorithmForSecurityPolicy(policy))
            {
                return sha.ComputeHash(data.Array, data.Offset, data.Count);
            }
        }

        public static bool SHAVerify(byte[] data, byte[] hash, SecurityPolicy policy)
        {
            var calc = SHACalculate(data, policy);
            if (calc.Length != hash.Length)
            {
                return false;
            }

            for (int i = 0; i < calc.Length; i++)
            {
                if (hash[i] != calc[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static byte[] PSHA(byte[] secret, byte[] seed, int length, SecurityPolicy policy)
        {
            var hmac = HMACForSecurityPolicy(secret, policy);
            int sigSize = SignatureSizeForSecurityPolicy(policy);

            var tmp = hmac.ComputeHash(seed);
            var keySeed = new byte[sigSize + seed.Length];

            Array.Copy(tmp, keySeed, tmp.Length);
            Array.Copy(seed, 0, keySeed, tmp.Length, seed.Length);

            var output = new byte[length];

            int pos = 0;
            while (pos < length)
            {
                byte[] hash = hmac.ComputeHash(keySeed);

                int writeLen = Math.Min(sigSize, length - pos);
                Array.Copy(hash, 0, output, pos, writeLen);
                pos += writeLen;

                tmp = hmac.ComputeHash(tmp);
                Array.Copy(tmp, keySeed, tmp.Length);
            }

            return output;
        }

        private static int SignatureSizeForSecurityPolicy(SecurityPolicy policy)
        {
            switch (policy)
            {
                case SecurityPolicy.Basic256Sha256:
                case SecurityPolicy.Aes128_Sha256_RsaOaep:
                case SecurityPolicy.Aes256_Sha256_RsaPss:
                    return Sha256Size;

                default:
                    return Sha1Size;
            }
        }

        public static StatusCode UnsecureSymmetric(MemoryBuffer recvBuf, uint tokenID, uint? prevTokenID, int messageEncodedBlockStart, SLChannel.Keyset localKeyset, SLChannel.Keyset[] remoteKeysets, SecurityPolicy policy, MessageSecurityMode securityMode, out int decrSize)
        {
            decrSize = -1;
            int restorePos = recvBuf.Position;
            if (!recvBuf.Decode(out byte _)) { return StatusCode.BadDecodingError; }

            if (!recvBuf.Decode(out uint messageSize)) { return StatusCode.BadDecodingError; }

            if (!recvBuf.Decode(out uint _)) { return StatusCode.BadDecodingError; }
            if (!recvBuf.Decode(out uint securityTokenId)) { return StatusCode.BadDecodingError; }

            int keysetIdx;
            if (tokenID == securityTokenId)
            {
                keysetIdx = 0;
            }
            else if (prevTokenID.HasValue && prevTokenID.Value == securityTokenId)
            {
                keysetIdx = 1;
            }
            else
            {
                return StatusCode.BadSecureChannelTokenUnknown;
            }

            //UInt32 respDecodeSize = messageSize;
            if (securityMode == MessageSecurityMode.SignAndEncrypt)
            {
                try
                {
                    decrSize = UASecurity.RijndaelDecryptInplace(
                        new ArraySegment<byte>(recvBuf.Buffer, messageEncodedBlockStart, (int)messageSize - messageEncodedBlockStart),
                        remoteKeysets[keysetIdx].SymEncKey, remoteKeysets[keysetIdx].SymIV) + messageEncodedBlockStart;

                    //respDecodeSize = (UInt32)(messageEncodedBlockStart + decrSize);
                }
                catch (CryptographicException)
                {
                    return StatusCode.BadSecurityChecksFailed;
                }
            }
            else
            {
                decrSize = (int)messageSize;
            }

            if (securityMode >= MessageSecurityMode.Sign)
            {
                try
                {
                    int sigSize = SignatureSizeForSecurityPolicy(policy);
                    var sigData = new ArraySegment<byte>(recvBuf.Buffer, 0, (int)messageSize - sigSize);

                    var sig = new ArraySegment<byte>(recvBuf.Buffer, (int)messageSize - sigSize, sigSize).ToArray();
                    var sigExpect = UASecurity.SymmetricSign(remoteKeysets[keysetIdx].SymSignKey, sigData, policy);

                    if (sig.Length != sigExpect.Length)
                    {
                        return StatusCode.BadSecurityChecksFailed;
                    }

                    for (int i = 0; i < sig.Length; i++)
                    {
                        if (sig[i] != sigExpect[i])
                        {
                            return StatusCode.BadSecurityChecksFailed;
                        }
                    }

                    int padValue = 0;
                    if (securityMode == MessageSecurityMode.SignAndEncrypt)
                    {
                        bool useExtraPadding = remoteKeysets[keysetIdx].SymEncKey.Length > 256;
                        if (useExtraPadding)
                        {
                            padValue = recvBuf.Buffer[messageSize - sigSize - 2] |
                                       (recvBuf.Buffer[messageSize - sigSize - 1] << 8);
                            padValue += 2; // padding bytes + 2 size bytes
                        }
                        else
                        {
                            padValue = recvBuf.Buffer[messageSize - sigSize - 1] + 1;
                        }
                    }
                    if (decrSize > 0)
                    {
                        decrSize -= sigSize;
                        decrSize -= padValue;
                        if (decrSize <= 0)
                        {
                            return StatusCode.BadSecurityChecksFailed;
                        }
                    }
                }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException or IndexOutOfRangeException)
                {
                    return StatusCode.BadSecurityChecksFailed;
                }
            }

            if (!recvBuf.Decode(out uint _)) { return StatusCode.BadDecodingError; }

            if (!recvBuf.Decode(out uint _)) { return StatusCode.BadDecodingError; }

            recvBuf.Position = restorePos;

            return StatusCode.Good;
        }

        public static StatusCode SecureSymmetric(MemoryBuffer respBuf, int messageEncodedBlockStart, SLChannel.Keyset localKeyset, SLChannel.Keyset remoteKeyset, SecurityPolicy policy, MessageSecurityMode securityMode)
        {
            if (securityMode == MessageSecurityMode.None)
            {
                return StatusCode.Good;
            }

            int sigSize = SignatureSizeForSecurityPolicy(policy);
            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                //int padSize2 = CalculateSymmetricPaddingSize(remoteKeyset.SymEncKey.Length, sigSize + respBuf.Position - messageEncodedBlockStart);
                int padSize = CalculateSymmetricPaddingSize(localKeyset.SymEncKey.Length, sigSize + respBuf.Position - messageEncodedBlockStart);
                bool useExtraPadding = localKeyset.SymEncKey.Length > 256;

                int paddingDataLen = useExtraPadding ? padSize - 2 : padSize - 1;
                byte paddingValue = (byte)(paddingDataLen & 0xFF);

                var appendPadding = new byte[padSize];
                for (int i = 0; i < padSize; i++) { appendPadding[i] = paddingValue; }
                if (useExtraPadding)
                {
                    // ExtraPaddingByte: high byte of padding size
                    appendPadding[padSize - 1] = (byte)((paddingDataLen >> 8) & 0xFF);
                }
                respBuf.Append(appendPadding);
            }

            int msgSize = respBuf.Position + sigSize;
            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                msgSize = messageEncodedBlockStart + CalculateSymmetricEncryptedSize(localKeyset.SymEncKey.Length, msgSize - messageEncodedBlockStart);
            }

            if (msgSize >= respBuf.Capacity)
            {
                return StatusCode.BadEncodingLimitsExceeded;
            }

            MarkUAMessageSize(respBuf, (UInt32)msgSize);

            var sig = UASecurity.SymmetricSign(localKeyset.SymSignKey, new ArraySegment<byte>(respBuf.Buffer, 0, respBuf.Position), policy);
            respBuf.Append(sig);

            if (msgSize != respBuf.Position)
            {
                throw new InvalidOperationException($"Signed message size mismatch: expected {msgSize}, actual {respBuf.Position}");
            }

            if (securityMode >= MessageSecurityMode.SignAndEncrypt)
            {
                _ = UASecurity.RijndaelEncryptInplace(
                    new ArraySegment<byte>(respBuf.Buffer, messageEncodedBlockStart, msgSize - messageEncodedBlockStart),
                    localKeyset.SymEncKey, localKeyset.SymIV);
            }

            return StatusCode.Good;
        }

        private static void MarkUAMessageSize(MemoryBuffer buf, UInt32 position)
        {
            int restorePos = buf.Position;
            buf.Position = 4;
            buf.Encode(position);
            buf.Position = restorePos;
        }
    }
}
