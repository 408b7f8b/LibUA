import asyncio
import uuid
import os
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from asyncua import Server, ua
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256

CERT_DIR = Path("/app/certs")

def generate_self_signed_cert():
    """Generate server certificate and key if not present."""
    CERT_DIR.mkdir(exist_ok=True)
    cert_path = CERT_DIR / "server_cert.pem"
    key_path = CERT_DIR / "server_key.pem"

    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Python asyncua Test Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LibUA Test"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:libua:test:python-asyncua"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, data_encipherment=True,
                content_commitment=True, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # asyncua expects DER for load_certificate despite the .pem extension
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )

    return str(cert_path), str(key_path)


async def main():
    cert_path, key_path = generate_self_signed_cert()

    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4841/freeopcua/server/")
    server.set_server_name("Python asyncua Test Server")

    # Load certificate for security
    await server.load_certificate(cert_path)
    await server.load_private_key(key_path)

    server.set_security_policy(
        [
            ua.SecurityPolicyType.NoSecurity,
            ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
            ua.SecurityPolicyType.Basic256Sha256_Sign,
        ],
    )

    server.set_security_IDs(["Anonymous", "Username"])

    uri = "http://libua.test.python-asyncua"
    idx = await server.register_namespace(uri)

    objects = server.nodes.objects
    test_folder = await objects.add_folder(idx, "TestVariables")

    bool_var = await test_folder.add_variable(idx, "BooleanVar", True)
    int32_var = await test_folder.add_variable(idx, "Int32Var", 42)
    double_var = await test_folder.add_variable(idx, "DoubleVar", 3.14159265)
    string_var = await test_folder.add_variable(idx, "StringVar", "Hello OPC UA")
    datetime_var = await test_folder.add_variable(idx, "DateTimeVar", datetime.now(timezone.utc))
    guid_var = await test_folder.add_variable(idx, "GuidVar", uuid.UUID("72962B91-FA75-4AE6-8D28-B404DC7DAF63"))
    bytestring_var = await test_folder.add_variable(idx, "ByteStringVar", bytes([0x01, 0x02, 0x03, 0x04]))
    float_var = await test_folder.add_variable(idx, "FloatVar", ua.Variant(2.71828, ua.VariantType.Float))
    array_var = await test_folder.add_variable(idx, "Int32ArrayVar", [1, 2, 3, 4, 5])
    counter_var = await test_folder.add_variable(idx, "DynamicCounter", 0)

    await int32_var.set_writable()
    await double_var.set_writable()
    await counter_var.set_writable()

    async with server:
        print("Python asyncua test server running on port 4841")
        print("Security: None + Basic256Sha256 (Sign, SignAndEncrypt)")
        print("Auth: Anonymous + Username (testuser/testpass)")
        counter = 0
        while True:
            await asyncio.sleep(0.5)
            counter += 1
            await counter_var.write_value(counter)

asyncio.run(main())
