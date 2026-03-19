using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LibUA.Core;

namespace LibUA.Tests;

public class CertificateValidationTests
{
    private static (X509Certificate2 cert, RSA key) GenerateCert(
        string cn = "Test",
        string appUri = "urn:test:app",
        string dns = null,
        int validDays = 365,
        int daysOffset = 0)
    {
        using var rsa = RSA.Create(2048);
        var dn = new X500DistinguishedName($"CN={cn}");
        var san = new SubjectAlternativeNameBuilder();
        if (appUri != null) san.AddUri(new Uri(appUri));
        if (dns != null) san.AddDnsName(dns);

        var req = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(daysOffset - 1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(daysOffset + validDays);
        var cert = req.CreateSelfSigned(notBefore, notAfter);

        var key = RSA.Create();
        key.ImportParameters(rsa.ExportParameters(true));
        return (cert, key);
    }

    [Fact]
    public void NullCert_ReturnsBadCertificateInvalid()
    {
        var result = UASecurity.ValidateCertificate(null, new UASecurity.CertificateValidationOptions());
        Assert.Equal(StatusCode.BadCertificateInvalid, result);
    }

    [Fact]
    public void SuppressAllValidation_AlwaysGood()
    {
        var result = UASecurity.ValidateCertificate(null, new UASecurity.CertificateValidationOptions { SuppressAllValidation = true });
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void ValidCert_NoOptions_ReturnsGood()
    {
        var (cert, _) = GenerateCert();
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions());
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void ExpiredCert_ReturnsBadCertificateTimeInvalid()
    {
        var (cert, _) = GenerateCert(validDays: 1, daysOffset: -10);
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions());
        Assert.Equal(StatusCode.BadCertificateTimeInvalid, result);
    }

    [Fact]
    public void FutureCert_ReturnsBadCertificateTimeInvalid()
    {
        var (cert, _) = GenerateCert(daysOffset: 10);
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions());
        Assert.Equal(StatusCode.BadCertificateTimeInvalid, result);
    }

    [Fact]
    public void CorrectApplicationUri_ReturnsGood()
    {
        var (cert, _) = GenerateCert(appUri: "urn:my:server");
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ExpectedApplicationUri = "urn:my:server"
        });
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void WrongApplicationUri_ReturnsBadCertificateUriInvalid()
    {
        var (cert, _) = GenerateCert(appUri: "urn:my:server");
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ExpectedApplicationUri = "urn:other:server"
        });
        Assert.Equal(StatusCode.BadCertificateUriInvalid, result);
    }

    [Fact]
    public void CorrectHostname_ReturnsGood()
    {
        var (cert, _) = GenerateCert(dns: "myserver.local");
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ExpectedHostname = "myserver.local"
        });
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void WrongHostname_ReturnsBadCertificateHostNameInvalid()
    {
        var (cert, _) = GenerateCert(dns: "myserver.local");
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ExpectedHostname = "other.host"
        });
        Assert.Equal(StatusCode.BadCertificateHostNameInvalid, result);
    }

    [Fact]
    public void HostnameInCN_Fallback_ReturnsGood()
    {
        // No DNS SAN, but hostname matches CN
        var (cert, _) = GenerateCert(cn: "myserver.local", dns: null);
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ExpectedHostname = "myserver.local"
        });
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void SelfSigned_AllowSelfSigned_ReturnsGood()
    {
        var (cert, _) = GenerateCert();
        var result = UASecurity.ValidateCertificate(cert, new UASecurity.CertificateValidationOptions
        {
            ValidateChain = true,
            AllowSelfSigned = true,
        });
        Assert.Equal(StatusCode.Good, result);
    }

    [Fact]
    public void BackwardCompatible_VerifyCertificate_StillWorks()
    {
        var (cert, _) = GenerateCert();
        Assert.True(UASecurity.VerifyCertificate(cert));
        Assert.False(UASecurity.VerifyCertificate(null));
    }
}
