using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using LibUA;
using LibUA.Core;

namespace DiagnosticTestClient;

/// <summary>
/// Instrumentierter Client der die rohen Response-Bytes sichtbar macht.
/// Überschreibt Read mit manueller Byte-Analyse.
/// </summary>
internal static class ByteDump
{
    private class InstrumentedClient : Client
    {
        private X509Certificate2? appCert;
        private RSA? appKey;
        public override X509Certificate2? ApplicationCertificate => appCert;
        public override RSA? ApplicationPrivateKey => appKey;

        public InstrumentedClient(string target, int port, int timeout) : base(target, port, timeout)
        {
            using var rsa = RSA.Create(2048);
            var dn = new X500DistinguishedName("CN=ByteDump;OU=Test", X500DistinguishedNameFlags.UseSemicolons);
            var san = new SubjectAlternativeNameBuilder();
            san.AddUri(new Uri("urn:LibUA:ByteDump"));
            var req = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(san.Build());
            appCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
            appKey = RSA.Create();
            appKey.ImportParameters(rsa.ExportParameters(true));
        }
    }

    public static void RunByteDump(string name, string host, int port)
    {
        Console.WriteLine($"\n{'=',-80}");
        Console.WriteLine($"  BYTE-DUMP: {name} ({host}:{port})");
        Console.WriteLine($"{'=',-80}\n");

        var client = new InstrumentedClient(host, port, 10);

        try
        {
            var res = client.Connect();
            if (res != StatusCode.Good) { Console.WriteLine($"  Connect failed: {res}"); return; }

            res = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            if (res != StatusCode.Good) { Console.WriteLine($"  OpenSecureChannel failed: {res}"); return; }

            // GetEndpoints first, then establish session in same connection
            client.FindServers(out _, new[] { "en" });
            client.GetEndpoints(out EndpointDescription[] eps, new[] { "en" });

            string policyId = "0";
            if (eps != null)
            {
                var noneEp = eps.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                var anonTok = noneEp?.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                if (anonTok != null) policyId = anonTok.PolicyId;
            }

            var appDesc = new ApplicationDescription("urn:LibUA:ByteDump", "uri:LibUA:ByteDump",
                new LocalizedText("ByteDump"), ApplicationType.Client, null, null, null);

            res = client.CreateSession(appDesc, "urn:LibUA:ByteDump", 120);
            if (res != StatusCode.Good) { Console.WriteLine($"  CreateSession failed: {res}"); return; }

            res = client.ActivateSession(new UserIdentityAnonymousToken(policyId), new[] { "en" });
            if (res != StatusCode.Good) { Console.WriteLine($"  ActivateSession failed: {res}"); return; }

            // ── Einfacher Read: 1 Node ──
            Console.WriteLine("  --- Read 1 Node (ServerState i=2259) ---");
            res = client.Read(new ReadValueId[]
            {
                new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs1);
            Console.WriteLine($"  StatusCode: {res}");
            Console.WriteLine($"  Results: {dvs1?.Length ?? 0}");
            if (dvs1 != null)
            {
                for (int i = 0; i < dvs1.Length; i++)
                    Console.WriteLine($"    [{i}] Value={dvs1[i]?.Value} ({dvs1[i]?.Value?.GetType()?.Name ?? "null"})");
            }

            // ── Read: 3 Nodes ──
            Console.WriteLine("\n  --- Read 3 Nodes (ServerState, CurrentTime, BuildInfo.ProductName) ---");
            res = client.Read(new ReadValueId[]
            {
                new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                new(new NodeId(0, 2258), NodeAttribute.Value, null, new QualifiedName(0, null)),
                new(new NodeId(0, 2261), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs3);
            Console.WriteLine($"  StatusCode: {res}");
            Console.WriteLine($"  Results: {dvs3?.Length ?? 0}");
            if (dvs3 != null)
            {
                for (int i = 0; i < dvs3.Length; i++)
                    Console.WriteLine($"    [{i}] Value={dvs3[i]?.Value} ({dvs3[i]?.Value?.GetType()?.Name ?? "null"})");
            }

            // ── Browse ObjectsFolder ──
            Console.WriteLine("\n  --- Browse ObjectsFolder (i=85) ---");
            res = client.Browse(new BrowseDescription[]
            {
                new(new NodeId(0, (uint)UAConst.ObjectsFolder),
                    BrowseDirection.Forward, NodeId.Zero,
                    true, 100, BrowseResultMask.All)
            }, 100, out BrowseResult[] br);
            Console.WriteLine($"  StatusCode: {res}");
            if (br != null)
            {
                for (int i = 0; i < br.Length; i++)
                {
                    Console.WriteLine($"    BrowseResult[{i}]: Status=0x{br[i].StatusCode:X8}, ContinuationPoint={br[i].ContinuationPoint?.Length ?? 0}bytes, Refs={br[i].Refs?.Length ?? 0}");
                    if (br[i].Refs != null)
                    {
                        foreach (var r in br[i].Refs)
                        {
                            Console.WriteLine($"      -> {r.DisplayName?.Text ?? "?"} TargetId={r.TargetId} (NS={r.Target?.NamespaceUri ?? "none"}) TypeDef={r.TypeDefinition}");
                        }
                    }
                }
            }

            // ── Browse RootFolder ──
            Console.WriteLine("\n  --- Browse RootFolder (i=84) ---");
            res = client.Browse(new BrowseDescription[]
            {
                new(new NodeId(0, (uint)UAConst.RootFolder),
                    BrowseDirection.Forward, NodeId.Zero,
                    true, 100, BrowseResultMask.All)
            }, 100, out BrowseResult[] brRoot);
            Console.WriteLine($"  StatusCode: {res}");
            if (brRoot != null && brRoot.Length > 0 && brRoot[0].Refs != null)
            {
                foreach (var r in brRoot[0].Refs)
                {
                    Console.WriteLine($"    -> {r.DisplayName?.Text ?? "?"} TargetId={r.TargetId} Forward={r.IsForward}");

                    // Versuche Sub-Browse
                    if (r.TargetId != null)
                    {
                        var subRes = client.Browse(new BrowseDescription[]
                        {
                            new(r.TargetId, BrowseDirection.Forward, NodeId.Zero, true, 100, BrowseResultMask.All)
                        }, 100, out BrowseResult[] subBr);
                        var subCount = subBr?.FirstOrDefault()?.Refs?.Length ?? 0;
                        Console.WriteLine($"       Sub-Browse: {subRes}, {subCount} Referenzen");
                    }
                }
            }

            client.CloseSession(true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  EXCEPTION: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            try { client.Disconnect(); } catch { }
            client.Dispose();
        }
    }
}
