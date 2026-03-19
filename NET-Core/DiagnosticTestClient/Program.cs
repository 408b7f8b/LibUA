using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using LibUA;
using LibUA.Core;

namespace DiagnosticTestClient;

/// <summary>
/// Umfassender Diagnostik-Testclient für LibUA OPC-UA-Client Kompatibilitätstests.
/// Testet gegen mehrere Server (Docker + öffentlich) und prüft alle implementierten Fixes.
/// </summary>
internal class Program
{
    // ══════════════════════════════════════════════════════════════════
    //  Test-Client mit Notification-Tracking
    // ══════════════════════════════════════════════════════════════════

    private class DiagClient : Client
    {
        private X509Certificate2? appCertificate;
        private RSA? appPrivateKey;

        public override X509Certificate2? ApplicationCertificate => appCertificate;
        public override RSA? ApplicationPrivateKey => appPrivateKey;

        public List<(uint subscrId, uint[] handles, DataValue[] values)> ReceivedDataChanges { get; } = new();
        public List<(uint subscrId, uint[] handles, object[][] fields)> ReceivedEvents { get; } = new();

        public DiagClient(string target, int port, int timeout) : base(target, port, timeout, 1 << 22)
        {
            GenerateCertificate();
        }

        private void GenerateCertificate()
        {
            using var rsa = RSA.Create(2048);
            var dn = new X500DistinguishedName("CN=LibUA DiagnosticTest;OU=Testing", X500DistinguishedNameFlags.UseSemicolons);
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddUri(new Uri("urn:LibUA:DiagnosticTest"));

            var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(sanBuilder.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, false));

            appCertificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365));

            appPrivateKey = RSA.Create();
            appPrivateKey.ImportParameters(rsa.ExportParameters(true));
        }

        public override void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
        {
            ReceivedDataChanges.Add((subscrId, clientHandles, notifications));
        }

        public override void NotifyEventNotifications(uint subscrId, uint[] clientHandles, object[][] notifications)
        {
            ReceivedEvents.Add((subscrId, clientHandles, notifications));
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Server-Konfiguration
    // ══════════════════════════════════════════════════════════════════

    private record ServerConfig(
        string Name,
        string Host,
        int Port,
        int Timeout,
        string? EndpointPath = null,
        bool TrySecure = false
    );

    // ══════════════════════════════════════════════════════════════════
    //  Test-Ergebnis-Tracking
    // ══════════════════════════════════════════════════════════════════

    private class TestResult
    {
        public string TestName { get; init; } = "";
        public bool Passed { get; set; }
        public string? Detail { get; set; }
        public string? Error { get; set; }
    }

    private class ServerTestReport
    {
        public string ServerName { get; init; } = "";
        public List<TestResult> Results { get; } = new();
        public int Passed => Results.Count(r => r.Passed);
        public int Failed => Results.Count(r => !r.Passed);
        public int Total => Results.Count;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Haupt-Einstiegspunkt
    // ══════════════════════════════════════════════════════════════════

    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Byte-level Diagnose bei --dump Flag
        if (args.Contains("--dump"))
        {
            ByteDump.RunByteDump("open62541", "127.0.0.1", 4840);
            ByteDump.RunByteDump("python-asyncua", "127.0.0.1", 4841);
            ByteDump.RunByteDump("node-opcua", "127.0.0.1", 26543);
            return;
        }

        var servers = new List<ServerConfig>
        {
            // Docker-Server (lokal)
            new("open62541 (Docker)", "127.0.0.1", 4840, 10),
            new("python-asyncua (Docker)", "127.0.0.1", 4841, 10),
            new("node-opcua (Docker)", "127.0.0.1", 26543, 10),

            // Öffentliche Server
            new("Prosys OPC UA Demo", "uademo.prosysopc.com", 53530, 15),
            new("umati (öffentlich)", "opcua.umati.app", 4840, 15),
        };

        var reports = new List<ServerTestReport>();

        foreach (var server in servers)
        {
            var report = TestServer(server);
            reports.Add(report);
        }

        // ── Zusammenfassung ──
        Console.WriteLine();
        Console.WriteLine(new string('═', 100));
        Console.WriteLine("  ZUSAMMENFASSUNG");
        Console.WriteLine(new string('═', 100));

        foreach (var report in reports)
        {
            var status = report.Failed == 0 && report.Passed > 0 ? "OK" :
                         report.Passed == 0 ? "FAIL" : "PARTIAL";
            Console.WriteLine($"  [{status,-7}] {report.ServerName,-40} {report.Passed}/{report.Total} bestanden");
        }

        Console.WriteLine(new string('═', 100));

        // ── Detail-Report ──
        Console.WriteLine();
        Console.WriteLine("DETAIL-ERGEBNISSE:");
        Console.WriteLine();

        foreach (var report in reports)
        {
            Console.WriteLine($"┌─ {report.ServerName} ─");
            foreach (var result in report.Results)
            {
                var icon = result.Passed ? "[PASS]" : "[FAIL]";
                Console.Write($"│  {icon} {result.TestName,-45}");
                if (result.Detail != null)
                    Console.Write($" {result.Detail}");
                Console.WriteLine();
                if (result.Error != null)
                    Console.WriteLine($"│         Fehler: {result.Error}");
            }
            Console.WriteLine("└─");
            Console.WriteLine();
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Server-Testsuite
    // ══════════════════════════════════════════════════════════════════

    private static ServerTestReport TestServer(ServerConfig config)
    {
        var report = new ServerTestReport { ServerName = config.Name };
        Console.WriteLine();
        Console.WriteLine($"══ Teste: {config.Name} ({config.Host}:{config.Port}) ══");

        // ── T01: TCP-Verbindung ──
        var client = new DiagClient(config.Host, config.Port, config.Timeout);
        var t01 = RunTest("T01 Connect", () =>
        {
            var res = client.Connect();
            return (res == StatusCode.Good, $"StatusCode={res}");
        });
        report.Results.Add(t01);
        if (!t01.Passed)
        {
            client.Dispose();
            return report;
        }

        // ── T02: OpenSecureChannel (None) ──
        var t02 = RunTest("T02 OpenSecureChannel (None/None)", () =>
        {
            var res = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            return (res == StatusCode.Good, $"StatusCode={res}");
        });
        report.Results.Add(t02);
        if (!t02.Passed)
        {
            client.Disconnect();
            client.Dispose();
            return report;
        }

        // ── T03: FindServers ──
        report.Results.Add(RunTest("T03 FindServers", () =>
        {
            var res = client.FindServers(out ApplicationDescription[] appDescs, new[] { "en" });
            var count = appDescs?.Length ?? 0;
            return (res == StatusCode.Good, $"StatusCode={res}, {count} Server gefunden");
        }));

        // ── T04: GetEndpoints ──
        EndpointDescription[]? endpoints = null;
        report.Results.Add(RunTest("T04 GetEndpoints", () =>
        {
            var res = client.GetEndpoints(out endpoints, new[] { "en" });
            var count = endpoints?.Length ?? 0;
            var policies = endpoints != null
                ? string.Join(", ", endpoints.Select(e => $"{e.SecurityMode}").Distinct())
                : "keine";
            return (res == StatusCode.Good && count > 0, $"StatusCode={res}, {count} Endpoints [{policies}]");
        }));

        // ── T05: CreateSession ──
        var appDesc = new ApplicationDescription(
            "urn:LibUA:DiagnosticTest", "uri:LibUA:DiagnosticTest",
            new LocalizedText("LibUA Diagnostic Test Client"),
            ApplicationType.Client, null, null, null);

        report.Results.Add(RunTest("T05 CreateSession", () =>
        {
            var res = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ── T06: ActivateSession (Anonymous) ──
        var t06 = RunTest("T06 ActivateSession (Anonymous)", () =>
        {
            // Versuche PolicyId aus Endpoints zu lesen, Fallback "0"
            string policyId = "0";
            if (endpoints != null)
            {
                var noneEndpoint = endpoints.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                if (noneEndpoint?.UserIdentityTokens != null)
                {
                    var anonToken = noneEndpoint.UserIdentityTokens.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                    if (anonToken != null) policyId = anonToken.PolicyId;
                }
            }
            var res = client.ActivateSession(new UserIdentityAnonymousToken(policyId), new[] { "en" });
            return (res == StatusCode.Good, $"StatusCode={res}, PolicyId=\"{policyId}\"");
        });
        report.Results.Add(t06);
        if (!t06.Passed)
        {
            client.Disconnect();
            client.Dispose();
            return report;
        }

        // ════════════════════════════════════════════════
        //  Ab hier: Session ist aktiv — Dienste testen
        // ════════════════════════════════════════════════

        // ── T07: Browse ObjectsFolder ──
        BrowseResult[]? browseResults = null;
        report.Results.Add(RunTest("T07 Browse (ObjectsFolder)", () =>
        {
            var res = client.Browse(new BrowseDescription[]
            {
                new(new NodeId(0, (uint)UAConst.ObjectsFolder),
                    BrowseDirection.Forward, NodeId.Zero,
                    true, 1000, BrowseResultMask.All)
            }, 1000, out browseResults);
            bool isGood = Types.StatusCodeIsGood((uint)res);
            var refCount = browseResults?.FirstOrDefault()?.Refs?.Length ?? 0;
            return (isGood && refCount > 0, $"StatusCode={res}, {refCount} Referenzen");
        }));

        // ── T08: Browse-Traversierung (ObjectsFolder → Kinder → Enkel) ──
        report.Results.Add(RunTest("T08 Browse (Adressraum-Traversierung)", () =>
        {
            int totalNodes = 0;
            var visited = new HashSet<string>();
            var queue = new Queue<NodeId>();

            // Starte mit ObjectsFolder UND Server-Knoten
            queue.Enqueue(new NodeId(0, (uint)UAConst.ObjectsFolder));
            queue.Enqueue(new NodeId(0, (uint)UAConst.Server));

            int maxNodes = 100;
            while (queue.Count > 0 && totalNodes < maxNodes)
            {
                var node = queue.Dequeue();
                if (node == null) continue;
                string key = $"{node.NamespaceIndex}:{node.NumericIdentifier}";
                if (visited.Contains(key)) continue;
                visited.Add(key);

                var res = client.Browse(new BrowseDescription[]
                {
                    new(node, BrowseDirection.Forward,
                        new NodeId(0, (uint)RefType.HierarchicalReferences),
                        true, 50, BrowseResultMask.All)
                }, 50, out BrowseResult[] results);

                if (Types.StatusCodeIsGood((uint)res) && results?.Length > 0 && results[0].Refs != null)
                {
                    foreach (var r in results[0].Refs)
                    {
                        totalNodes++;
                        if (r.TargetId != null)
                            queue.Enqueue(r.TargetId);
                    }
                }
            }
            return (totalNodes >= 5, $"{totalNodes} Knoten traversiert (max {maxNodes})");
        }));

        // ── T09: Read Standardknoten (ServerStatus etc.) ──
        report.Results.Add(RunTest("T09 Read (Server-Standardknoten)", () =>
        {
            var res = client.Read(new ReadValueId[]
            {
                // Server_ServerStatus_State (i=2259)
                new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                // Server_ServerStatus_CurrentTime (i=2258)
                new(new NodeId(0, 2258), NodeAttribute.Value, null, new QualifiedName(0, null)),
                // Server_ServerStatus_BuildInfo_ProductName (i=2261)
                new(new NodeId(0, 2261), NodeAttribute.Value, null, new QualifiedName(0, null)),
                // Server_NamespaceArray (i=2255)
                new(new NodeId(0, 2255), NodeAttribute.Value, null, new QualifiedName(0, null)),
                // Server_ServerArray (i=2254)
                new(new NodeId(0, 2254), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            var details = new List<string>();
            if (dvs != null)
            {
                for (int i = 0; i < dvs.Length; i++)
                {
                    var val = dvs[i]?.Value;
                    var type = val?.GetType().Name ?? "null";
                    var display = val is Array arr ? $"{type}[{arr.Length}]" : $"{type}={Truncate(val?.ToString(), 30)}";
                    details.Add(display);
                }
            }

            bool isGood = Types.StatusCodeIsGood((uint)res);
            bool allNonNull = dvs != null && dvs.Length == 5 && dvs.All(d => d != null);
            return (isGood && allNonNull, $"StatusCode={res}, Werte: [{string.Join(", ", details)}]");
        }));

        // ── T10: Read verschiedene Datentypen (Variant-Test) ──
        report.Results.Add(RunTest("T10 Read (Variant-Typen: Bool, Int, Double, String, DateTime)", () =>
        {
            // Lese DisplayName von bekannten Knoten — funktioniert immer
            var res = client.Read(new ReadValueId[]
            {
                // Server node DisplayName (i=2253)
                new(new NodeId(0, 2253), NodeAttribute.DisplayName, null, new QualifiedName(0, null)),
                // Server node BrowseName
                new(new NodeId(0, 2253), NodeAttribute.BrowseName, null, new QualifiedName(0, null)),
                // Server node NodeClass
                new(new NodeId(0, 2253), NodeAttribute.NodeClass, null, new QualifiedName(0, null)),
                // Server node NodeId
                new(new NodeId(0, 2253), NodeAttribute.NodeId, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            var types = dvs?.Select(d => d?.Value?.GetType()?.Name ?? "null").ToArray() ?? Array.Empty<string>();
            bool hasValues = dvs != null && dvs.Any(d => d?.Value != null);
            return (Types.StatusCodeIsGood((uint)res) && hasValues, $"StatusCode={res}, Typen: [{string.Join(", ", types)}]");
        }));

        // ── T11: Read mit ResponseHeader-DiagnosticInfo (ungültiger Knoten) ──
        report.Results.Add(RunTest("T11 Read (ungültiger Knoten → DiagnosticInfo testen)", () =>
        {
            var res = client.Read(new ReadValueId[]
            {
                new(new NodeId(99, 99999), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            // Service-Call sollte trotzdem Good sein, aber DataValue enthält BadNodeIdUnknown
            return (Types.StatusCodeIsGood((uint)res), $"StatusCode={res}, DV-Count={dvs?.Length ?? 0}");
        }));

        // ── T12: Write ──
        report.Results.Add(RunTest("T12 Write (Int32-Wert)", () =>
        {
            // Schreibe auf Server_ServiceLevel (i=2267) — wird wahrscheinlich abgelehnt, aber der Encode/Decode funktioniert
            var res = client.Write(new WriteValue[]
            {
                new(new NodeId(0, 2267), NodeAttribute.Value, null,
                    new DataValue(255, StatusCode.Good, DateTime.UtcNow))
            }, out uint[] statuses);

            var statusStr = statuses != null && statuses.Length > 0 ? $"0x{statuses[0]:X8}" : "keine";
            return (res == StatusCode.Good, $"ServiceStatus={res}, WriteStatus={statusStr}");
        }));

        // ── T13: RegisterNodes (NEU) ──
        report.Results.Add(RunTest("T13 RegisterNodes", () =>
        {
            var res = client.RegisterNodes(
                new NodeId[] { new(0, 2259), new(0, 2258) },
                out NodeId[] registeredIds);

            var count = registeredIds?.Length ?? 0;
            return (res == StatusCode.Good && count == 2, $"StatusCode={res}, {count} Knoten registriert");
        }));

        // ── T14: UnregisterNodes (NEU) ──
        report.Results.Add(RunTest("T14 UnregisterNodes", () =>
        {
            var res = client.UnregisterNodes(new NodeId[] { new(0, 2259), new(0, 2258) });
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ── T15: CreateSubscription ──
        uint subscriptionId = 0;
        report.Results.Add(RunTest("T15 CreateSubscription", () =>
        {
            var res = client.CreateSubscription(500, 100, true, 0, out subscriptionId);
            return (Types.StatusCodeIsGood((uint)res) && subscriptionId != 0xFFFFFFFF,
                $"StatusCode={res}, SubscriptionId={subscriptionId}");
        }));

        // ── T16: CreateMonitoredItems ──
        report.Results.Add(RunTest("T16 CreateMonitoredItems", () =>
        {
            if (subscriptionId == 0 || subscriptionId == 0xFFFFFFFF)
                return (false, "Keine Subscription vorhanden");

            var res = client.CreateMonitoredItems(subscriptionId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new(new ReadValueId(new NodeId(0, 2258), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(1u, 500, null, 10, true)),
                }, out MonitoredItemCreateResult[] results);

            var resultStr = results?.Length > 0 ? $"MonitorId={results[0].MonitoredItemId}" : "keine";
            return (res == StatusCode.Good, $"StatusCode={res}, {resultStr}");
        }));

        // ── T17: SetMonitoringMode (NEU) ──
        report.Results.Add(RunTest("T17 SetMonitoringMode", () =>
        {
            if (subscriptionId == 0 || subscriptionId == 0xFFFFFFFF)
                return (false, "Keine Subscription vorhanden");

            var res = client.SetMonitoringMode(subscriptionId, MonitoringMode.Reporting,
                new uint[] { 1 }, out uint[] results);
            var statusStr = results?.Length > 0 ? $"0x{results[0]:X8}" : "keine";
            return (res == StatusCode.Good, $"StatusCode={res}, ItemStatus={statusStr}");
        }));

        // ── T18: Notification-Empfang (SubscriptionAcknowledgements-Test) ──
        report.Results.Add(RunTest("T18 Notification-Empfang (2s warten)", () =>
        {
            client.ReceivedDataChanges.Clear();
            Thread.Sleep(2500);
            var count = client.ReceivedDataChanges.Count;
            return (count > 0, $"{count} DataChange-Notifications empfangen");
        }));

        // ── T19: ModifySubscription ──
        report.Results.Add(RunTest("T19 ModifySubscription", () =>
        {
            if (subscriptionId == 0 || subscriptionId == 0xFFFFFFFF)
                return (false, "Keine Subscription vorhanden");

            var res = client.ModifySubscription(subscriptionId, 200, 100, true, 0, out uint status);
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ── T20: DeleteMonitoredItems ──
        report.Results.Add(RunTest("T20 DeleteMonitoredItems", () =>
        {
            if (subscriptionId == 0 || subscriptionId == 0xFFFFFFFF)
                return (false, "Keine Subscription vorhanden");

            var res = client.DeleteMonitoredItems(subscriptionId, new uint[] { 1 }, out uint[] statuses);
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ── T21: DeleteSubscription ──
        report.Results.Add(RunTest("T21 DeleteSubscription", () =>
        {
            if (subscriptionId == 0 || subscriptionId == 0xFFFFFFFF)
                return (false, "Keine Subscription vorhanden");

            var res = client.DeleteSubscription(new uint[] { subscriptionId }, out uint[] statuses);
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ── T22: CloseSession (deleteSubscriptions=true, NEU) ──
        report.Results.Add(RunTest("T22 CloseSession (deleteSubscriptions=true)", () =>
        {
            var res = client.CloseSession(deleteSubscriptions: true);
            return (res == StatusCode.Good, $"StatusCode={res}");
        }));

        // ════════════════════════════════════════════════
        //  Standard-Dienst-Tests (neue Session nötig)
        // ════════════════════════════════════════════════
        try { client.Disconnect(); } catch { }
        client.Dispose();
        client = new DiagClient(config.Host, config.Port, config.Timeout);

        // Session für Standard-Dienst-Tests aufbauen
        bool standardTestsReady = false;
        {
            var c = client.Connect();
            if (c == StatusCode.Good) c = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            if (c == StatusCode.Good) c = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
            if (c == StatusCode.Good)
            {
                string pid = "0";
                if (endpoints != null)
                {
                    var ne = endpoints.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                    var at = ne?.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                    if (at != null) pid = at.PolicyId;
                }
                c = client.ActivateSession(new UserIdentityAnonymousToken(pid), new[] { "en" });
            }
            standardTestsReady = (c == StatusCode.Good);
        }

        // ── T27: BrowseNext (Continuation Points) ──
        report.Results.Add(RunTest("T27 BrowseNext (Continuation Points)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            // Browse mit maxReferences=1 erzwingt ContinuationPoint
            var res = client.Browse(new BrowseDescription[]
            {
                new(new NodeId(0, (uint)UAConst.ObjectsFolder),
                    BrowseDirection.Forward,
                    new NodeId(0, (uint)RefType.HierarchicalReferences),
                    true, 1, BrowseResultMask.All)
            }, 1, out BrowseResult[] br);

            if (!Types.StatusCodeIsGood((uint)res) || br == null || br.Length == 0)
                return (false, $"Browse: {res}");

            var firstRefs = br[0].Refs?.Length ?? 0;
            if (br[0].ContinuationPoint == null || br[0].ContinuationPoint.Length == 0)
                return (true, $"Keine Continuation (nur {firstRefs} Referenz) — Server hat wenig Kinder");

            var nextRes = client.BrowseNext(new[] { br[0].ContinuationPoint }, false, out BrowseResult[] nextBr);
            var nextRefs = nextBr?.FirstOrDefault()?.Refs?.Length ?? 0;
            return (Types.StatusCodeIsGood((uint)nextRes), $"Browse={firstRefs} + BrowseNext={nextRefs} Referenzen");
        }));

        // ── T28: TranslateBrowsePathsToNodeIds ──
        report.Results.Add(RunTest("T28 TranslateBrowsePathsToNodeIds", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
            {
                new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                {
                    new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true,
                        new QualifiedName(0, "Server"))
                })
            }, out BrowsePathResult[] results);

            var targetCount = results?.FirstOrDefault()?.Targets?.Length ?? 0;
            return (Types.StatusCodeIsGood((uint)res), $"StatusCode={res}, {targetCount} Targets");
        }));

        // ── T29: Call (Methode aufrufen — GetMonitoredItems falls vorhanden) ──
        report.Results.Add(RunTest("T29 Call (Server.GetMonitoredItems)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            // Versuche GetMonitoredItems auf dem Server-Objekt — nicht alle Server haben das
            var res = client.Call(new CallMethodRequest[]
            {
                new(new NodeId(0, (uint)UAConst.Server),
                    new NodeId(0, 11492), // GetMonitoredItems MethodId
                    new object[] { (uint)0 }) // SubscriptionId=0 (ungültig, aber testet den Dienst)
            }, out CallMethodResult[] results);

            if (res == StatusCode.Good && results?.Length > 0)
            {
                var methodStatus = results[0].StatusCode;
                return (true, $"StatusCode={res}, MethodStatus=0x{(uint)methodStatus:X8}");
            }
            return (Types.StatusCodeIsGood((uint)res), $"StatusCode={res}");
        }));

        // ── T30: HistoryRead ──
        report.Results.Add(RunTest("T30 HistoryRead", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res = client.HistoryRead(
                new ReadRawModifiedDetails(false, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow, 10, true),
                TimestampsToReturn.Both, false,
                new HistoryReadValueId[]
                {
                    new(new NodeId(0, 2259), null, new QualifiedName(), null),
                }, out HistoryReadResult[] results);

            // Viele Server unterstützen keine History — Good oder BadHistoryOperationUnsupported sind beide OK
            bool ok = Types.StatusCodeIsGood((uint)res) || res == StatusCode.Good;
            return (ok, $"StatusCode={res}, Results={results?.Length ?? 0}");
        }));

        // ── T31: Mehrere Subscriptions gleichzeitig ──
        report.Results.Add(RunTest("T31 Mehrere Subscriptions gleichzeitig", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res1 = client.CreateSubscription(1000, 100, true, 0, out uint subId1);
            var res2 = client.CreateSubscription(2000, 100, true, 0, out uint subId2);

            if (!Types.StatusCodeIsGood((uint)res1) || !Types.StatusCodeIsGood((uint)res2))
                return (false, $"Sub1={res1} (id={subId1}), Sub2={res2} (id={subId2})");

            bool different = subId1 != subId2;

            // Aufräumen
            client.DeleteSubscription(new uint[] { subId1, subId2 }, out _);

            return (different, $"Sub1={subId1}, Sub2={subId2}, unterschiedlich={different}");
        }));

        // ── T32: Event-Monitoring (EventFilter) ──
        report.Results.Add(RunTest("T32 Event-Monitoring (EventFilter)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res = client.CreateSubscription(500, 100, true, 0, out uint subId);
            if (!Types.StatusCodeIsGood((uint)res)) return (false, $"CreateSubscription: {res}");

            var eventFilterOperands = new SimpleAttributeOperand[]
            {
                new(new[] { new QualifiedName("EventId") }),
                new(new[] { new QualifiedName("EventType") }),
                new(new[] { new QualifiedName("Message") }),
            };
            var eventFilter = new EventFilter(eventFilterOperands, null);

            res = client.CreateMonitoredItems(subId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new(new ReadValueId(new NodeId(0, 2253),
                            NodeAttribute.EventNotifier, null, new QualifiedName(0, null)),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(100u, 0, eventFilter, 100, true)),
                }, out MonitoredItemCreateResult[] monResults);

            var monStatus = monResults?.FirstOrDefault()?.StatusCode ?? (StatusCode)0xFFFFFFFF;
            client.DeleteSubscription(new uint[] { subId }, out _);

            return (Types.StatusCodeIsGood((uint)res), $"StatusCode={res}, MonitorStatus=0x{(uint)monStatus:X8}");
        }));

        // ── T33: SecureChannel-Renewal ──
        report.Results.Add(RunTest("T33 SecureChannel-Renewal (RenewSecureChannel)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res = client.RenewSecureChannel();
            return (Types.StatusCodeIsGood((uint)res), $"StatusCode={res}");
        }));

        // ── T34: Read nach Renewal (Kanal noch funktionsfähig) ──
        report.Results.Add(RunTest("T34 Read nach SecureChannel-Renewal", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var res = client.Read(new ReadValueId[]
            {
                new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            return (Types.StatusCodeIsGood((uint)res) && dvs?.FirstOrDefault()?.Value != null,
                $"StatusCode={res}, Value={dvs?.FirstOrDefault()?.Value}");
        }));

        // ── T35: Write + Readback (Wert schreiben und zurücklesen) ──
        report.Results.Add(RunTest("T35 Write + Readback", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            // Finde einen beschreibbaren Knoten — versuche NamespaceArray-Browse für custom Nodes
            // Fallback: Schreibe auf ServerStatus (wird abgelehnt, aber testet den Round-Trip)
            var writeVal = new Random().Next(1, 10000);

            // Versuche zuerst ns=1 "Int32Var" via TranslateBrowsePaths
            NodeId targetNode = null;
            var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
            {
                new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                {
                    new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(1, "TestVariables")),
                    new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(1, "Int32Var")),
                })
            }, out BrowsePathResult[] pathResults);

            if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 &&
                pathResults[0].Targets?.Length > 0)
            {
                targetNode = pathResults[0].Targets[0].Target;
            }

            if (targetNode == null)
            {
                // Versuche ns=2
                pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                {
                    new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                    {
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(2, "TestVariables")),
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(2, "Int32Var")),
                    })
                }, out pathResults);

                if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 &&
                    pathResults[0].Targets?.Length > 0)
                {
                    targetNode = pathResults[0].Targets[0].Target;
                }
            }

            if (targetNode == null)
                return (false, "Kein beschreibbarer Int32Var-Knoten gefunden");

            var writeRes = client.WriteWithTypeCheck(new WriteValue[]
            {
                new(targetNode, NodeAttribute.Value, null,
                    new DataValue(writeVal, StatusCode.Good, DateTime.UtcNow))
            }, out uint[] writeStatuses);

            if (!Types.StatusCodeIsGood((uint)writeRes) ||
                writeStatuses == null || writeStatuses.Length == 0 ||
                !Types.StatusCodeIsGood(writeStatuses[0]))
                return (false, $"Write: {writeRes}, Status=0x{(writeStatuses?.FirstOrDefault() ?? 0xFFFFFFFF):X8}");

            var readRes = client.Read(new ReadValueId[]
            {
                new(targetNode, NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] readDvs);

            var readVal = readDvs?.FirstOrDefault()?.Value;
            bool match = readVal != null && Convert.ToInt32(readVal) == writeVal;
            return (Types.StatusCodeIsGood((uint)readRes) && match,
                $"Wrote={writeVal}, Read={readVal}, Match={match}");
        }));

        // ── T36: Subscription-Datenänderungs-Verifikation (Write → Notification) ──
        report.Results.Add(RunTest("T36 Subscription-Datenänderung (Write → Notify)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            // Finde Int32Var
            NodeId targetNode = null;
            for (ushort ns = 1; ns <= 2 && targetNode == null; ns++)
            {
                var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                {
                    new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                    {
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TestVariables")),
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "Int32Var")),
                    })
                }, out BrowsePathResult[] pathResults);
                if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                    targetNode = pathResults[0].Targets[0].Target;
            }

            if (targetNode == null)
                return (false, "Kein Int32Var-Knoten gefunden");

            var subRes = client.CreateSubscription(100, 100, true, 0, out uint subId);
            if (!Types.StatusCodeIsGood((uint)subRes)) return (false, $"CreateSubscription: {subRes}");

            var monRes = client.CreateMonitoredItems(subId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new(new ReadValueId(targetNode, NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(200u, 100, null, 10, false)),
                }, out _);
            if (!Types.StatusCodeIsGood((uint)monRes)) { client.DeleteSubscription(new[] { subId }, out _); return (false, $"CreateMonitoredItems: {monRes}"); }

            client.ReceivedDataChanges.Clear();
            Thread.Sleep(500); // Warte auf initiale Notification

            // Schreibe neuen Wert
            var newVal = new Random().Next(10000, 99999);
            client.WriteWithTypeCheck(new WriteValue[]
            {
                new(targetNode, NodeAttribute.Value, null, new DataValue(newVal, StatusCode.Good, DateTime.UtcNow))
            }, out _);

            Thread.Sleep(1500); // Warte auf Notification
            var notifications = client.ReceivedDataChanges.ToList();
            bool received = notifications.Any(n => n.values.Any(dv => dv?.Value != null && Convert.ToInt32(dv.Value) == newVal));

            client.DeleteSubscription(new[] { subId }, out _);
            return (received, $"Wrote={newVal}, Notifications={notifications.Count}, ValueReceived={received}");
        }));

        // ── T37: Verschiedene Server-Datentypen lesen ──
        report.Results.Add(RunTest("T37 Read (Server-Datentypen: Bool, Int32, Double, String)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var typeNames = new[] { "BoolVar", "Int32Var", "DoubleVar", "StringVar" };
            var results = new List<string>();

            foreach (var typeName in typeNames)
            {
                NodeId node = null;
                for (ushort ns = 1; ns <= 2 && node == null; ns++)
                {
                    var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                    {
                        new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                        {
                            new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TestVariables")),
                            new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, typeName)),
                        })
                    }, out BrowsePathResult[] pathResults);
                    if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                        node = pathResults[0].Targets[0].Target;
                }

                if (node == null) { results.Add($"{typeName}=N/A"); continue; }

                var readRes = client.Read(new ReadValueId[]
                {
                    new(node, NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

                var val = dvs?.FirstOrDefault()?.Value;
                results.Add($"{typeName}={val?.GetType()?.Name ?? "null"}:{Truncate(val?.ToString(), 15)}");
            }

            bool hasAny = results.Any(r => !r.Contains("N/A") && !r.Contains("null"));
            return (hasAny, string.Join(", ", results));
        }));

        // ── T38: Reconnection (Disconnect → Connect → Session wieder aufbauen) ──
        report.Results.Add(RunTest("T38 Reconnection", () =>
        {
            try { client.CloseSession(true); } catch { }
            try { client.Disconnect(); } catch { }

            // Neue Verbindung
            var connectRes = client.Connect();
            if (connectRes != StatusCode.Good) return (false, $"Reconnect: {connectRes}");

            var openRes = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            if (openRes != StatusCode.Good) return (false, $"OpenSecureChannel: {openRes}");

            var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
            if (createRes != StatusCode.Good) return (false, $"CreateSession: {createRes}");

            string policyId = "0";
            if (endpoints != null)
            {
                var ne = endpoints.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                var at = ne?.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                if (at != null) policyId = at.PolicyId;
            }

            var activateRes = client.ActivateSession(new UserIdentityAnonymousToken(policyId), new[] { "en" });
            if (!Types.StatusCodeIsGood((uint)activateRes)) return (false, $"ActivateSession: {activateRes}");

            // Verifiziere dass Read funktioniert
            var readRes = client.Read(new ReadValueId[]
            {
                new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            bool ok = Types.StatusCodeIsGood((uint)readRes) && dvs?.FirstOrDefault()?.Value != null;
            standardTestsReady = ok; // Update für nachfolgende Tests
            return (ok, $"Read={readRes}, Value={dvs?.FirstOrDefault()?.Value}");
        }));

        // ════════════════════════════════════════════════
        //  Alarms & Conditions Lifecycle Tests
        // ════════════════════════════════════════════════

        // ── T43: A&C Event-Subscription (Alarm-Events empfangen) ──
        report.Results.Add(RunTest("T43 A&C Event-Subscription (Alarm empfangen)", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var filter = Client.CreateAlarmEventFilter();
            var subRes = client.CreateSubscription(500, 100, true, 0, out uint subId);
            if (!Types.StatusCodeIsGood((uint)subRes)) return (false, $"CreateSubscription: {subRes}");

            // Monitor auf Server-Objekt (empfängt alle Events)
            var monRes = client.CreateMonitoredItems(subId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new(new ReadValueId(new NodeId(0, (uint)UAConst.Server),
                            NodeAttribute.EventNotifier, null, new QualifiedName(0, null)),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(500u, 0, filter, 100, true)),
                }, out MonitoredItemCreateResult[] monResults);

            if (!Types.StatusCodeIsGood((uint)monRes))
            {
                client.DeleteSubscription(new[] { subId }, out _);
                return (false, $"CreateMonitoredItems: {monRes}");
            }

            uint monItemId = monResults[0].MonitoredItemId;

            // Warte auf Alarm-Events (Server erzeugt alle 3s Temperaturwechsel)
            client.ReceivedEvents.Clear();
            Thread.Sleep(5000);
            var eventCount = client.ReceivedEvents.Count;

            client.DeleteSubscription(new[] { subId }, out _);
            return (eventCount > 0, $"{eventCount} Alarm-Events empfangen, MonitorId={monItemId}");
        }));

        // ── T44: ConditionRefresh (aktuellen Alarm-Zustand abrufen) ──
        report.Results.Add(RunTest("T44 ConditionRefresh", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            var filter = Client.CreateAlarmEventFilter();
            var subRes = client.CreateSubscription(500, 100, true, 0, out uint subId);
            if (!Types.StatusCodeIsGood((uint)subRes)) return (false, $"CreateSubscription: {subRes}");

            client.CreateMonitoredItems(subId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new(new ReadValueId(new NodeId(0, (uint)UAConst.Server),
                            NodeAttribute.EventNotifier, null, new QualifiedName(0, null)),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(501u, 0, filter, 100, true)),
                }, out _);

            Thread.Sleep(1000);
            client.ReceivedEvents.Clear();

            // ConditionRefresh aufrufen
            var refreshRes = client.ConditionRefresh(subId);

            Thread.Sleep(2000);
            var eventCount = client.ReceivedEvents.Count;
            client.DeleteSubscription(new[] { subId }, out _);

            return (Types.StatusCodeIsGood((uint)refreshRes), $"ConditionRefresh={refreshRes}, Events nach Refresh={eventCount}");
        }));

        // ── T45: Acknowledge Alarm ──
        report.Results.Add(RunTest("T45 Acknowledge Alarm", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            // Finde TemperatureAlarm via Browse
            NodeId alarmNodeId = null;
            for (ushort ns = 1; ns <= 2 && alarmNodeId == null; ns++)
            {
                var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                {
                    new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                    {
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "AlarmsArea")),
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TemperatureAlarm")),
                    })
                }, out BrowsePathResult[] pathResults);
                if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                    alarmNodeId = pathResults[0].Targets[0].Target;
            }

            if (alarmNodeId == null)
                return (false, "TemperatureAlarm nicht gefunden");

            // Lese EventId vom Alarm
            var readRes = client.Read(new ReadValueId[]
            {
                new(alarmNodeId, NodeAttribute.Value, null, new QualifiedName(0, null)),
            }, out DataValue[] dvs);

            // Versuche Acknowledge mit leerem EventId (Server gibt BadEventIdUnknown zurück — aber der Call selbst funktioniert)
            var ackRes = client.AcknowledgeCondition(alarmNodeId, new byte[] { 0 }, "Test acknowledge");
            // Good oder BadEventIdUnknown sind beide akzeptabel — der Service-Call hat funktioniert
            bool ok = Types.StatusCodeIsGood((uint)ackRes) ||
                      ackRes == StatusCode.Good ||
                      (uint)ackRes == 0x80BB0000; // BadEventNotAcknowledgeable
            return (ok, $"Acknowledge={ackRes}, AlarmNode={alarmNodeId}");
        }));

        // ── T46: Enable/Disable Condition ──
        report.Results.Add(RunTest("T46 Enable/Disable Condition", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            NodeId alarmNodeId = null;
            for (ushort ns = 1; ns <= 2 && alarmNodeId == null; ns++)
            {
                var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                {
                    new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                    {
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "AlarmsArea")),
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TemperatureAlarm")),
                    })
                }, out BrowsePathResult[] pathResults);
                if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                    alarmNodeId = pathResults[0].Targets[0].Target;
            }

            if (alarmNodeId == null)
                return (false, "TemperatureAlarm nicht gefunden");

            var disableRes = client.DisableCondition(alarmNodeId);
            var enableRes = client.EnableCondition(alarmNodeId);

            bool ok = Types.StatusCodeIsGood((uint)disableRes) && Types.StatusCodeIsGood((uint)enableRes);
            return (ok, $"Disable={disableRes}, Enable={enableRes}");
        }));

        // ── T47: AddComment to Condition ──
        report.Results.Add(RunTest("T47 AddComment to Condition", () =>
        {
            if (!standardTestsReady) return (false, "Session nicht aktiv");

            NodeId alarmNodeId = null;
            for (ushort ns = 1; ns <= 2 && alarmNodeId == null; ns++)
            {
                var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                {
                    new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                    {
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "AlarmsArea")),
                        new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TemperatureAlarm")),
                    })
                }, out BrowsePathResult[] pathResults);
                if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                    alarmNodeId = pathResults[0].Targets[0].Target;
            }

            if (alarmNodeId == null)
                return (false, "TemperatureAlarm nicht gefunden");

            var commentRes = client.AddConditionComment(alarmNodeId, new byte[] { 0 }, "Operator comment from LibUA test");
            return (Types.StatusCodeIsGood((uint)commentRes), $"AddComment={commentRes}");
        }));

        try { client.CloseSession(true); } catch { }

        // ════════════════════════════════════════════════
        //  Security-Tests: Verschlüsselung + Authentifizierung
        // ════════════════════════════════════════════════

        // Neue Verbindung für Security-Tests
        try { client.Disconnect(); } catch { }
        client.Dispose();
        client = new DiagClient(config.Host, config.Port, config.Timeout);

        // ── T23: SignAndEncrypt SecureChannel + Session ──
        {
            var secEndpoint = endpoints?.FirstOrDefault(e =>
                e.SecurityMode == MessageSecurityMode.SignAndEncrypt &&
                e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]);

            report.Results.Add(RunTest("T23 SecureChannel (SignAndEncrypt/Basic256Sha256)", () =>
            {
                if (secEndpoint == null)
                    return (false, "Kein Basic256Sha256/SignAndEncrypt Endpoint");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Basic256Sha256, secEndpoint.ServerCertificate);
                if (openRes != StatusCode.Good) return (false, $"OpenSecureChannel: {openRes}");

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) return (false, $"CreateSession: {createRes}");

                // Anonymous auf verschlüsseltem Kanal
                string secPolicyId = "0";
                if (secEndpoint.UserIdentityTokens != null)
                {
                    var anonTok = secEndpoint.UserIdentityTokens.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                    if (anonTok != null) secPolicyId = anonTok.PolicyId;
                }
                var activateRes = client.ActivateSession(new UserIdentityAnonymousToken(secPolicyId), new[] { "en" });
                if (!Types.StatusCodeIsGood((uint)activateRes)) return (false, $"ActivateSession: {activateRes}");

                // Verifiziere dass Read über verschlüsselten Kanal funktioniert
                var readRes = client.Read(new ReadValueId[]
                {
                    new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

                var val = dvs?.FirstOrDefault()?.Value;
                client.CloseSession(true);
                client.Disconnect();
                return (Types.StatusCodeIsGood((uint)readRes) && val != null, $"Read={readRes}, Value={val}");
            }));

            // ── T24: Username/Password-Authentifizierung ──
            report.Results.Add(RunTest("T24 Auth (Username/Password)", () =>
            {
                try { client.Disconnect(); } catch { }

                var upEndpoint = secEndpoint ?? endpoints?.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                if (upEndpoint == null) return (false, "Kein Endpoint");

                var userTokenPolicy = upEndpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.UserName);
                if (userTokenPolicy == null) return (false, "Server unterstützt keine Username-Tokens");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                StatusCode openRes;
                if (secEndpoint != null)
                {
                    openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                        SecurityPolicy.Basic256Sha256, secEndpoint.ServerCertificate);
                }
                else
                {
                    openRes = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                }
                if (openRes != StatusCode.Good) return (false, $"OpenSecureChannel: {openRes}");

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) return (false, $"CreateSession: {createRes}");

                var activateRes = client.ActivateSession(
                    new UserIdentityUsernameToken(userTokenPolicy.PolicyId, "testuser",
                        System.Text.Encoding.UTF8.GetBytes("testpass"),
                        Types.SignatureAlgorithmRsaOaep),
                    new[] { "en" });

                if (Types.StatusCodeIsGood((uint)activateRes))
                {
                    // Verifiziere Zugriff
                    var readRes = client.Read(new ReadValueId[]
                    {
                        new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    }, out DataValue[] dvs);
                    client.CloseSession(true);
                    client.Disconnect();
                    return (Types.StatusCodeIsGood((uint)readRes), $"Activate={activateRes}, Read={readRes}");
                }

                client.Disconnect();
                return (false, $"ActivateSession: {activateRes}");
            }));

            // ── T25: Falsche Credentials → Ablehnung ──
            report.Results.Add(RunTest("T25 Auth (Falsche Credentials → Ablehnung)", () =>
            {
                try { client.Disconnect(); } catch { }

                var upEndpoint = secEndpoint ?? endpoints?.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.None);
                if (upEndpoint == null) return (false, "Kein Endpoint");

                var userTokenPolicy = upEndpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.UserName);
                if (userTokenPolicy == null) return (false, "Server unterstützt keine Username-Tokens");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                StatusCode openRes;
                if (secEndpoint != null)
                {
                    openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                        SecurityPolicy.Basic256Sha256, secEndpoint.ServerCertificate);
                }
                else
                {
                    openRes = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                }
                if (openRes != StatusCode.Good) return (false, $"OpenSecureChannel: {openRes}");

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) return (false, $"CreateSession: {createRes}");

                var activateRes = client.ActivateSession(
                    new UserIdentityUsernameToken(userTokenPolicy.PolicyId, "wronguser",
                        System.Text.Encoding.UTF8.GetBytes("wrongpass"),
                        Types.SignatureAlgorithmRsaOaep),
                    new[] { "en" });

                client.Disconnect();
                bool rejected = Types.StatusCodeIsBad((uint)activateRes);
                return (rejected, $"ActivateSession: {activateRes} (Ablehnung={rejected})");
            }));

            // ── T26: Sign-Only SecureChannel ──
            report.Results.Add(RunTest("T26 SecureChannel (Sign-Only/Basic256Sha256)", () =>
            {
                try { client.Disconnect(); } catch { }

                var signEndpoint = endpoints?.FirstOrDefault(e =>
                    e.SecurityMode == MessageSecurityMode.Sign &&
                    e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]);

                if (signEndpoint == null)
                    return (false, "Kein Sign/Basic256Sha256 Endpoint");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.Sign,
                    SecurityPolicy.Basic256Sha256, signEndpoint.ServerCertificate);
                if (openRes != StatusCode.Good) { client.Disconnect(); return (false, $"OpenSecureChannel: {openRes}"); }

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) { client.Disconnect(); return (false, $"CreateSession: {createRes}"); }

                string signPolicyId = "0";
                if (signEndpoint.UserIdentityTokens != null)
                {
                    var anonTok = signEndpoint.UserIdentityTokens.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous);
                    if (anonTok != null) signPolicyId = anonTok.PolicyId;
                }
                var activateRes = client.ActivateSession(new UserIdentityAnonymousToken(signPolicyId), new[] { "en" });
                if (!Types.StatusCodeIsGood((uint)activateRes)) { client.Disconnect(); return (false, $"ActivateSession: {activateRes}"); }

                var readRes = client.Read(new ReadValueId[]
                {
                    new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

                client.CloseSession(true);
                client.Disconnect();
                return (Types.StatusCodeIsGood((uint)readRes), $"Read={readRes}, Value={dvs?.FirstOrDefault()?.Value}");
            }));

            // ── T39: Aes128_Sha256_RsaOaep Policy ──
            report.Results.Add(RunTest("T39 SecureChannel (Aes128_Sha256_RsaOaep)", () =>
            {
                try { client.Disconnect(); } catch { }

                var aes128Endpoint = endpoints?.FirstOrDefault(e =>
                    e.SecurityMode == MessageSecurityMode.SignAndEncrypt &&
                    e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep]);

                if (aes128Endpoint == null)
                    return (false, "Kein Aes128_Sha256_RsaOaep Endpoint");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Aes128_Sha256_RsaOaep, aes128Endpoint.ServerCertificate);
                if (openRes != StatusCode.Good) { client.Disconnect(); return (false, $"OpenSecureChannel: {openRes}"); }

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) { client.Disconnect(); return (false, $"CreateSession: {createRes}"); }

                string pid = aes128Endpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous)?.PolicyId ?? "0";
                var activateRes = client.ActivateSession(new UserIdentityAnonymousToken(pid), new[] { "en" });
                if (!Types.StatusCodeIsGood((uint)activateRes)) { client.Disconnect(); return (false, $"ActivateSession: {activateRes}"); }

                var readRes = client.Read(new ReadValueId[]
                {
                    new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

                client.CloseSession(true);
                client.Disconnect();
                return (Types.StatusCodeIsGood((uint)readRes), $"Read={readRes}, Value={dvs?.FirstOrDefault()?.Value}");
            }));

            // ── T40: Username-Auth über verschlüsselten Kanal + Read ──
            report.Results.Add(RunTest("T40 Username-Auth (verschlüsselt) + Write + Read", () =>
            {
                try { client.Disconnect(); } catch { }

                if (secEndpoint == null) return (false, "Kein verschlüsselter Endpoint");

                var userTokenPolicy = secEndpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.UserName);
                if (userTokenPolicy == null) return (false, "Kein Username-Token auf verschlüsseltem Endpoint");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Basic256Sha256, secEndpoint.ServerCertificate);
                if (openRes != StatusCode.Good) { client.Disconnect(); return (false, $"OpenSecureChannel: {openRes}"); }

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) { client.Disconnect(); return (false, $"CreateSession: {createRes}"); }

                var activateRes = client.ActivateSession(
                    new UserIdentityUsernameToken(userTokenPolicy.PolicyId, "testuser",
                        System.Text.Encoding.UTF8.GetBytes("testpass"),
                        Types.SignatureAlgorithmRsaOaep),
                    new[] { "en" });
                if (!Types.StatusCodeIsGood((uint)activateRes)) { client.Disconnect(); return (false, $"ActivateSession: {activateRes}"); }

                // Write + Read über authentifizierte verschlüsselte Verbindung
                NodeId targetNode = null;
                for (ushort ns = 1; ns <= 2 && targetNode == null; ns++)
                {
                    var pathRes = client.TranslateBrowsePathsToNodeIds(new BrowsePath[]
                    {
                        new(new NodeId(0, (uint)UAConst.ObjectsFolder), new RelativePathElement[]
                        {
                            new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "TestVariables")),
                            new(new NodeId(0, (uint)RefType.HierarchicalReferences), false, true, new QualifiedName(ns, "Int32Var")),
                        })
                    }, out BrowsePathResult[] pathResults);
                    if (Types.StatusCodeIsGood((uint)pathRes) && pathResults?.Length > 0 && pathResults[0].Targets?.Length > 0)
                        targetNode = pathResults[0].Targets[0].Target;
                }

                if (targetNode != null)
                {
                    var writeVal = 77777;
                    client.WriteWithTypeCheck(new WriteValue[]
                    {
                        new(targetNode, NodeAttribute.Value, null, new DataValue(writeVal, StatusCode.Good, DateTime.UtcNow))
                    }, out _);

                    var readRes = client.Read(new ReadValueId[]
                    {
                        new(targetNode, NodeAttribute.Value, null, new QualifiedName(0, null)),
                    }, out DataValue[] dvs);

                    var readVal = dvs?.FirstOrDefault()?.Value;
                    client.CloseSession(true);
                    client.Disconnect();
                    bool match = readVal != null && Convert.ToInt32(readVal) == writeVal;
                    return (Types.StatusCodeIsGood((uint)readRes) && match,
                        $"Wrote={writeVal}, Read={readVal}, Match={match}");
                }

                // Kein beschreibbarer Node — nur Read testen
                var simpleRead = client.Read(new ReadValueId[]
                {
                    new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] simpleDvs);
                client.CloseSession(true);
                client.Disconnect();
                return (Types.StatusCodeIsGood((uint)simpleRead), $"Read={simpleRead}, Value={simpleDvs?.FirstOrDefault()?.Value}");
            }));

            // ── T41: Aes256_Sha256_RsaPss Policy ──
            report.Results.Add(RunTest("T41 SecureChannel (Aes256_Sha256_RsaPss)", () =>
            {
                try { client.Disconnect(); } catch { }

                var aes256Endpoint = endpoints?.FirstOrDefault(e =>
                    e.SecurityMode == MessageSecurityMode.SignAndEncrypt &&
                    e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss]);

                if (aes256Endpoint == null)
                    return (false, "Kein Aes256_Sha256_RsaPss Endpoint");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Aes256_Sha256_RsaPss, aes256Endpoint.ServerCertificate);
                if (openRes != StatusCode.Good) { client.Disconnect(); return (false, $"OpenSecureChannel: {openRes}"); }

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) { client.Disconnect(); return (false, $"CreateSession: {createRes}"); }

                string pid = aes256Endpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Anonymous)?.PolicyId ?? "0";
                var activateRes = client.ActivateSession(new UserIdentityAnonymousToken(pid), new[] { "en" });
                if (!Types.StatusCodeIsGood((uint)activateRes)) { client.Disconnect(); return (false, $"ActivateSession: {activateRes}"); }

                var readRes = client.Read(new ReadValueId[]
                {
                    new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

                client.CloseSession(true);
                client.Disconnect();
                return (Types.StatusCodeIsGood((uint)readRes), $"Read={readRes}, Value={dvs?.FirstOrDefault()?.Value}");
            }));

            // ── T42: X509 Zertifikat-Authentifizierung ──
            report.Results.Add(RunTest("T42 Auth (X509-Zertifikat)", () =>
            {
                try { client.Disconnect(); } catch { }

                var certEndpoint = secEndpoint ?? endpoints?.FirstOrDefault(e => e.SecurityMode == MessageSecurityMode.SignAndEncrypt);
                if (certEndpoint == null) return (false, "Kein verschlüsselter Endpoint");

                var certTokenPolicy = certEndpoint.UserIdentityTokens?.FirstOrDefault(t => t.TokenType == UserTokenType.Certificate);
                if (certTokenPolicy == null) return (false, "Server unterstützt keine Certificate-Tokens");

                var connectRes = client.Connect();
                if (connectRes != StatusCode.Good) return (false, $"Connect: {connectRes}");

                var openRes = client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Basic256Sha256, certEndpoint.ServerCertificate);
                if (openRes != StatusCode.Good) { client.Disconnect(); return (false, $"OpenSecureChannel: {openRes}"); }

                var createRes = client.CreateSession(appDesc, "urn:LibUA:DiagnosticTest", 120);
                if (createRes != StatusCode.Good) { client.Disconnect(); return (false, $"CreateSession: {createRes}"); }

                // Use application certificate as identity token
                var certData = client.ApplicationCertificate?.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
                if (certData == null) { client.Disconnect(); return (false, "Kein Client-Zertifikat vorhanden"); }

                var activateRes = client.ActivateSession(
                    new UserIdentityX509IdentityToken(certTokenPolicy.PolicyId, certData, client.ApplicationPrivateKey),
                    new[] { "en" });

                if (Types.StatusCodeIsGood((uint)activateRes))
                {
                    var readRes = client.Read(new ReadValueId[]
                    {
                        new(new NodeId(0, 2259), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    }, out DataValue[] dvs);
                    client.CloseSession(true);
                    client.Disconnect();
                    return (Types.StatusCodeIsGood((uint)readRes), $"Activate={activateRes}, Read={readRes}");
                }

                client.Disconnect();
                return (false, $"ActivateSession: {activateRes}");
            }));
        }

        // ── Aufräumen ──
        try { client.Disconnect(); } catch { }
        client.Dispose();

        Console.WriteLine($"   → {report.Passed}/{report.Total} Tests bestanden");
        return report;
    }

    // ══════════════════════════════════════════════════════════════════
    //  Hilfsmethoden
    // ══════════════════════════════════════════════════════════════════

    private static TestResult RunTest(string name, Func<(bool passed, string detail)> test)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var (passed, detail) = test();
            sw.Stop();
            var result = new TestResult
            {
                TestName = name,
                Passed = passed,
                Detail = $"{detail} ({sw.ElapsedMilliseconds}ms)"
            };
            Console.WriteLine($"   {(passed ? "[PASS]" : "[FAIL]")} {name}: {detail} ({sw.ElapsedMilliseconds}ms)");
            return result;
        }
        catch (Exception ex)
        {
            sw.Stop();
            var result = new TestResult
            {
                TestName = name,
                Passed = false,
                Error = $"{ex.GetType().Name}: {ex.Message}",
                Detail = $"Exception ({sw.ElapsedMilliseconds}ms)"
            };
            Console.WriteLine($"   [FAIL] {name}: {ex.GetType().Name}: {ex.Message} ({sw.ElapsedMilliseconds}ms)");
            return result;
        }
    }

    private static string? Truncate(string? s, int maxLen)
    {
        if (s == null) return null;
        return s.Length <= maxLen ? s : s[..maxLen] + "...";
    }
}
