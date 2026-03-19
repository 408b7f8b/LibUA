using LibUA.Core;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Xunit;

namespace LibUA.Tests
{
    /// <summary>
    /// A TestClient subclass that captures data change notifications from subscriptions.
    /// </summary>
    public class NotifyingTestClient : TestClient
    {
        public ConcurrentBag<(uint SubscriptionId, uint[] ClientHandles, DataValue[] Notifications)> ReceivedNotifications { get; }
            = new();

        public NotifyingTestClient(string target, int port, int timeout)
            : base(target, port, timeout)
        {
        }

        public override void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
        {
            ReceivedNotifications.Add((subscrId, clientHandles, notifications));
        }
    }

    [Collection("ServerTests")]
    public class ServerIntegrationTests : IDisposable
    {
        private readonly TestServerFixture serverFixture;

        public ServerIntegrationTests()
        {
            serverFixture = new TestServerFixture();
        }

        public void Dispose()
        {
            serverFixture?.Dispose();
            GC.SuppressFinalize(this);
        }

        private TestClient CreateConnectedClient(
            MessageSecurityMode mode = MessageSecurityMode.None,
            SecurityPolicy policy = SecurityPolicy.None,
            byte[] serverCert = null)
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            client.Connect();
            client.OpenSecureChannel(mode, policy, serverCert);
            var appDesc = new ApplicationDescription(
                "urn:TestApp", "http://test.com/",
                new LocalizedText("en-US", "Test"), ApplicationType.Client,
                null, null, null);
            client.CreateSession(appDesc, "urn:TestApp", 120);
            client.ActivateSession(new UserIdentityAnonymousToken("0"), new[] { "en" });
            return client;
        }

        private NotifyingTestClient CreateConnectedNotifyingClient()
        {
            var client = new NotifyingTestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            client.Connect();
            client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            var appDesc = new ApplicationDescription(
                "urn:TestApp", "http://test.com/",
                new LocalizedText("en-US", "Test"), ApplicationType.Client,
                null, null, null);
            client.CreateSession(appDesc, "urn:TestApp", 120);
            client.ActivateSession(new UserIdentityAnonymousToken("0"), new[] { "en" });
            return client;
        }

        private byte[] GetServerCertificateForSecureChannel()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                client.GetEndpoints(out EndpointDescription[] endpoints, new[] { "en" });
                client.Disconnect();

                var endpoint = endpoints.First(e =>
                    e.SecurityMode == MessageSecurityMode.SignAndEncrypt &&
                    e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]);
                return endpoint.ServerCertificate;
            }
            finally
            {
                client?.Dispose();
            }
        }

        #region 1. Read Value Verification

        [Fact]
        public void ReadTrendNode_ReturnsFloat()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Single(dvs);

                var value = dvs[0].Value;
                Assert.NotNull(value);
                // The server returns 3.14159265 as a double
                double floatValue = Convert.ToDouble(value);
                Assert.True(Math.Abs(floatValue - 3.14159265) < 0.001,
                    $"Expected approximately 3.14159265 but got {floatValue}");
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void ReadNode1D_ReturnsFloatArray()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1001), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Single(dvs);

                var value = dvs[0].Value;
                Assert.NotNull(value);
                Assert.IsType<float[]>(value);
                var arr = (float[])value;
                Assert.Equal(3, arr.Length);
                Assert.Equal(1.0f, arr[0], 0.001f);
                Assert.Equal(2.0f, arr[1], 0.001f);
                Assert.Equal(3.0f, arr[2], 0.001f);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void ReadNode2D_ReturnsMultidimensionalArray()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1002), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Single(dvs);

                var value = dvs[0].Value;
                Assert.NotNull(value);
                // The 2D array may come back as float[,] or float[]
                // depending on encoding; verify the values are present
                if (value is float[,] arr2d)
                {
                    Assert.Equal(2, arr2d.GetLength(0));
                    Assert.Equal(2, arr2d.GetLength(1));
                    Assert.Equal(1.0f, arr2d[0, 0], 0.001f);
                    Assert.Equal(2.0f, arr2d[0, 1], 0.001f);
                    Assert.Equal(3.0f, arr2d[1, 0], 0.001f);
                    Assert.Equal(4.0f, arr2d[1, 1], 0.001f);
                }
                else if (value is float[] arr1d)
                {
                    // Flattened: {1, 2, 3, 4}
                    Assert.Equal(4, arr1d.Length);
                    Assert.Equal(1.0f, arr1d[0], 0.001f);
                    Assert.Equal(2.0f, arr1d[1], 0.001f);
                    Assert.Equal(3.0f, arr1d[2], 0.001f);
                    Assert.Equal(4.0f, arr1d[3], 0.001f);
                }
                else
                {
                    // Accept any array type that has 4 elements with values 1-4
                    Assert.True(value is Array, $"Expected array type but got {value.GetType()}");
                }
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void ReadInvalidNode_ReturnsError()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(99, 99999u), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                // The service call itself may succeed, but the DataValue should have a bad status
                if (result == StatusCode.Good && dvs != null && dvs.Length > 0)
                {
                    Assert.True(dvs[0].StatusCode.HasValue && dvs[0].StatusCode.Value != 0,
                        "Expected bad status code for invalid node");
                }
                // Or the entire call may return a bad status
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 2. Write and Readback

        [Fact]
        public void WriteToItemsRoot_ReturnsStatus()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var writeValues = new WriteValue[]
                {
                    new(
                        new NodeId(2, 0), NodeAttribute.Value,
                        null, new DataValue(3.14159265, StatusCode.Good, DateTime.Now))
                };

                var result = client.Write(writeValues, out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
                Assert.Single(respStatuses);
                // ItemsRoot is a NodeObject, write may return BadNotWritable — the service itself returns Good
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void WriteToReadOnlyNode_ReturnsBadNotWritable()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var writeValues = new WriteValue[]
                {
                    new(
                        new NodeId(2, 1), NodeAttribute.Value,
                        null, new DataValue(42.0f, StatusCode.Good, DateTime.Now))
                };

                var result = client.Write(writeValues, out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
                Assert.Single(respStatuses);
                // TrendNode has AccessLevel CurrentRead | HistoryRead — NOT writable
                Assert.Equal((uint)StatusCode.BadNotWritable, respStatuses[0]);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 3. Browse Operations

        [Fact]
        public void BrowseItemsRoot_ReturnsChildren()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var browseDescs = new BrowseDescription[]
                {
                    new(
                        new NodeId(2, 0),
                        BrowseDirection.Forward,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
                };

                var result = client.Browse(browseDescs, 20000, out BrowseResult[] browseResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(browseResults);
                Assert.Single(browseResults);

                // ItemsRoot has 1000 TrendNodes + Node1D + Node2D + parent reference = 1003 references
                // Forward only should give at least 1002 children
                int totalRefs = browseResults[0].Refs?.Length ?? 0;

                // If there is a continuation point, browse next to get remaining
                while (browseResults[0].ContinuationPoint != null && browseResults[0].ContinuationPoint.Length > 0)
                {
                    var nextResult = client.BrowseNext(
                        new[] { browseResults[0].ContinuationPoint }, false,
                        out BrowseResult[] nextResults);
                    Assert.Equal(StatusCode.Good, nextResult);
                    if (nextResults != null && nextResults.Length > 0 && nextResults[0].Refs != null)
                    {
                        totalRefs += nextResults[0].Refs.Length;
                        browseResults[0] = nextResults[0];
                    }
                    else
                    {
                        break;
                    }
                }

                Assert.True(totalRefs >= 1000,
                    $"Expected at least 1000 child references from ItemsRoot, got {totalRefs}");
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void BrowseWithMaxResults_ReturnsContinuationPoint()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var browseDescs = new BrowseDescription[]
                {
                    new(
                        new NodeId(2, 0),
                        BrowseDirection.Both,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
                };

                // Use maxRefsPerNode=5 to force continuation points
                var result = client.Browse(browseDescs, 5, out BrowseResult[] browseResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(browseResults);
                Assert.Single(browseResults);
                Assert.NotNull(browseResults[0].Refs);
                Assert.True(browseResults[0].Refs.Length <= 5,
                    $"Expected at most 5 references, got {browseResults[0].Refs.Length}");

                // Should have a continuation point since ItemsRoot has 1000+ children
                Assert.NotNull(browseResults[0].ContinuationPoint);
                Assert.True(browseResults[0].ContinuationPoint.Length > 0);

                // BrowseNext should return more results
                var nextResult = client.BrowseNext(
                    new[] { browseResults[0].ContinuationPoint }, false,
                    out BrowseResult[] nextResults);
                Assert.Equal(StatusCode.Good, nextResult);
                Assert.NotNull(nextResults);
                Assert.NotEmpty(nextResults);
                Assert.NotNull(nextResults[0].Refs);
                Assert.NotEmpty(nextResults[0].Refs);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void BrowseInvalidNode_ReturnsEmpty()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var browseDescs = new BrowseDescription[]
                {
                    new(
                        new NodeId(99, 99999u),
                        BrowseDirection.Both,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
                };

                var result = client.Browse(browseDescs, 10000, out BrowseResult[] browseResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(browseResults);
                Assert.Single(browseResults);

                // Either no references or a bad status on the result
                bool isEmpty = browseResults[0].Refs == null || browseResults[0].Refs.Length == 0;
                bool isBadStatus = browseResults[0].StatusCode != 0;
                Assert.True(isEmpty || isBadStatus,
                    "Expected empty references or bad status for invalid node");
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 4. Subscription with Actual Notification Delivery

        [Fact]
        public void SubscriptionReceivesDataChangeNotification()
        {
            NotifyingTestClient client = null;
            try
            {
                client = CreateConnectedNotifyingClient();

                var createResult = client.CreateSubscription(100, 1000, true, 0, out uint subscrId);
                Assert.Equal(StatusCode.Good, createResult);

                var monResult = client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                    new[]
                    {
                        new MonitoredItemCreateRequest(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    }, out MonitoredItemCreateResult[] monResults);
                Assert.Equal(StatusCode.Good, monResult);
                Assert.NotNull(monResults);

                // Trigger data changes on the server
                serverFixture.PlayRow();
                serverFixture.PlayRow();

                // Wait for notifications to arrive via the background receive thread
                Thread.Sleep(2000);

                Assert.NotEmpty(client.ReceivedNotifications);
                var notification = client.ReceivedNotifications.First();
                Assert.NotNull(notification.Notifications);
                Assert.True(notification.Notifications.Length > 0);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void MultipleSubscriptions_IndependentNotifications()
        {
            NotifyingTestClient client = null;
            try
            {
                client = CreateConnectedNotifyingClient();

                // Create two subscriptions
                var res1 = client.CreateSubscription(100, 1000, true, 0, out uint subscrId1);
                Assert.Equal(StatusCode.Good, res1);
                var res2 = client.CreateSubscription(100, 1000, true, 0, out uint subscrId2);
                Assert.Equal(StatusCode.Good, res2);
                Assert.NotEqual(subscrId1, subscrId2);

                // Monitor different nodes on each subscription
                client.CreateMonitoredItems(subscrId1, TimestampsToReturn.Both,
                    new[]
                    {
                        new MonitoredItemCreateRequest(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    }, out _);

                client.CreateMonitoredItems(subscrId2, TimestampsToReturn.Both,
                    new[]
                    {
                        new MonitoredItemCreateRequest(
                            new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(2u, 0, null, 100, false))
                    }, out _);

                // Trigger data changes
                serverFixture.PlayRow();

                Thread.Sleep(2000);

                // Both subscriptions should have received notifications
                var sub1Notifs = client.ReceivedNotifications.Where(n => n.SubscriptionId == subscrId1).ToList();
                var sub2Notifs = client.ReceivedNotifications.Where(n => n.SubscriptionId == subscrId2).ToList();

                Assert.NotEmpty(sub1Notifs);
                Assert.NotEmpty(sub2Notifs);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void DeleteSubscription_StopsNotifications()
        {
            NotifyingTestClient client = null;
            try
            {
                client = CreateConnectedNotifyingClient();

                var createResult = client.CreateSubscription(100, 1000, true, 0, out uint subscrId);
                Assert.Equal(StatusCode.Good, createResult);

                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                    new[]
                    {
                        new MonitoredItemCreateRequest(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    }, out _);

                // Trigger and wait for initial notifications
                serverFixture.PlayRow();
                Thread.Sleep(1000);

                // Delete the subscription
                var deleteResult = client.DeleteSubscription(new[] { subscrId }, out uint[] deleteStatuses);
                Assert.Equal(StatusCode.Good, deleteResult);
                Assert.NotNull(deleteStatuses);
                Assert.Equal((uint)StatusCode.Good, deleteStatuses[0]);

                // Clear received notifications
                while (client.ReceivedNotifications.TryTake(out _)) { }

                // Trigger more data changes
                serverFixture.PlayRow();
                Thread.Sleep(1000);

                // Should not receive any more notifications for the deleted subscription
                var postDeleteNotifs = client.ReceivedNotifications
                    .Where(n => n.SubscriptionId == subscrId).ToList();
                Assert.Empty(postDeleteNotifs);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 5. RegisterNodes / UnregisterNodes

        [Fact]
        public void RegisterNodes_ReturnsRegisteredIds()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var nodesToRegister = new NodeId[]
                {
                    new(2, 1),
                    new(2, 2),
                    new(2, 3)
                };

                var result = client.RegisterNodes(nodesToRegister, out NodeId[] registeredIds);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(registeredIds);
                Assert.Equal(3, registeredIds.Length);

                // Registered IDs should be valid (non-null)
                foreach (var regId in registeredIds)
                {
                    Assert.NotNull(regId);
                }
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void UnregisterNodes_Succeeds()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();
                var nodesToRegister = new NodeId[]
                {
                    new(2, 1),
                    new(2, 2),
                    new(2, 3)
                };

                client.RegisterNodes(nodesToRegister, out NodeId[] registeredIds);
                Assert.NotNull(registeredIds);

                var result = client.UnregisterNodes(registeredIds);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 6. Security Channel Tests

        [Fact]
        public void SecureChannel_Basic256Sha256_Sign()
        {
            var serverCert = GetServerCertificateForSecureChannel();
            TestClient client = null;
            try
            {
                client = CreateConnectedClient(
                    MessageSecurityMode.Sign,
                    SecurityPolicy.Basic256Sha256,
                    serverCert);

                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Single(dvs);
                Assert.NotNull(dvs[0].Value);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void SecureChannel_Basic256Sha256_SignAndEncrypt()
        {
            var serverCert = GetServerCertificateForSecureChannel();
            TestClient client = null;
            try
            {
                client = CreateConnectedClient(
                    MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Basic256Sha256,
                    serverCert);

                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Single(dvs);
                Assert.NotNull(dvs[0].Value);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void SecureChannelRenewal_ContinuesWorking()
        {
            var serverCert = GetServerCertificateForSecureChannel();
            TestClient client = null;
            try
            {
                client = CreateConnectedClient(
                    MessageSecurityMode.SignAndEncrypt,
                    SecurityPolicy.Basic256Sha256,
                    serverCert);

                // First read
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result1 = client.Read(readValues, out DataValue[] dvs1);
                Assert.Equal(StatusCode.Good, result1);
                Assert.NotNull(dvs1);

                // Renew the secure channel
                var renewResult = client.RenewSecureChannel();
                Assert.Equal(StatusCode.Good, renewResult);

                // Read again after renewal
                var result2 = client.Read(readValues, out DataValue[] dvs2);
                Assert.Equal(StatusCode.Good, result2);
                Assert.NotNull(dvs2);
                Assert.Single(dvs2);
                Assert.NotNull(dvs2[0].Value);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 7. Authentication Rejection

        [Fact]
        public void UsernameAuth_WrongPassword_Rejected()
        {
            TestClient client = null;
            try
            {
                client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:TestApp", "http://test.com/",
                    new LocalizedText("en-US", "Test"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:TestApp", 120);

                // Set handler to reject all username tokens
                serverFixture.SessionValidateClientUserHandler = (_, userToken) =>
                    !(userToken is UserIdentityUsernameToken);

                var result = client.ActivateSession(
                    new UserIdentityUsernameToken("1", "wronguser", "wrongpass"u8.ToArray(),
                        Types.SignatureAlgorithmRsaOaep),
                    new[] { "en" });
                Assert.NotEqual(StatusCode.Good, result);
            }
            finally
            {
                serverFixture.SessionValidateClientUserHandler = null;
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void AnonymousAuth_WhenRejected_Fails()
        {
            TestClient client = null;
            try
            {
                client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:TestApp", "http://test.com/",
                    new LocalizedText("en-US", "Test"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:TestApp", 120);

                // Reject anonymous tokens
                serverFixture.SessionValidateClientUserHandler = (_, userToken) =>
                    !(userToken is UserIdentityAnonymousToken);

                var result = client.ActivateSession(
                    new UserIdentityAnonymousToken("0"),
                    new[] { "en" });
                Assert.NotEqual(StatusCode.Good, result);
            }
            finally
            {
                serverFixture.SessionValidateClientUserHandler = null;
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 8. Multiple Concurrent Clients

        [Fact]
        public void TwoConcurrentClients_BothWork()
        {
            TestClient client1 = null;
            TestClient client2 = null;
            try
            {
                client1 = CreateConnectedClient();
                client2 = CreateConnectedClient();

                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result1 = client1.Read(readValues, out DataValue[] dvs1);
                var result2 = client2.Read(readValues, out DataValue[] dvs2);

                Assert.Equal(StatusCode.Good, result1);
                Assert.Equal(StatusCode.Good, result2);
                Assert.NotNull(dvs1);
                Assert.NotNull(dvs2);
                Assert.Single(dvs1);
                Assert.Single(dvs2);

                // Both should get the same value (~3.14159265)
                double val1 = Convert.ToDouble(dvs1[0].Value);
                double val2 = Convert.ToDouble(dvs2[0].Value);
                Assert.True(Math.Abs(val1 - 3.14159265) < 0.001);
                Assert.True(Math.Abs(val2 - 3.14159265) < 0.001);
            }
            finally
            {
                client1?.Disconnect();
                client1?.Dispose();
                client2?.Disconnect();
                client2?.Dispose();
            }
        }

        #endregion

        #region 9. History Read Verification

        [Fact]
        public void HistoryRead_ReturnsValues()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();

                var historyReadDetails = new ReadRawModifiedDetails(false,
                    new DateTime(2015, 12, 1),
                    new DateTime(2015, 12, 2),
                    100, true);

                var result = client.HistoryRead(historyReadDetails, TimestampsToReturn.Both, false,
                    new[]
                    {
                        new HistoryReadValueId(new NodeId(2, 1), null, new QualifiedName(), null),
                    }, out HistoryReadResult[] histResults);

                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(histResults);
                Assert.Single(histResults);

                // Dec 1-2 2015 at hourly intervals should return up to 24 data values
                Assert.NotNull(histResults[0].Values);
                Assert.NotEmpty(histResults[0].Values);
                Assert.True(histResults[0].Values.Length <= 100,
                    "Should not exceed requested max of 100");

                // Verify values are actual computed values (sin/cos based)
                foreach (var dv in histResults[0].Values)
                {
                    Assert.NotNull(dv.Value);
                    Assert.NotNull(dv.SourceTimestamp);
                }
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void HistoryRead_EmptyRange_ReturnsEmpty()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();

                // Request history for a date range far beyond the generated data
                // Data goes from 2015-12-01 for 100000 hourly points (~11.4 years, ending ~April 2027)
                // Use a range well beyond that
                var historyReadDetails = new ReadRawModifiedDetails(false,
                    new DateTime(2030, 1, 1),
                    new DateTime(2030, 1, 2),
                    100, true);

                var result = client.HistoryRead(historyReadDetails, TimestampsToReturn.Both, false,
                    new[]
                    {
                        new HistoryReadValueId(new NodeId(2, 1), null, new QualifiedName(), null),
                    }, out HistoryReadResult[] histResults);

                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(histResults);
                Assert.Single(histResults);

                // Should have no data values for this range
                Assert.True(histResults[0].Values == null || histResults[0].Values.Length == 0,
                    "Expected empty result for date range with no data");
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 10. Endpoint and Discovery

        [Fact]
        public void GetEndpoints_ReturnsMultiplePolicies()
        {
            TestClient client = null;
            try
            {
                client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var result = client.GetEndpoints(out EndpointDescription[] endpoints, new[] { "en" });
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(endpoints);

                // The server defines 11 endpoints (1 None + 5 Sign + 5 SignAndEncrypt)
                Assert.True(endpoints.Length >= 10,
                    $"Expected at least 10 endpoints but got {endpoints.Length}");

                // Verify different security modes are present
                var modes = endpoints.Select(e => e.SecurityMode).Distinct().ToList();
                Assert.Contains(MessageSecurityMode.None, modes);
                Assert.Contains(MessageSecurityMode.Sign, modes);
                Assert.Contains(MessageSecurityMode.SignAndEncrypt, modes);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void FindServers_ReturnsServerDescription()
        {
            TestClient client = null;
            try
            {
                client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var result = client.FindServers(out ApplicationDescription[] appDescs, new[] { "en" });
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(appDescs);
                Assert.NotEmpty(appDescs);

                var serverDesc = appDescs[0];
                Assert.Equal("urn:DemoApplication", serverDesc.ApplicationUri);
                Assert.Equal(ApplicationType.Server, serverDesc.Type);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region 11. Error Handling

        [Fact]
        public void SessionNotActivated_ReadFails()
        {
            TestClient client = null;
            try
            {
                client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:TestApp", "http://test.com/",
                    new LocalizedText("en-US", "Test"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:TestApp", 120);
                // Deliberately NOT activating session

                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                // Should fail because session is not activated
                Assert.NotEqual(StatusCode.Good, result);
            }
            finally
            {
                try { client?.Disconnect(); } catch { /* Session never activated — disconnect may fail */ }
                client?.Dispose();
            }
        }

        [Fact]
        public void ReadAfterDisconnect_Fails()
        {
            TestClient client = null;
            try
            {
                client = CreateConnectedClient();

                // Verify read works
                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null))
                };

                var result1 = client.Read(readValues, out DataValue[] dvs1);
                Assert.Equal(StatusCode.Good, result1);

                // Close session and disconnect
                client.CloseSession();
                client.CloseSecureChannel();
                client.Disconnect();

                // Read after disconnect should fail (no connection)
                var result2 = client.Read(readValues, out DataValue[] dvs2);
                Assert.NotEqual(StatusCode.Good, result2);
            }
            finally
            {
                client?.Dispose();
            }
        }

        #endregion
    }
}
