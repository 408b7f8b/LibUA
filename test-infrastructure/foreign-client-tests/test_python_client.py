#!/usr/bin/env python3
"""
Foreign client test: python-asyncua against LibUA server.
Tests OPC UA interoperability from an independent client implementation.
"""

import asyncio
import sys
import time
from datetime import datetime, timezone

RESULTS = []
SERVER_URL = "opc.tcp://libua-server:7718"


def report(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    RESULTS.append((name, passed, detail))
    print(f"  [{status}] {name}: {detail}")


async def run_tests():
    from asyncua import Client, ua

    # Wait for server to be ready
    for attempt in range(30):
        try:
            async with Client(url=SERVER_URL, timeout=5) as c:
                break
        except Exception:
            if attempt == 29:
                print(f"FATAL: Cannot connect to {SERVER_URL} after 30 attempts")
                sys.exit(1)
            await asyncio.sleep(1)

    # T01: Connect and GetEndpoints
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            endpoints = await client.get_endpoints()
            report("T01 Connect + GetEndpoints", len(endpoints) > 0,
                   f"{len(endpoints)} endpoints")
    except Exception as e:
        report("T01 Connect + GetEndpoints", False, str(e))

    # T02: Browse ObjectsFolder
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            objects = client.nodes.objects
            children = await objects.get_children()
            report("T02 Browse ObjectsFolder", len(children) > 0,
                   f"{len(children)} children")
    except Exception as e:
        report("T02 Browse ObjectsFolder", False, str(e))

    # T03: Browse Items folder and count children
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            items_node = client.get_node(ua.NodeId(0, 2))  # ns=2, i=0
            children = await items_node.get_children()
            report("T03 Browse Items (1000+ nodes)", len(children) >= 1000,
                   f"{len(children)} children")
    except Exception as e:
        report("T03 Browse Items (1000+ nodes)", False, str(e))

    # T04: Read a TrendNode value
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(1, 2))  # ns=2, i=1
            value = await node.read_value()
            ok = isinstance(value, (int, float)) and abs(value - 3.14159265) < 1.0
            report("T04 Read TrendNode value", ok,
                   f"value={value}, type={type(value).__name__}")
    except Exception as e:
        report("T04 Read TrendNode value", False, str(e))

    # T05: Read 1D Array node
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(1001, 2))  # ns=2, i=1001
            value = await node.read_value()
            ok = hasattr(value, '__len__') and len(value) == 3
            report("T05 Read 1D Array", ok,
                   f"value={value}")
    except Exception as e:
        report("T05 Read 1D Array", False, str(e))

    # T06: Read multiple nodes at once
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            nodes = [client.get_node(ua.NodeId(i, 2)) for i in range(1, 6)]
            values = await client.read_values(nodes)
            ok = len(values) == 5 and all(v is not None for v in values)
            report("T06 Read multiple nodes", ok,
                   f"{len(values)} values read")
    except Exception as e:
        report("T06 Read multiple nodes", False, str(e))

    # T07: Read server status (standard node)
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            # ServerStatus_State = i=2259
            node = client.get_node(ua.NodeId(2259, 0))
            value = await node.read_value()
            report("T07 Read ServerStatus_State", value is not None,
                   f"value={value}")
    except Exception as e:
        report("T07 Read ServerStatus_State", False, str(e))

    # T08: Read invalid node
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(99999, 99))
            try:
                value = await node.read_value()
                report("T08 Read invalid node", False, "Should have raised")
            except ua.UaStatusCodeError as e:
                report("T08 Read invalid node (rejected)", True,
                       f"StatusCode={e.code}")
    except Exception as e:
        report("T08 Read invalid node (rejected)", False, str(e))

    # T09: Create and use subscription
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            received = []

            class Handler:
                def datachange_notification(self, node, val, data):
                    received.append(val)

            handler = Handler()
            sub = await client.create_subscription(200, handler)
            node = client.get_node(ua.NodeId(1, 2))
            handle = await sub.subscribe_data_change(node)
            await asyncio.sleep(3)
            await sub.unsubscribe(handle)
            await sub.delete()
            report("T09 Subscription + DataChange", len(received) > 0,
                   f"{len(received)} notifications received")
    except Exception as e:
        report("T09 Subscription + DataChange", False, str(e))

    # T10: FindServers
    try:
        from asyncua import Client
        async with Client(url=SERVER_URL, timeout=10) as client:
            servers = await client.find_servers()
            ok = len(servers) > 0
            name = servers[0].ApplicationName.Text if ok else "N/A"
            report("T10 FindServers", ok, f"found={len(servers)}, name={name}")
    except Exception as e:
        report("T10 FindServers", False, str(e))

    # T11: TranslateBrowsePathsToNodeIds
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            browse_path = ua.BrowsePath()
            browse_path.StartingNode = ua.NodeId(ua.ObjectIds.ObjectsFolder)
            rel = ua.RelativePathElement()
            rel.TargetName = ua.QualifiedName("Items", 0)
            browse_path.RelativePath.Elements.append(rel)
            results = await client.uaclient.translate_browsepaths_to_nodeids([browse_path])
            ok = len(results) > 0
            report("T11 TranslateBrowsePaths", ok, f"results={len(results)}")
    except Exception as e:
        report("T11 TranslateBrowsePaths", False, str(e))

    # T12: RegisterNodes
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node1 = client.get_node(ua.NodeId(1, 2))
            node2 = client.get_node(ua.NodeId(2, 2))
            registered = await client.register_nodes([node1, node2])
            ok = len(registered) == 2
            await client.unregister_nodes(registered)
            report("T12 RegisterNodes + Unregister", ok,
                   f"registered={len(registered)}")
    except Exception as e:
        report("T12 RegisterNodes + Unregister", False, str(e))

    # T13: Encrypted Channel (Basic256Sha256 SignAndEncrypt)
    try:
        from asyncua.crypto.cert_gen import setup_self_signed_certificate
        from cryptography.x509.oid import ExtendedKeyUsageOID
        from pathlib import Path
        import tempfile

        tmpdir = tempfile.mkdtemp()
        cert_file = Path(tmpdir) / "cert.der"
        key_file = Path(tmpdir) / "key.pem"

        await setup_self_signed_certificate(
            key_file,
            cert_file,
            "urn:asyncua:testclient",
            "localhost",
            cert_use=[ExtendedKeyUsageOID.CLIENT_AUTH],
            subject_attrs={"organizationName": "Test"},
        )

        client = Client(url=SERVER_URL, timeout=15)
        client.application_uri = "urn:asyncua:testclient"
        security_string = f"Basic256Sha256,SignAndEncrypt,{cert_file},{key_file}"
        await client.set_security_string(security_string)
        await client.connect()
        try:
            node = client.get_node(ua.NodeId(1, 2))
            value = await node.read_value()
            ok = isinstance(value, (int, float)) and abs(value - 3.14159265) < 1.0
            report("T13 Encrypted Channel (B256S256)", ok,
                   f"value={value}")
        finally:
            await client.disconnect()
    except Exception as e:
        report("T13 Encrypted Channel (B256S256)", False, str(e))

    # T14: Username Authentication
    try:
        client = Client(url=SERVER_URL, timeout=10)
        client.set_user("testuser")
        client.set_password("testpass")
        await client.connect()
        try:
            node = client.get_node(ua.NodeId(1, 2))
            value = await node.read_value()
            ok = isinstance(value, (int, float)) and abs(value - 3.14159265) < 1.0
            report("T14 Username Authentication", ok,
                   f"value={value}")
        finally:
            await client.disconnect()
    except Exception as e:
        report("T14 Username Authentication", False, str(e))

    # T15: Read Node Attributes (DisplayName, BrowseName)
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(1, 2))
            display_name = await node.read_display_name()
            browse_name = await node.read_browse_name()
            ok = display_name is not None and browse_name is not None
            report("T15 Read Node Attributes", ok,
                   f"DisplayName={display_name}, BrowseName={browse_name}")
    except Exception as e:
        report("T15 Read Node Attributes", False, str(e))

    # T16: Multiple Subscriptions
    try:
        async with Client(url=SERVER_URL, timeout=15) as client:
            received1 = []
            received2 = []

            class Handler1:
                def datachange_notification(self, node, val, data):
                    received1.append(val)

            class Handler2:
                def datachange_notification(self, node, val, data):
                    received2.append(val)

            sub1 = await client.create_subscription(200, Handler1())
            sub2 = await client.create_subscription(200, Handler2())
            node1 = client.get_node(ua.NodeId(1, 2))
            node2 = client.get_node(ua.NodeId(2, 2))
            handle1 = await sub1.subscribe_data_change(node1)
            handle2 = await sub2.subscribe_data_change(node2)
            await asyncio.sleep(3)
            await sub1.unsubscribe(handle1)
            await sub2.unsubscribe(handle2)
            await sub1.delete()
            await sub2.delete()
            ok = len(received1) > 0 and len(received2) > 0
            report("T16 Multiple Subscriptions", ok,
                   f"sub1={len(received1)} notifs, sub2={len(received2)} notifs")
    except Exception as e:
        report("T16 Multiple Subscriptions", False, str(e))

    # T17: History Read
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(1, 2))
            start = datetime(2015, 12, 1, tzinfo=timezone.utc)
            end = datetime(2015, 12, 2, tzinfo=timezone.utc)
            history = await node.read_raw_history(starttime=start, endtime=end)
            ok = history is not None and len(history) > 0
            report("T17 History Read", ok,
                   f"{len(history)} data values returned")
    except Exception as e:
        report("T17 History Read", False, str(e))

    # T18: Read 2D Array
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            node = client.get_node(ua.NodeId(1002, 2))
            value = await node.read_value()
            # 2D array may come as flat list or nested list
            ok = value is not None and hasattr(value, '__len__') and len(value) > 0
            report("T18 Read 2D Array", ok,
                   f"value type={type(value).__name__}, len={len(value) if hasattr(value, '__len__') else 'N/A'}")
    except Exception as e:
        report("T18 Read 2D Array", False, str(e))

    # T19: Concurrent Reads (asyncio.gather)
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            async def read_node(node_id):
                node = client.get_node(ua.NodeId(node_id, 2))
                return await node.read_value()

            tasks = [read_node(i) for i in range(1, 11)]
            values = await asyncio.gather(*tasks)
            ok = len(values) == 10 and all(v is not None for v in values)
            report("T19 Concurrent Reads", ok,
                   f"{len(values)} values, all valid={ok}")
    except Exception as e:
        report("T19 Concurrent Reads", False, str(e))

    # T20: Subscription Modify + Delete
    try:
        async with Client(url=SERVER_URL, timeout=10) as client:
            class DummyHandler:
                def datachange_notification(self, node, val, data):
                    pass

            sub = await client.create_subscription(500, DummyHandler())
            node = client.get_node(ua.NodeId(1, 2))
            handle = await sub.subscribe_data_change(node)
            # Modify publishing interval via low-level uaclient API
            mod_params = ua.ModifySubscriptionParameters()
            mod_params.SubscriptionId = sub.subscription_id
            mod_params.RequestedPublishingInterval = 1000
            mod_params.RequestedMaxKeepAliveCount = 10
            mod_params.RequestedLifetimeCount = 300
            mod_params.MaxNotificationsPerPublish = 0
            result = await client.uaclient.modify_subscription(mod_params)
            ok = result.RevisedPublishingInterval is not None
            await sub.unsubscribe(handle)
            await sub.delete()
            report("T20 Subscription Modify + Delete", ok,
                   f"revised interval={result.RevisedPublishingInterval}")
    except Exception as e:
        report("T20 Subscription Modify + Delete", False, str(e))


async def main():
    print(f"\n{'='*70}")
    print(f"  Foreign Client Test: python-asyncua → LibUA Server")
    print(f"  Server: {SERVER_URL}")
    print(f"{'='*70}")

    await run_tests()

    passed = sum(1 for _, p, _ in RESULTS if p)
    total = len(RESULTS)
    print(f"\n  Result: {passed}/{total} tests passed")
    print(f"{'='*70}\n")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
