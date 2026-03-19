#!/usr/bin/env node
/**
 * Foreign client test: node-opcua against LibUA server.
 * Tests OPC UA interoperability from an independent client implementation.
 */

const {
    OPCUAClient,
    MessageSecurityMode,
    SecurityPolicy,
    AttributeIds,
    TimestampsToReturn,
    StatusCodes,
    DataType,
    NodeId,
    resolveNodeId,
    BrowseDirection,
} = require("node-opcua-client");

const SERVER_URL = "opc.tcp://libua-server:7718";
const results = [];

function report(name, passed, detail = "") {
    const status = passed ? "PASS" : "FAIL";
    results.push({ name, passed, detail });
    console.log(`  [${status}] ${name}: ${detail}`);
}

async function waitForServer(maxAttempts = 30) {
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const client = OPCUAClient.create({ endpointMustExist: false, connectionStrategy: { maxRetry: 0 } });
            await client.connect(SERVER_URL);
            await client.disconnect();
            return;
        } catch (e) {
            if (i === maxAttempts - 1) {
                console.error(`FATAL: Cannot connect to ${SERVER_URL} after ${maxAttempts} attempts`);
                process.exit(1);
            }
            await new Promise(r => setTimeout(r, 1000));
        }
    }
}

async function runTests() {
    const client = OPCUAClient.create({
        endpointMustExist: false,
        securityMode: MessageSecurityMode.None,
        securityPolicy: SecurityPolicy.None,
        connectionStrategy: { maxRetry: 2, initialDelay: 1000 },
    });

    // T01: Connect
    try {
        await client.connect(SERVER_URL);
        report("T01 Connect", true, "Connected");
    } catch (e) {
        report("T01 Connect", false, e.message);
        process.exit(1);
    }

    // T02: GetEndpoints
    try {
        const endpoints = await client.getEndpoints();
        report("T02 GetEndpoints", endpoints.length > 0, `${endpoints.length} endpoints`);
    } catch (e) {
        report("T02 GetEndpoints", false, e.message);
    }

    // T03: CreateSession
    let session;
    try {
        session = await client.createSession();
        report("T03 CreateSession", true, "Session created");
    } catch (e) {
        report("T03 CreateSession", false, e.message);
        await client.disconnect();
        process.exit(1);
    }

    // T04: Browse ObjectsFolder
    try {
        const browseResult = await session.browse({
            nodeId: resolveNodeId("ObjectsFolder"),
            browseDirection: BrowseDirection.Forward,
            resultMask: 63,
        });
        const refs = browseResult.references || [];
        report("T04 Browse ObjectsFolder", refs.length > 0, `${refs.length} references`);
    } catch (e) {
        report("T04 Browse ObjectsFolder", false, e.message);
    }

    // T05: Browse Items folder
    try {
        const browseResult = await session.browse({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 0, 2),
            browseDirection: BrowseDirection.Forward,
            resultMask: 63,
        });
        const refs = browseResult.references || [];
        report("T05 Browse Items (1000+ nodes)", refs.length >= 100,
            `${refs.length} references`);
    } catch (e) {
        report("T05 Browse Items (1000+ nodes)", false, e.message);
    }

    // T06: Read TrendNode value
    try {
        const dataValue = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2),
            attributeId: AttributeIds.Value,
        });
        const val = dataValue.value.value;
        const ok = typeof val === "number" && Math.abs(val - 3.14159265) < 1.0;
        report("T06 Read TrendNode", ok, `value=${val}, status=${dataValue.statusCode.name}`);
    } catch (e) {
        report("T06 Read TrendNode", false, e.message);
    }

    // T07: Read 1D Array
    try {
        const dataValue = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1001, 2),
            attributeId: AttributeIds.Value,
        });
        const val = dataValue.value.value;
        const ok = val && val.length === 3;
        report("T07 Read 1D Array", ok, `value=[${val}], type=${val?.constructor?.name}`);
    } catch (e) {
        report("T07 Read 1D Array", false, e.message);
    }

    // T08: Read multiple nodes
    try {
        const nodesToRead = [1, 2, 3, 4, 5].map(i => ({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, i, 2),
            attributeId: AttributeIds.Value,
        }));
        const dataValues = await session.read(nodesToRead);
        const ok = dataValues.length === 5 && dataValues.every(dv => dv.statusCode.equals(StatusCodes.Good));
        report("T08 Read multiple nodes", ok, `${dataValues.length} values`);
    } catch (e) {
        report("T08 Read multiple nodes", false, e.message);
    }

    // T09: Read ServerStatus_State
    try {
        const dataValue = await session.read({
            nodeId: resolveNodeId("i=2259"),
            attributeId: AttributeIds.Value,
        });
        report("T09 Read ServerStatus_State", dataValue.value.value !== null,
            `value=${dataValue.value.value}`);
    } catch (e) {
        report("T09 Read ServerStatus_State", false, e.message);
    }

    // T10: Read invalid node
    try {
        const dataValue = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 99999, 99),
            attributeId: AttributeIds.Value,
        });
        const ok = !dataValue.statusCode.equals(StatusCodes.Good);
        report("T10 Read invalid node (rejected)", ok,
            `status=${dataValue.statusCode.name}`);
    } catch (e) {
        report("T10 Read invalid node (rejected)", true, e.message);
    }

    // T11: FindServers
    try {
        const servers = await client.findServers();
        const ok = servers.length > 0;
        const name = ok ? servers[0].applicationName.text : "N/A";
        report("T11 FindServers", ok, `found=${servers.length}, name=${name}`);
    } catch (e) {
        report("T11 FindServers", false, e.message);
    }

    // T12: RegisterNodes
    try {
        const registered = await session.registerNodes([
            new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2),
            new NodeId(NodeId.NodeIdType.NUMERIC, 2, 2),
        ]);
        const ok = registered.length === 2;
        await session.unregisterNodes(registered);
        report("T12 RegisterNodes + Unregister", ok, `${registered.length} registered`);
    } catch (e) {
        report("T12 RegisterNodes + Unregister", false, e.message);
    }

    // T13: Encrypted Channel (Basic256Sha256 SignAndEncrypt)
    try {
        const secureClient = OPCUAClient.create({
            endpointMustExist: false,
            securityMode: MessageSecurityMode.SignAndEncrypt,
            securityPolicy: SecurityPolicy.Basic256Sha256,
            connectionStrategy: { maxRetry: 1, initialDelay: 500 },
        });
        await secureClient.connect(SERVER_URL);
        const secSession = await secureClient.createSession();
        const secDataValue = await secSession.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2),
            attributeId: AttributeIds.Value,
        });
        const secVal = secDataValue.value.value;
        const secOk = typeof secVal === "number" && Math.abs(secVal - 3.14159265) < 1.0;
        report("T13 Encrypted Channel (B256S256)", secOk,
            `value=${secVal}, status=${secDataValue.statusCode.name}`);
        await secSession.close();
        await secureClient.disconnect();
    } catch (e) {
        report("T13 Encrypted Channel (B256S256)", false, e.message);
    }

    // T14: Read Node Attributes (DisplayName, BrowseName)
    try {
        const dvDisplayName = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2),
            attributeId: AttributeIds.DisplayName,
        });
        const dvBrowseName = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2),
            attributeId: AttributeIds.BrowseName,
        });
        const displayName = dvDisplayName.value.value;
        const browseName = dvBrowseName.value.value;
        const ok = displayName !== null && browseName !== null;
        report("T14 Read Node Attributes", ok,
            `DisplayName=${displayName?.text || displayName}, BrowseName=${browseName?.name || browseName}`);
    } catch (e) {
        report("T14 Read Node Attributes", false, e.message);
    }

    // T15: Read 2D Array
    try {
        const dataValue2d = await session.read({
            nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1002, 2),
            attributeId: AttributeIds.Value,
        });
        const val2d = dataValue2d.value.value;
        const ok2d = val2d !== null && val2d !== undefined;
        const dimInfo = val2d ? (val2d.length !== undefined ? `len=${val2d.length}` : `type=${typeof val2d}`) : "null";
        report("T15 Read 2D Array", ok2d,
            `status=${dataValue2d.statusCode.name}, ${dimInfo}`);
    } catch (e) {
        report("T15 Read 2D Array", false, e.message);
    }

    // T16: History Read
    try {
        const { ReadRawModifiedDetails } = require("node-opcua-client");
        const historyNode = new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2);
        const start = new Date("2015-12-01T00:00:00Z");
        const end = new Date("2015-12-02T00:00:00Z");
        const historyResult = await session.readHistoryValue(
            historyNode,
            start,
            end
        );
        const histValues = historyResult.historyData?.dataValues || [];
        report("T16 History Read", histValues.length > 0,
            `${histValues.length} data values returned`);
    } catch (e) {
        report("T16 History Read", false, e.message);
    }

    // T17: Multiple Subscriptions
    try {
        const sub1 = await session.createSubscription2({
            requestedPublishingInterval: 200,
            maxNotificationsPerPublish: 100,
            publishingEnabled: true,
        });
        const sub2 = await session.createSubscription2({
            requestedPublishingInterval: 200,
            maxNotificationsPerPublish: 100,
            publishingEnabled: true,
        });

        let received1 = 0, received2 = 0;
        const mi1 = await sub1.monitor(
            { nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2), attributeId: AttributeIds.Value },
            { samplingInterval: 200, queueSize: 10 },
            TimestampsToReturn.Both
        );
        const mi2 = await sub2.monitor(
            { nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 2, 2), attributeId: AttributeIds.Value },
            { samplingInterval: 200, queueSize: 10 },
            TimestampsToReturn.Both
        );
        mi1.on("changed", () => { received1++; });
        mi2.on("changed", () => { received2++; });

        await new Promise(r => setTimeout(r, 3000));
        await sub1.terminate();
        await sub2.terminate();
        const ok = received1 > 0 && received2 > 0;
        report("T17 Multiple Subscriptions", ok,
            `sub1=${received1} notifs, sub2=${received2} notifs`);
    } catch (e) {
        report("T17 Multiple Subscriptions", false, e.message);
    }

    // T18: Modify Subscription
    try {
        const modSub = await session.createSubscription2({
            requestedPublishingInterval: 500,
            maxNotificationsPerPublish: 100,
            publishingEnabled: true,
        });
        const modMi = await modSub.monitor(
            { nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2), attributeId: AttributeIds.Value },
            { samplingInterval: 500, queueSize: 10 },
            TimestampsToReturn.Both
        );
        // Modify the subscription publishing interval
        await modSub.modify({
            requestedPublishingInterval: 1000,
        });
        report("T18 Modify Subscription", true, "modify completed");
        await modSub.terminate();
    } catch (e) {
        report("T18 Modify Subscription", false, e.message);
    }

    // T19: Subscription + DataChange (run last as it can affect channel state)
    try {
        const subscription = await session.createSubscription2({
            requestedPublishingInterval: 200,
            maxNotificationsPerPublish: 100,
            publishingEnabled: true,
        });

        let received = 0;
        const monitoredItem = await subscription.monitor(
            { nodeId: new NodeId(NodeId.NodeIdType.NUMERIC, 1, 2), attributeId: AttributeIds.Value },
            { samplingInterval: 200, queueSize: 10 },
            TimestampsToReturn.Both
        );
        monitoredItem.on("changed", (dataValue) => { received++; });

        await new Promise(r => setTimeout(r, 3000));
        await subscription.terminate();
        report("T19 Subscription + DataChange", received > 0,
            `${received} notifications`);
    } catch (e) {
        report("T19 Subscription + DataChange", false, e.message);
    }

    // Cleanup
    try {
        await session.close();
        await client.disconnect();
    } catch (e) { /* ignore cleanup errors */ }
}

async function main() {
    console.log(`\n${"=".repeat(70)}`);
    console.log(`  Foreign Client Test: node-opcua → LibUA Server`);
    console.log(`  Server: ${SERVER_URL}`);
    console.log(`${"=".repeat(70)}`);

    await waitForServer();
    await runTests();

    const passed = results.filter(r => r.passed).length;
    const total = results.length;
    console.log(`\n  Result: ${passed}/${total} tests passed`);
    console.log(`${"=".repeat(70)}\n`);

    process.exit(passed === total ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
