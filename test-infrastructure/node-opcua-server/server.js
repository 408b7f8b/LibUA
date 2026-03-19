const opcua = require("node-opcua");

(async () => {
    const server = new opcua.OPCUAServer({
        port: 26543,
        allowAnonymous: true,
        userManager: {
            isValidUser: (userName, password) => {
                return userName === "testuser" && password === "testpass";
            }
        },
    });

    await server.initialize();

    const addressSpace = server.engine.addressSpace;
    const namespace = addressSpace.getOwnNamespace();

    const testFolder = namespace.addFolder(addressSpace.rootFolder.objects, {
        browseName: "TestVariables"
    });

    // ── Standard-Testvariablen ──
    let int32Value = 42;
    namespace.addVariable({
        componentOf: testFolder,
        browseName: "Int32Var",
        dataType: "Int32",
        value: {
            get: () => new opcua.Variant({ dataType: opcua.DataType.Int32, value: int32Value }),
            set: (v) => { int32Value = v.value; return opcua.StatusCodes.Good; }
        }
    });

    let doubleValue = 3.14159265;
    namespace.addVariable({
        componentOf: testFolder,
        browseName: "DoubleVar",
        dataType: "Double",
        value: {
            get: () => new opcua.Variant({ dataType: opcua.DataType.Double, value: doubleValue }),
            set: (v) => { doubleValue = v.value; return opcua.StatusCodes.Good; }
        }
    });

    namespace.addVariable({
        componentOf: testFolder,
        browseName: "StringVar",
        dataType: "String",
        value: { get: () => new opcua.Variant({ dataType: opcua.DataType.String, value: "Hello OPC UA" }) }
    });

    namespace.addVariable({
        componentOf: testFolder,
        browseName: "BoolVar",
        dataType: "Boolean",
        value: { get: () => new opcua.Variant({ dataType: opcua.DataType.Boolean, value: true }) }
    });

    // Dynamischer Counter
    let counter = 0;
    const dynamicVar = namespace.addVariable({
        componentOf: testFolder,
        browseName: "DynamicCounter",
        dataType: "Int32",
        value: { get: () => new opcua.Variant({ dataType: opcua.DataType.Int32, value: counter }) }
    });

    setInterval(() => {
        counter++;
        dynamicVar.setValueFromSource(new opcua.Variant({ dataType: opcua.DataType.Int32, value: counter }));
    }, 500);

    // ══════════════════════════════════════════════════
    //  Alarms & Conditions
    // ══════════════════════════════════════════════════

    const alarmsFolder = namespace.addFolder(addressSpace.rootFolder.objects, {
        browseName: "AlarmsArea"
    });

    // AlarmsArea als Event-Notifier konfigurieren
    alarmsFolder.setEventNotifier(1); // SubscribeToEvents

    // Quellvariable für den Alarm (simulierter Temperaturwert)
    let temperature = 25.0;
    const tempVar = namespace.addVariable({
        componentOf: alarmsFolder,
        browseName: "Temperature",
        dataType: "Double",
        value: {
            get: () => new opcua.Variant({ dataType: opcua.DataType.Double, value: temperature }),
            set: (v) => { temperature = v.value; return opcua.StatusCodes.Good; }
        },
        eventSourceOf: alarmsFolder,
    });

    // ExclusiveLevelAlarm
    try {
        const alarm = namespace.instantiateExclusiveLimitAlarm("ExclusiveLevelAlarmType", {
            componentOf: alarmsFolder,
            browseName: "TemperatureAlarm",
            conditionSource: tempVar,
            inputNode: tempVar,
            conditionName: "TemperatureAlarm",
            highHighLimit: 90,
            highLimit: 70,
            lowLimit: 10,
            lowLowLimit: 0,
        });
        console.log("  Alarm created: TemperatureAlarm (ExclusiveLevelAlarm)");
    } catch(e) {
        console.log("  ExclusiveLevelAlarm failed: " + e.message + " — trying simple AcknowledgeableCondition");
        try {
            const alarm = namespace.instantiateCondition("AcknowledgeableConditionType", {
                componentOf: alarmsFolder,
                browseName: "TemperatureAlarm",
                conditionSource: tempVar,
                conditionName: "TemperatureAlarm",
            });
            console.log("  Alarm created: TemperatureAlarm (AcknowledgeableCondition)");
        } catch(e2) {
            console.log("  AcknowledgeableCondition also failed: " + e2.message);
        }
    }

    // Temperatur-Simulation
    let alarmCycle = 0;
    setInterval(() => {
        alarmCycle++;
        temperature = (alarmCycle % 2 === 0) ? 80 : 25;
        tempVar.setValueFromSource(new opcua.Variant({ dataType: opcua.DataType.Double, value: temperature }));
    }, 3000);

    await server.start();
    console.log("node-opcua test server running on port 26543");
    console.log("Alarms & Conditions: TemperatureAlarm in AlarmsArea");
    console.log("  Temperature cycles: 25°C (normal) ↔ 80°C (high alarm) every 3s");
    console.log("Username auth: testuser/testpass");
})();
