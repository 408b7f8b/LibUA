using LibUA.Core;
using LibUA.ValueTypes;

namespace LibUA.Tests;

public class CustomDataTypeTests
{
    #region StructuredTypeCodec Round-Trip

    [Fact]
    public void Structure_SimpleFields_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            DefaultEncodingId = new NodeId(1, 1001),
            Fields = new[]
            {
                new StructureField { Name = "Temperature", DataType = new NodeId(0, 11) },  // Double
                new StructureField { Name = "Label", DataType = new NodeId(0, 12) },          // String
                new StructureField { Name = "Count", DataType = new NodeId(0, 6) },            // Int32
            }
        };

        var registry = new DataTypeRegistry();
        registry.Register(def.DefaultEncodingId, new NodeId(1, 1000), def);

        var original = new StructuredValue
        {
            TypeId = def.DefaultEncodingId,
            Definition = def,
        };
        original["Temperature"] = 42.5;
        original["Label"] = "Sensor A";
        original["Count"] = 7;

        // Encode
        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, registry));

        // Decode
        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, registry);

        Assert.NotNull(decoded);
        Assert.Equal(42.5, decoded.GetField<double>("Temperature"));
        Assert.Equal("Sensor A", decoded.GetField<string>("Label"));
        Assert.Equal(7, decoded.GetField<int>("Count"));
    }

    [Fact]
    public void Structure_AllBuiltInTypes_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            DefaultEncodingId = new NodeId(1, 2001),
            Fields = new[]
            {
                new StructureField { Name = "BoolField", DataType = new NodeId(0, 1) },
                new StructureField { Name = "ByteField", DataType = new NodeId(0, 3) },
                new StructureField { Name = "Int16Field", DataType = new NodeId(0, 4) },
                new StructureField { Name = "UInt32Field", DataType = new NodeId(0, 7) },
                new StructureField { Name = "Int64Field", DataType = new NodeId(0, 8) },
                new StructureField { Name = "FloatField", DataType = new NodeId(0, 10) },
                new StructureField { Name = "StringField", DataType = new NodeId(0, 12) },
            }
        };

        var registry = new DataTypeRegistry();

        var original = new StructuredValue { Definition = def };
        original["BoolField"] = true;
        original["ByteField"] = (byte)0xFF;
        original["Int16Field"] = (short)-1234;
        original["UInt32Field"] = 99999u;
        original["Int64Field"] = (long)1234567890123;
        original["FloatField"] = 2.71828f;
        original["StringField"] = "hello world";

        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, registry));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, registry);

        Assert.NotNull(decoded);
        Assert.True(decoded.GetField<bool>("BoolField"));
        Assert.Equal((byte)0xFF, decoded.GetField<byte>("ByteField"));
        Assert.Equal((short)-1234, decoded.GetField<short>("Int16Field"));
        Assert.Equal(99999u, decoded.GetField<uint>("UInt32Field"));
        Assert.Equal(2.71828f, decoded.GetField<float>("FloatField"));
        Assert.Equal("hello world", decoded.GetField<string>("StringField"));
    }

    [Fact]
    public void StructureWithOptionalFields_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.StructureWithOptionalFields,
            DefaultEncodingId = new NodeId(1, 3001),
            Fields = new[]
            {
                new StructureField { Name = "Required1", DataType = new NodeId(0, 6), IsOptional = false },
                new StructureField { Name = "Optional1", DataType = new NodeId(0, 12), IsOptional = true },
                new StructureField { Name = "Optional2", DataType = new NodeId(0, 11), IsOptional = true },
                new StructureField { Name = "Required2", DataType = new NodeId(0, 1), IsOptional = false },
            }
        };

        var registry = new DataTypeRegistry();

        // Only set Required1, Optional2, Required2 (skip Optional1)
        var original = new StructuredValue { Definition = def };
        original["Required1"] = 42;
        original["Optional2"] = 3.14;
        original["Required2"] = true;

        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, registry));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, registry);

        Assert.NotNull(decoded);
        Assert.Equal(42, decoded.GetField<int>("Required1"));
        Assert.Null(decoded["Optional1"]);
        Assert.Equal(3.14, decoded.GetField<double>("Optional2"));
        Assert.True(decoded.GetField<bool>("Required2"));
    }

    [Fact]
    public void Union_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.Union,
            DefaultEncodingId = new NodeId(1, 4001),
            Fields = new[]
            {
                new StructureField { Name = "IntChoice", DataType = new NodeId(0, 6) },
                new StructureField { Name = "StringChoice", DataType = new NodeId(0, 12) },
                new StructureField { Name = "DoubleChoice", DataType = new NodeId(0, 11) },
            }
        };

        var registry = new DataTypeRegistry();

        // Select second field (StringChoice)
        var original = new StructuredValue { Definition = def, UnionSwitchField = 2 };
        original["StringChoice"] = "selected value";

        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, registry));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, registry);

        Assert.NotNull(decoded);
        Assert.Equal(2, decoded.UnionSwitchField);
        Assert.Equal("selected value", decoded.GetField<string>("StringChoice"));
    }

    [Fact]
    public void Union_Null_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.Union,
            DefaultEncodingId = new NodeId(1, 4002),
            Fields = new[]
            {
                new StructureField { Name = "Choice1", DataType = new NodeId(0, 6) },
            }
        };

        var original = new StructuredValue { Definition = def, UnionSwitchField = 0 };

        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, new DataTypeRegistry()));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, new DataTypeRegistry());

        Assert.Equal(0, decoded.UnionSwitchField);
        Assert.Empty(decoded.Fields);
    }

    [Fact]
    public void NestedStructure_RoundTrip()
    {
        var innerDef = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            DefaultEncodingId = new NodeId(1, 5001),
            Fields = new[]
            {
                new StructureField { Name = "X", DataType = new NodeId(0, 11) },
                new StructureField { Name = "Y", DataType = new NodeId(0, 11) },
            }
        };

        var outerDef = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            DefaultEncodingId = new NodeId(1, 5002),
            Fields = new[]
            {
                new StructureField { Name = "Name", DataType = new NodeId(0, 12) },
                new StructureField { Name = "Position", DataType = new NodeId(1, 5000) }, // Custom type
            }
        };

        var registry = new DataTypeRegistry();
        registry.Register(innerDef.DefaultEncodingId, new NodeId(1, 5000), innerDef);
        registry.Register(outerDef.DefaultEncodingId, new NodeId(1, 5100), outerDef);

        var innerVal = new StructuredValue { Definition = innerDef };
        innerVal["X"] = 1.5;
        innerVal["Y"] = 2.5;

        var outerVal = new StructuredValue { Definition = outerDef };
        outerVal["Name"] = "Point A";
        outerVal["Position"] = innerVal;

        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, outerVal, registry));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, outerDef, registry);

        Assert.NotNull(decoded);
        Assert.Equal("Point A", decoded.GetField<string>("Name"));
        var pos = decoded.GetField<StructuredValue>("Position");
        Assert.NotNull(pos);
        Assert.Equal(1.5, pos.GetField<double>("X"));
        Assert.Equal(2.5, pos.GetField<double>("Y"));
    }

    [Fact]
    public void ArrayField_RoundTrip()
    {
        var def = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            DefaultEncodingId = new NodeId(1, 6001),
            Fields = new[]
            {
                new StructureField { Name = "Label", DataType = new NodeId(0, 12) },
                new StructureField { Name = "Values", DataType = new NodeId(0, 11), ValueRank = 1 },
            }
        };

        var original = new StructuredValue { Definition = def };
        original["Label"] = "measurements";
        original["Values"] = new object[] { 1.1, 2.2, 3.3 };

        var registry = new DataTypeRegistry();
        var buf = new MemoryBuffer(4096);
        Assert.True(StructuredTypeCodec.Encode(buf, original, registry));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        var decoded = StructuredTypeCodec.Decode(readBuf, def, registry);

        Assert.NotNull(decoded);
        Assert.Equal("measurements", decoded.GetField<string>("Label"));
        var arr = decoded["Values"] as object[];
        Assert.NotNull(arr);
        Assert.Equal(3, arr.Length);
        Assert.Equal(1.1, arr[0]);
        Assert.Equal(3.3, arr[2]);
    }

    #endregion

    #region DataTypeRegistry

    [Fact]
    public void Registry_RegisterAndLookup()
    {
        var registry = new DataTypeRegistry();
        var def = new StructureDefinition
        {
            StructureType = StructureType.Structure,
            Fields = new[] { new StructureField { Name = "X", DataType = new NodeId(0, 11) } }
        };

        var encodingId = new NodeId(1, 100);
        var dataTypeId = new NodeId(1, 99);
        registry.Register(encodingId, dataTypeId, def);

        Assert.True(registry.IsKnown(encodingId));
        Assert.True(registry.TryGetByEncodingId(encodingId, out var found1));
        Assert.Same(def, found1);
        Assert.True(registry.TryGetByDataTypeId(dataTypeId, out var found2));
        Assert.Same(def, found2);
        Assert.Equal(1, registry.Count);
    }

    [Fact]
    public void Registry_UnknownId_ReturnsFalse()
    {
        var registry = new DataTypeRegistry();
        Assert.False(registry.IsKnown(new NodeId(1, 999)));
        Assert.False(registry.TryGetByEncodingId(new NodeId(1, 999), out _));
    }

    #endregion

    #region StructuredValue API

    [Fact]
    public void StructuredValue_Indexer_And_GetField()
    {
        var sv = new StructuredValue();
        sv["Temp"] = 42.5;
        sv["Name"] = "test";

        Assert.Equal(42.5, sv["Temp"]);
        Assert.Equal(42.5, sv.GetField<double>("Temp"));
        Assert.Equal("test", sv.GetField<string>("Name"));
        Assert.True(sv.HasField("Temp"));
        Assert.False(sv.HasField("Missing"));
        Assert.Null(sv["Missing"]);
    }

    #endregion
}
