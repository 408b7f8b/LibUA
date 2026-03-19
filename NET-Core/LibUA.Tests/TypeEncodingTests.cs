using LibUA.Core;

namespace LibUA.Tests;

public class TypeEncodingTests
{
    private static MemoryBuffer RoundTrip(Action<MemoryBuffer> encode)
    {
        var buf = new MemoryBuffer(4096);
        encode(buf);
        return new MemoryBuffer(buf.Buffer, buf.Position);
    }

    #region DiagnosticInfo

    [Fact]
    public void DiagnosticInfo_Empty_RoundTrip()
    {
        var original = new DiagnosticInfo();
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out DiagnosticInfo decoded));
        Assert.Equal((byte)0, decoded.GetEncodingMask());
    }

    [Fact]
    public void DiagnosticInfo_AllFields_RoundTrip()
    {
        var original = new DiagnosticInfo
        {
            SymbolicId = 1,
            NamespaceUri = 2,
            LocalizedText = 3,
            Locale = 4,
            AdditionalInfo = "test error",
            InnerStatusCode = 0x80000000,
        };

        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out DiagnosticInfo decoded));
        Assert.Equal(1, decoded.SymbolicId);
        Assert.Equal(2, decoded.NamespaceUri);
        Assert.Equal(3, decoded.LocalizedText);
        Assert.Equal(4, decoded.Locale);
        Assert.Equal("test error", decoded.AdditionalInfo);
        Assert.Equal(0x80000000u, decoded.InnerStatusCode);
    }

    [Fact]
    public void DiagnosticInfo_Nested_RoundTrip()
    {
        var original = new DiagnosticInfo
        {
            SymbolicId = 10,
            InnerDiagnosticInfo = new DiagnosticInfo
            {
                AdditionalInfo = "inner error",
                InnerDiagnosticInfo = new DiagnosticInfo
                {
                    Locale = 99,
                }
            }
        };

        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out DiagnosticInfo decoded));
        Assert.Equal(10, decoded.SymbolicId);
        Assert.NotNull(decoded.InnerDiagnosticInfo);
        Assert.Equal("inner error", decoded.InnerDiagnosticInfo.AdditionalInfo);
        Assert.NotNull(decoded.InnerDiagnosticInfo.InnerDiagnosticInfo);
        Assert.Equal(99, decoded.InnerDiagnosticInfo.InnerDiagnosticInfo.Locale);
    }

    [Fact]
    public void DiagnosticInfo_Null_RoundTrip()
    {
        var buf = RoundTrip(b => b.Encode((DiagnosticInfo)null));
        Assert.True(buf.Decode(out DiagnosticInfo decoded));
        Assert.Equal((byte)0, decoded.GetEncodingMask());
    }

    [Fact]
    public void DiagnosticInfo_Array_RoundTrip()
    {
        var original = new DiagnosticInfo[]
        {
            new() { SymbolicId = 1 },
            new() { AdditionalInfo = "second" },
        };

        var buf = new MemoryBuffer(4096);
        buf.Encode((uint)original.Length);
        foreach (var di in original) buf.Encode(di);

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.Decode(out DiagnosticInfo[] decoded));
        Assert.Equal(2, decoded.Length);
        Assert.Equal(1, decoded[0].SymbolicId);
        Assert.Equal("second", decoded[1].AdditionalInfo);
    }

    #endregion

    #region ExpandedNodeId

    [Fact]
    public void ExpandedNodeId_Simple_RoundTrip()
    {
        var original = new ExpandedNodeId(new NodeId(2, 1234));
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out ExpandedNodeId decoded));
        Assert.Equal(2, decoded.NodeId.NamespaceIndex);
        Assert.Equal(1234u, decoded.NodeId.NumericIdentifier);
        Assert.Null(decoded.NamespaceUri);
        Assert.Equal(0u, decoded.ServerIndex);
    }

    [Fact]
    public void ExpandedNodeId_WithNamespaceUri_RoundTrip()
    {
        var original = new ExpandedNodeId(new NodeId(0, 42), "http://example.com/ns", 0);
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out ExpandedNodeId decoded));
        Assert.Equal(42u, decoded.NodeId.NumericIdentifier);
        Assert.Equal("http://example.com/ns", decoded.NamespaceUri);
    }

    [Fact]
    public void ExpandedNodeId_WithServerIndex_RoundTrip()
    {
        var original = new ExpandedNodeId(new NodeId(0, 1), null, 5);
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out ExpandedNodeId decoded));
        Assert.Equal(1u, decoded.NodeId.NumericIdentifier);
        Assert.Equal(5u, decoded.ServerIndex);
    }

    [Fact]
    public void ExpandedNodeId_WithBoth_RoundTrip()
    {
        var original = new ExpandedNodeId(new NodeId(3, 999), "urn:test", 7);
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out ExpandedNodeId decoded));
        Assert.Equal(3, decoded.NodeId.NamespaceIndex);
        Assert.Equal(999u, decoded.NodeId.NumericIdentifier);
        Assert.Equal("urn:test", decoded.NamespaceUri);
        Assert.Equal(7u, decoded.ServerIndex);
    }

    [Fact]
    public void ExpandedNodeId_StringNodeId_RoundTrip()
    {
        var original = new ExpandedNodeId(new NodeId(1, "MyNode"), "urn:ns", 0);
        var buf = RoundTrip(b => b.Encode(original));
        Assert.True(buf.Decode(out ExpandedNodeId decoded));
        Assert.Equal("MyNode", decoded.NodeId.StringIdentifier);
        Assert.Equal("urn:ns", decoded.NamespaceUri);
    }

    [Fact]
    public void NodeId_Decode_ConsumesExpandedBits()
    {
        // Encode an ExpandedNodeId with NamespaceUri
        var expanded = new ExpandedNodeId(new NodeId(0, 42), "http://test.com", 3);
        var buf = RoundTrip(b => b.Encode(expanded));

        // Decode as plain NodeId — should consume all bytes without error
        Assert.True(buf.Decode(out NodeId nodeId));
        Assert.Equal(42u, nodeId.NumericIdentifier);
        Assert.Equal(0, buf.Position - buf.Capacity); // All bytes consumed
    }

    #endregion

    #region Variant Types

    [Fact]
    public void Variant_Guid_RoundTrip()
    {
        var guid = Guid.Parse("72962B91-FA75-4AE6-8D28-B404DC7DAF63");
        var buf = new MemoryBuffer(256);
        Assert.True(buf.VariantEncode(guid));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.VariantDecode(out object decoded));
        Assert.IsType<Guid>(decoded);
        Assert.Equal(guid, (Guid)decoded);
    }

    [Fact]
    public void Variant_ExpandedNodeId_RoundTrip()
    {
        var expandedNid = new ExpandedNodeId(new NodeId(2, 100));
        var buf = new MemoryBuffer(256);
        Assert.True(buf.VariantEncode(expandedNid));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.VariantDecode(out object decoded));
        Assert.IsType<ExpandedNodeId>(decoded);
        Assert.Equal(100u, ((ExpandedNodeId)decoded).NodeId.NumericIdentifier);
    }

    [Fact]
    public void Variant_DiagnosticInfo_RoundTrip()
    {
        var di = new DiagnosticInfo { SymbolicId = 42, AdditionalInfo = "test" };
        var buf = new MemoryBuffer(256);
        Assert.True(buf.VariantEncode(di));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.VariantDecode(out object decoded));
        Assert.IsType<DiagnosticInfo>(decoded);
        Assert.Equal(42, ((DiagnosticInfo)decoded).SymbolicId);
    }

    [Fact]
    public void Variant_GuidArray_RoundTrip()
    {
        var guids = new Guid[] { Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid() };
        var buf = new MemoryBuffer(256);
        Assert.True(buf.VariantEncode(guids));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.VariantDecode(out object decoded));
        var arr = Assert.IsType<Guid[]>(decoded);
        Assert.Equal(3, arr.Length);
        Assert.Equal(guids[0], arr[0]);
        Assert.Equal(guids[2], arr[2]);
    }

    #endregion

    #region DataValue Picoseconds

    [Fact]
    public void DataValue_WithPicoseconds_RoundTrip()
    {
        var original = new DataValue
        {
            Value = 42,
            StatusCode = (uint)StatusCode.Good,
            SourceTimestamp = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc),
            SourcePicoseconds = 12345,
            ServerTimestamp = new DateTime(2025, 6, 15, 12, 0, 1, DateTimeKind.Utc),
            ServerPicoseconds = 54321,
        };

        var buf = new MemoryBuffer(256);
        Assert.True(buf.Encode(original));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.Decode(out DataValue decoded));

        Assert.Equal(42, decoded.Value);
        Assert.Equal((uint)StatusCode.Good, decoded.StatusCode);
        Assert.Equal(original.SourceTimestamp, decoded.SourceTimestamp);
        Assert.Equal((ushort)12345, decoded.SourcePicoseconds);
        Assert.Equal(original.ServerTimestamp, decoded.ServerTimestamp);
        Assert.Equal((ushort)54321, decoded.ServerPicoseconds);
    }

    [Fact]
    public void DataValue_NoPicoseconds_RoundTrip()
    {
        var original = new DataValue
        {
            Value = "hello",
            SourceTimestamp = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ServerTimestamp = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };

        var buf = new MemoryBuffer(256);
        Assert.True(buf.Encode(original));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.Decode(out DataValue decoded));

        Assert.Equal("hello", decoded.Value);
        Assert.Null(decoded.SourcePicoseconds);
        Assert.Null(decoded.ServerPicoseconds);
    }

    [Fact]
    public void DataValue_OnlySourcePicoseconds_RoundTrip()
    {
        var original = new DataValue
        {
            Value = 3.14,
            SourceTimestamp = DateTime.UtcNow,
            SourcePicoseconds = 999,
            // No ServerTimestamp or ServerPicoseconds
        };

        var buf = new MemoryBuffer(256);
        Assert.True(buf.Encode(original));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.Decode(out DataValue decoded));

        Assert.Equal((ushort)999, decoded.SourcePicoseconds);
        Assert.Null(decoded.ServerPicoseconds);
        Assert.Null(decoded.ServerTimestamp);
    }

    [Fact]
    public void DataValue_MultipleWithPicoseconds_Sequential()
    {
        // This tests the exact scenario that was failing with node-opcua:
        // Multiple DataValues with picoseconds decoded sequentially
        var dv1 = new DataValue
        {
            Value = 0,
            ServerTimestamp = DateTime.UtcNow,
            ServerPicoseconds = 100,
        };
        var dv2 = new DataValue
        {
            Value = DateTime.UtcNow,
            SourceTimestamp = DateTime.UtcNow,
            SourcePicoseconds = 200,
            ServerTimestamp = DateTime.UtcNow,
            ServerPicoseconds = 300,
        };
        var dv3 = new DataValue
        {
            Value = "test",
            ServerTimestamp = DateTime.UtcNow,
            ServerPicoseconds = 400,
        };

        var buf = new MemoryBuffer(1024);
        Assert.True(buf.Encode(dv1));
        Assert.True(buf.Encode(dv2));
        Assert.True(buf.Encode(dv3));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.Decode(out DataValue d1));
        Assert.True(readBuf.Decode(out DataValue d2));
        Assert.True(readBuf.Decode(out DataValue d3));

        Assert.Equal(0, d1.Value);
        Assert.Equal((ushort)100, d1.ServerPicoseconds);

        Assert.IsType<DateTime>(d2.Value);
        Assert.Equal((ushort)200, d2.SourcePicoseconds);
        Assert.Equal((ushort)300, d2.ServerPicoseconds);

        Assert.Equal("test", d3.Value);
        Assert.Equal((ushort)400, d3.ServerPicoseconds);
    }

    #endregion

    #region Multidimensional Arrays

    [Fact]
    public void Variant_MultidimensionalArray_2D_RoundTrip()
    {
        var original = new int[2, 3] { { 1, 2, 3 }, { 4, 5, 6 } };
        var buf = new MemoryBuffer(256);
        Assert.True(buf.VariantEncode(original));

        var readBuf = new MemoryBuffer(buf.Buffer, buf.Position);
        Assert.True(readBuf.VariantDecode(out object decoded));

        var arr = decoded as int[,];
        Assert.NotNull(arr);
        Assert.Equal(2, arr.GetLength(0));
        Assert.Equal(3, arr.GetLength(1));
        Assert.Equal(1, arr[0, 0]);
        Assert.Equal(6, arr[1, 2]);
    }

    #endregion
}
