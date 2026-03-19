using LibUA.Core;

namespace LibUA.ValueTypes;

/// <summary>
/// OPC UA Part 3: StructureType enum for structured DataTypes.
/// </summary>
public enum StructureType : int
{
    Structure = 0,
    StructureWithOptionalFields = 1,
    Union = 2,
}

/// <summary>
/// OPC UA Part 3: Definition of a single field within a StructureDefinition.
/// </summary>
public class StructureField
{
    public string Name { get; set; }
    public LocalizedText Description { get; set; }
    public NodeId DataType { get; set; }
    public int ValueRank { get; set; } = -1;        // -1 = scalar, 1 = one-dimensional array
    public uint[] ArrayDimensions { get; set; }
    public uint MaxStringLength { get; set; }
    public bool IsOptional { get; set; }

    public override string ToString() => $"{Name} ({DataType}, VR={ValueRank}{(IsOptional ? ", optional" : "")})";
}

/// <summary>
/// OPC UA Part 3: Complete definition of a structured DataType.
/// Obtained by reading the DataTypeDefinition attribute (OPC UA 1.04+)
/// or from a DataTypeDictionary (legacy).
/// </summary>
public class StructureDefinition
{
    public NodeId DefaultEncodingId { get; set; }
    public NodeId BaseDataType { get; set; }
    public StructureType StructureType { get; set; }
    public StructureField[] Fields { get; set; }

    public override string ToString() => $"StructureDefinition({StructureType}, {Fields?.Length ?? 0} fields, Encoding={DefaultEncodingId})";
}
