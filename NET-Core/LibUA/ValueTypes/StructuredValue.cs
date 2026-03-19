using System.Collections.Generic;
using System.Linq;
using System.Text;
using LibUA.Core;

namespace LibUA.ValueTypes;

/// <summary>
/// Decoded instance of a custom OPC UA structured DataType.
/// Fields are accessible by name via dictionary or indexer.
/// </summary>
public class StructuredValue
{
    /// <summary>Encoding NodeId (identifies this type on the wire)</summary>
    public NodeId TypeId { get; set; }

    /// <summary>The definition used to decode/encode this value</summary>
    public StructureDefinition Definition { get; set; }

    /// <summary>Decoded field values, keyed by field name</summary>
    public Dictionary<string, object> Fields { get; } = new();

    /// <summary>For Union types: which field is active (0 = null, 1-N = field index)</summary>
    public int? UnionSwitchField { get; set; }

    /// <summary>Access fields by name</summary>
    public object this[string fieldName]
    {
        get => Fields.TryGetValue(fieldName, out var v) ? v : null;
        set => Fields[fieldName] = value;
    }

    /// <summary>Get a field value with type casting</summary>
    public T GetField<T>(string fieldName)
    {
        if (Fields.TryGetValue(fieldName, out var v) && v is T typed)
            return typed;
        return default;
    }

    /// <summary>Check if a field exists and has a non-null value</summary>
    public bool HasField(string fieldName) => Fields.ContainsKey(fieldName) && Fields[fieldName] != null;

    public override string ToString()
    {
        var sb = new StringBuilder();
        var typeName = Definition?.Fields?.Length > 0 ? "Struct" : "Unknown";
        if (Definition?.StructureType == ValueTypes.StructureType.Union)
            typeName = "Union";

        sb.Append($"{typeName}(");
        sb.Append(string.Join(", ", Fields.Select(f => $"{f.Key}={f.Value}")));
        sb.Append(')');
        return sb.ToString();
    }
}
