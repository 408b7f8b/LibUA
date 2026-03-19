using System.Collections.Concurrent;
using LibUA.Core;

namespace LibUA.ValueTypes;

/// <summary>
/// Registry of custom DataType definitions, populated by reading from an OPC UA server.
/// Maps encoding NodeIds and DataType NodeIds to StructureDefinitions.
/// Each Client instance has its own registry (different servers have different namespaces).
/// </summary>
public class DataTypeRegistry
{
    private readonly ConcurrentDictionary<string, StructureDefinition> _encodingToDefinition = new();
    private readonly ConcurrentDictionary<string, StructureDefinition> _dataTypeToDefinition = new();
    private readonly ConcurrentDictionary<string, NodeId> _encodingToDataType = new();

    private static string Key(NodeId id) => id == null ? "null" : $"{id.NamespaceIndex}:{id.NumericIdentifier}:{id.StringIdentifier}";

    /// <summary>Register a DataType definition with its encoding and DataType NodeIds.</summary>
    public void Register(NodeId encodingId, NodeId dataTypeId, StructureDefinition definition)
    {
        if (encodingId != null)
        {
            _encodingToDefinition[Key(encodingId)] = definition;
            if (dataTypeId != null)
                _encodingToDataType[Key(encodingId)] = dataTypeId;
        }
        if (dataTypeId != null)
            _dataTypeToDefinition[Key(dataTypeId)] = definition;
    }

    /// <summary>Look up a definition by the encoding NodeId (from ExtensionObject.TypeId).</summary>
    public bool TryGetByEncodingId(NodeId encodingId, out StructureDefinition definition)
    {
        return _encodingToDefinition.TryGetValue(Key(encodingId), out definition);
    }

    /// <summary>Look up a definition by the DataType NodeId (from a Variable's DataType attribute).</summary>
    public bool TryGetByDataTypeId(NodeId dataTypeId, out StructureDefinition definition)
    {
        return _dataTypeToDefinition.TryGetValue(Key(dataTypeId), out definition);
    }

    /// <summary>Check if an encoding NodeId is known.</summary>
    public bool IsKnown(NodeId encodingId)
    {
        return _encodingToDefinition.ContainsKey(Key(encodingId));
    }

    /// <summary>Get the DataType NodeId for an encoding NodeId.</summary>
    public NodeId GetDataTypeId(NodeId encodingId)
    {
        return _encodingToDataType.TryGetValue(Key(encodingId), out var dataTypeId) ? dataTypeId : null;
    }

    /// <summary>Number of registered definitions.</summary>
    public int Count => _encodingToDefinition.Count;

    /// <summary>Clear all registered definitions.</summary>
    public void Clear()
    {
        _encodingToDefinition.Clear();
        _dataTypeToDefinition.Clear();
        _encodingToDataType.Clear();
    }
}
