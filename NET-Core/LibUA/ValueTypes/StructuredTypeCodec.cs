using System;
using System.Collections.Generic;
using LibUA.Core;

namespace LibUA.ValueTypes;

/// <summary>
/// Binary encoder/decoder for custom OPC UA structured DataTypes.
/// Uses StructureDefinition metadata to decode/encode ExtensionObject bodies.
/// </summary>
public static class StructuredTypeCodec
{
    // OPC UA namespace 0 DataType NodeIds → VariantType mapping for built-in types
    private static readonly Dictionary<uint, VariantType> BuiltInTypeMap = new()
    {
        { 1, VariantType.Boolean },
        { 2, VariantType.SByte },
        { 3, VariantType.Byte },
        { 4, VariantType.Int16 },
        { 5, VariantType.UInt16 },
        { 6, VariantType.Int32 },
        { 7, VariantType.UInt32 },
        { 8, VariantType.Int64 },
        { 9, VariantType.UInt64 },
        { 10, VariantType.Float },
        { 11, VariantType.Double },
        { 12, VariantType.String },
        { 13, VariantType.DateTime },
        { 14, VariantType.Guid },
        { 15, VariantType.ByteString },
        { 17, VariantType.NodeId },
        { 18, VariantType.ExpandedNodeId },
        { 19, VariantType.StatusCode },
        { 20, VariantType.QualifiedName },
        { 21, VariantType.LocalizedText },
        { 22, VariantType.ExtensionObject },
        { 23, VariantType.DataValue },
        { 24, VariantType.Variant },
        { 25, VariantType.DiagnosticInfo },
        { 29, VariantType.Int32 }, // Enumeration → encoded as Int32
    };

    /// <summary>
    /// Decode a structured value from a binary buffer using its StructureDefinition.
    /// </summary>
    public static StructuredValue Decode(MemoryBuffer buf, StructureDefinition def, DataTypeRegistry registry)
    {
        if (def == null || def.Fields == null) return null;

        var result = new StructuredValue
        {
            TypeId = def.DefaultEncodingId,
            Definition = def,
        };

        switch (def.StructureType)
        {
            case StructureType.Structure:
                foreach (var field in def.Fields)
                {
                    var value = DecodeField(buf, field, registry);
                    result.Fields[field.Name] = value;
                }
                break;

            case StructureType.StructureWithOptionalFields:
                if (!buf.Decode(out uint optionalMask)) return null;
                int optBitIndex = 0;
                foreach (var field in def.Fields)
                {
                    if (field.IsOptional)
                    {
                        if ((optionalMask & (1u << optBitIndex)) == 0)
                        {
                            result.Fields[field.Name] = null;
                            optBitIndex++;
                            continue;
                        }
                        optBitIndex++;
                    }
                    result.Fields[field.Name] = DecodeField(buf, field, registry);
                }
                break;

            case StructureType.Union:
                if (!buf.Decode(out uint switchField)) return null;
                result.UnionSwitchField = (int)switchField;
                if (switchField == 0)
                {
                    // Null union
                }
                else if (switchField <= def.Fields.Length)
                {
                    var field = def.Fields[switchField - 1];
                    result.Fields[field.Name] = DecodeField(buf, field, registry);
                }
                break;
        }

        return result;
    }

    /// <summary>
    /// Encode a structured value into a binary buffer.
    /// </summary>
    public static bool Encode(MemoryBuffer buf, StructuredValue value, DataTypeRegistry registry)
    {
        if (value?.Definition?.Fields == null) return false;
        var def = value.Definition;

        switch (def.StructureType)
        {
            case StructureType.Structure:
                foreach (var field in def.Fields)
                {
                    value.Fields.TryGetValue(field.Name, out var fieldValue);
                    if (!EncodeField(buf, field, fieldValue, registry)) return false;
                }
                break;

            case StructureType.StructureWithOptionalFields:
                uint mask = 0;
                int bitIdx = 0;
                foreach (var field in def.Fields)
                {
                    if (field.IsOptional)
                    {
                        if (value.HasField(field.Name))
                            mask |= (1u << bitIdx);
                        bitIdx++;
                    }
                }
                if (!buf.Encode(mask)) return false;

                bitIdx = 0;
                foreach (var field in def.Fields)
                {
                    if (field.IsOptional)
                    {
                        if ((mask & (1u << bitIdx)) == 0)
                        {
                            bitIdx++;
                            continue;
                        }
                        bitIdx++;
                    }
                    value.Fields.TryGetValue(field.Name, out var fieldValue);
                    if (!EncodeField(buf, field, fieldValue, registry)) return false;
                }
                break;

            case StructureType.Union:
                var sw = (uint)(value.UnionSwitchField ?? 0);
                if (!buf.Encode(sw)) return false;
                if (sw > 0 && sw <= def.Fields.Length)
                {
                    var field = def.Fields[sw - 1];
                    value.Fields.TryGetValue(field.Name, out var fieldValue);
                    if (!EncodeField(buf, field, fieldValue, registry)) return false;
                }
                break;
        }

        return true;
    }

    private static object DecodeField(MemoryBuffer buf, StructureField field, DataTypeRegistry registry)
    {
        if (field.ValueRank >= 1)
        {
            // Array field
            if (!buf.Decode(out int arrLen)) return null;
            if (arrLen < 0) return null;

            var arr = new object[arrLen];
            for (int i = 0; i < arrLen; i++)
            {
                arr[i] = DecodeScalarField(buf, field, registry);
            }
            return arr;
        }

        return DecodeScalarField(buf, field, registry);
    }

    private static object DecodeScalarField(MemoryBuffer buf, StructureField field, DataTypeRegistry registry)
    {
        var dataTypeId = field.DataType;

        // Check if it's a built-in type (namespace 0)
        if (dataTypeId != null && dataTypeId.NamespaceIndex == 0 &&
            BuiltInTypeMap.TryGetValue(dataTypeId.NumericIdentifier, out var varType))
        {
            // Use VariantDecode's per-type decode
            byte mask = (byte)varType;
            if (buf.VariantDecode(out object val, mask))
                return val;
            return null;
        }

        // Check if it's a known custom structured type (nested structure)
        if (registry != null && dataTypeId != null && registry.TryGetByDataTypeId(dataTypeId, out var nestedDef))
        {
            return Decode(buf, nestedDef, registry);
        }

        // Unknown type — try as Variant (some servers encode unknown fields as Variant)
        if (buf.VariantDecode(out object varVal))
            return varVal;

        return null;
    }

    private static bool EncodeField(MemoryBuffer buf, StructureField field, object value, DataTypeRegistry registry)
    {
        if (field.ValueRank >= 1)
        {
            // Array field
            if (value is object[] arr)
            {
                if (!buf.Encode((int)arr.Length)) return false;
                foreach (var elem in arr)
                {
                    if (!EncodeScalarField(buf, field, elem, registry)) return false;
                }
                return true;
            }
            // Null array
            if (!buf.Encode((int)-1)) return false;
            return true;
        }

        return EncodeScalarField(buf, field, value, registry);
    }

    private static bool EncodeScalarField(MemoryBuffer buf, StructureField field, object value, DataTypeRegistry registry)
    {
        var dataTypeId = field.DataType;

        // Built-in type
        if (dataTypeId != null && dataTypeId.NamespaceIndex == 0 &&
            BuiltInTypeMap.TryGetValue(dataTypeId.NumericIdentifier, out var varType))
        {
            byte mask = (byte)varType;
            return buf.VariantEncode(value, mask);
        }

        // Nested structured type
        if (value is StructuredValue sv && registry != null)
        {
            return Encode(buf, sv, registry);
        }

        // Fallback: encode as Variant
        return buf.VariantEncode(value);
    }
}
