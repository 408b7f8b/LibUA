# OPC UA Client Compatibility Fixes

This document describes the compatibility fixes applied to the LibUA OPC UA client
to improve conformance with IEC 62541 (OPC UA specification) and interoperability
with real-world OPC UA servers.

## Motivation

The LibUA client had 14+ verified compatibility issues that caused crashes, data
corruption, or connection failures with servers from Siemens, Beckhoff, Unified
Automation, Kepware, and others. These fixes address all critical and most severe
issues.

---

## 1. New Types: DiagnosticInfo and ExpandedNodeId

**Files:** `Types.cs`, `MemoryBufferExtensions.cs`

### DiagnosticInfo

OPC UA services return `DiagnosticInfo` structures in response headers and error
responses. Previously, LibUA only read a single byte (the encoding mask) and
discarded the rest, causing stream desynchronization when servers sent non-empty
diagnostics.

```csharp
public class DiagnosticInfo
{
    public int? SymbolicId { get; set; }           // Bit 0
    public int? NamespaceUri { get; set; }          // Bit 1
    public int? LocalizedText { get; set; }         // Bit 2
    public int? Locale { get; set; }                // Bit 3
    public string AdditionalInfo { get; set; }      // Bit 4
    public uint? InnerStatusCode { get; set; }      // Bit 5
    public DiagnosticInfo InnerDiagnosticInfo { get; set; }  // Bit 6, recursive
}
```

Encoding is bitmask-driven per OPC UA Part 6, 5.2.2.12. The `InnerDiagnosticInfo`
field enables recursive nesting as required by the specification.

### ExpandedNodeId

OPC UA uses ExpandedNodeId for cross-server references. The encoding uses bit flags
in the NodeId encoding byte:
- Bit 0x80: NamespaceUri string follows after the NodeId body
- Bit 0x40: ServerIndex (UInt32) follows after NamespaceUri

Previously, the 0x80 bit was not consumed during NodeId decoding, causing the
deserialization cursor to go out of sync for the remainder of the message.

**Breaking change:** `Decode(out NodeId)` now internally calls `DecodeNodeId()` which
consumes the 0x80 and 0x40 trailing fields. This is wire-compatible but means
ExpandedNodeId information (NamespaceUri, ServerIndex) is discarded when decoding
as plain NodeId. Use `Decode(out ExpandedNodeId)` to capture these fields.

---

## 2. Variant Type Completion

**Files:** `MemoryBuffer.cs`, `Coding.cs`

Six previously unimplemented Variant types now work:

| Type | Encoding | Notes |
|------|----------|-------|
| **Guid** | 16 raw bytes (LE layout) | `Guid.ToByteArray()` produces correct OPC UA wire format on LE systems |
| **XmlElement** | UAString | OPC UA encodes XML elements as length-prefixed UTF-8 strings |
| **ExpandedNodeId** | NodeId + optional NamespaceUri + ServerIndex | Uses new Encode/Decode from Phase 1 |
| **DataValue** | Existing Encode/Decode | Was already implemented but not wired into Variant switch |
| **Variant** (nested) | Recursive | A Variant containing another Variant |
| **DiagnosticInfo** | Bitmask-driven | Uses new Encode/Decode from Phase 1 |

All three `Coding.cs` mapping methods (`GetNetType`, `GetVariantTypeFromInstance`,
`GetVariantTypeFromType`) and `VariantCodingSize` are updated accordingly.

### Multidimensional Array Decoding

Previously, dimension information was read and discarded. Now:
```csharp
// Dimensions are read and used to reconstruct the multi-dim array
var multiArray = Array.CreateInstance(elementType, dimensions);
// ... index mapping from flat to multi-dimensional
```

**Compatibility note:** Code that previously received flat `T[]` arrays may now
receive `T[,]` or `T[,,]` etc. for multidimensional data. This only affects servers
that actually send multidimensional arrays (rare in practice).

---

## 3. ResponseHeader DiagnosticInfo

**Files:** `Types.cs`, `MemoryBufferExtensions.cs`

`ResponseHeader.ServiceDiagnosticsMask` (byte) replaced with
`ResponseHeader.ServiceDiagnostics` (DiagnosticInfo). A computed property
`ServiceDiagnosticsMask` is retained for backward compatibility.

The Decode method now reads the full DiagnosticInfo structure instead of a single
byte. The Encode method writes the DiagnosticInfo structure instead of hardcoded `0x00`.

---

## 4. Protocol Fixes in Client.cs

### 4a. DateTime.UtcNow

All 26 request header timestamps changed from `DateTime.Now` to `DateTime.UtcNow`.
OPC UA Part 6, 5.2.2.5 requires UTC timestamps.

### 4b. Abort Chunk Handling

Chunk type `'A'` (abort) is now recognized in `ChunkCalculateSizes()`. When an abort
chunk is received, the method returns an empty list, and the caller sets
`StatusCode.BadRequestInterrupted` instead of terminating the connection.

Spec reference: OPC UA Part 6, 6.7.2.4.

### 4c. Sequence Number Validation

The received sequence number is now validated against the expected value:
- Forward gaps are tolerated (some servers skip numbers)
- Backward jumps are rejected as potential replay attacks
- Wrap-around at 4294966271 → 1 per specification

### 4d. Token Lifetime / Session Timeout Separation

`SLChannel` gains a new `SessionTimeout` field. `CreateSession()` now stores
`revisedSessionTimeout` in `SessionTimeout` instead of overwriting `TokenLifetime`.
This prevents the secure channel renew timer from being set to the wrong interval.

### 4e. Error Message Handling

When an OPC UA Error message is received, all waiting ManualResetEvents are now
signaled so that blocked service calls can observe the error via `recvHandlerStatus`.
Previously, these calls would hang until timeout.

---

## 5. Subscription and Service Improvements

### SubscriptionAcknowledgements

A `ConcurrentQueue<(uint subscriptionId, uint sequenceNumber)>` tracks notification
sequence numbers. `ConsumeNotification()` enqueues them; `PublishRequest()` dequeues
and encodes them. Previously, all Publish requests sent 0 acknowledgements, causing
servers to retransmit unnecessarily.

### Multiple Outstanding Publish Requests

New property `MaxOutstandingPublishRequests` (default: 2). `CreateSubscription()`
fills up to this many outstanding Publish requests. The OPC UA specification
recommends at least one per subscription.

### New Service Methods

Three service methods added following the established pattern (lock → encode → send → wait → decode):

- **`RegisterNodes(NodeId[], out NodeId[])`** — Request 560/563
- **`UnregisterNodes(NodeId[])`** — Request 566/569
- **`SetMonitoringMode(uint, MonitoringMode, uint[], out uint[])`** — Request 769/772

### CloseSession Parameter

`CloseSession()` now accepts `bool deleteSubscriptions = true`. The previous
hardcoded `false` was non-standard.

---

## 6. 4096-bit RSA Key Support

**File:** `Security.cs`

`CalculateSymmetricPaddingSize()` now supports keys larger than 2048 bits (256 bytes).
For large keys, a 2-byte padding header (ExtraPaddingByte) is used per OPC UA Part 6.

Both the encryption side (`SecureSymmetric`) and decryption side (`UnsecureSymmetric`)
are updated:
- **Encrypt:** writes `paddingDataLen & 0xFF` as padding value, then
  `(paddingDataLen >> 8) & 0xFF` as ExtraPaddingByte
- **Decrypt:** reads 2-byte padding size when `SymEncKey.Length > 256`

---

## Known Remaining Issues

These issues were identified but not fixed in this round:

1. **Fixed initial sequence number (51)** — should be random per spec
2. **MaxChunkCount hardcoded to 1337** — should be configurable
3. **Certificate thumbprint always uses SHA-1** via Basic128Rsa15
4. **Missing services:** SetTriggering, TransferSubscriptions, QueryFirst/Next
5. **No certificate validation:** ApplicationUri, hostname, CRL checks missing

---

## Testing

All 47 existing tests pass. Build succeeds on net6.0 through net9.0 with 0 errors.
The changes are wire-compatible with existing OPC UA servers — no protocol-level
breaking changes.
