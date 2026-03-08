# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [datapathplugins/datapathplugins.proto](#datapathplugins_datapathplugins-proto)
    - [AttachmentContext](#datapathplugins-AttachmentContext)
    - [AttachmentContext.TC](#datapathplugins-AttachmentContext-TC)
    - [AttachmentContext.TC.EndpointConfig](#datapathplugins-AttachmentContext-TC-EndpointConfig)
    - [LoadHooksRequest](#datapathplugins-LoadHooksRequest)
    - [LoadHooksRequest.Collection](#datapathplugins-LoadHooksRequest-Collection)
    - [LoadHooksRequest.Collection.Map](#datapathplugins-LoadHooksRequest-Collection-Map)
    - [LoadHooksRequest.Collection.MapsEntry](#datapathplugins-LoadHooksRequest-Collection-MapsEntry)
    - [LoadHooksRequest.Collection.Program](#datapathplugins-LoadHooksRequest-Collection-Program)
    - [LoadHooksRequest.Collection.ProgramsEntry](#datapathplugins-LoadHooksRequest-Collection-ProgramsEntry)
    - [LoadHooksRequest.Hook](#datapathplugins-LoadHooksRequest-Hook)
    - [LoadHooksRequest.Hook.AttachTarget](#datapathplugins-LoadHooksRequest-Hook-AttachTarget)
    - [LoadHooksResponse](#datapathplugins-LoadHooksResponse)
    - [LocalNodeConfig](#datapathplugins-LocalNodeConfig)
    - [PrepareHooksRequest](#datapathplugins-PrepareHooksRequest)
    - [PrepareHooksRequest.CollectionSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec)
    - [PrepareHooksRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec-MapSpec)
    - [PrepareHooksRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareHooksRequest-CollectionSpec-MapsEntry)
    - [PrepareHooksRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramSpec)
    - [PrepareHooksRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramsEntry)
    - [PrepareHooksResponse](#datapathplugins-PrepareHooksResponse)
    - [PrepareHooksResponse.HookSpec](#datapathplugins-PrepareHooksResponse-HookSpec)
    - [PrepareHooksResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint)
  
    - [HookType](#datapathplugins-HookType)
    - [PrepareHooksResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint-Order)
  
    - [DatapathPlugin](#datapathplugins-DatapathPlugin)
  
- [Scalar Value Types](#scalar-value-types)



<a name="datapathplugins_datapathplugins-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## datapathplugins/datapathplugins.proto



<a name="datapathplugins-AttachmentContext"></a>

### AttachmentContext
AttachmentContext contains the context about the attachment point in
question. It may carry endpoint-specific information used to determine which
hooks to load or how to configure them.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tc | [AttachmentContext.TC](#datapathplugins-AttachmentContext-TC) |  | XDP xdp = 2; CgroupSock cgroup_sock = 3; |






<a name="datapathplugins-AttachmentContext-TC"></a>

### AttachmentContext.TC



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ep_config | [AttachmentContext.TC.EndpointConfig](#datapathplugins-AttachmentContext-TC-EndpointConfig) |  |  |






<a name="datapathplugins-AttachmentContext-TC-EndpointConfig"></a>

### AttachmentContext.TC.EndpointConfig
Contains endpoint-specific config (IP, MAC, etc.)






<a name="datapathplugins-LoadHooksRequest"></a>

### LoadHooksRequest
Phase 2: Cilium has constructed and loaded the collection along with any
dispatcher programs that are meant to replace existing entrypoints in the
collection. Cilium sends a round of requests to any plugins that wanted to
inject hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [LoadHooksRequest.Collection](#datapathplugins-LoadHooksRequest-Collection) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |
| hooks | [LoadHooksRequest.Hook](#datapathplugins-LoadHooksRequest-Hook) | repeated |  |
| cookie | [string](#string) |  |  |






<a name="datapathplugins-LoadHooksRequest-Collection"></a>

### LoadHooksRequest.Collection
Program and map IDs in the collection


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [LoadHooksRequest.Collection.ProgramsEntry](#datapathplugins-LoadHooksRequest-Collection-ProgramsEntry) | repeated |  |
| maps | [LoadHooksRequest.Collection.MapsEntry](#datapathplugins-LoadHooksRequest-Collection-MapsEntry) | repeated |  |






<a name="datapathplugins-LoadHooksRequest-Collection-Map"></a>

### LoadHooksRequest.Collection.Map



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-LoadHooksRequest-Collection-MapsEntry"></a>

### LoadHooksRequest.Collection.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [LoadHooksRequest.Collection.Map](#datapathplugins-LoadHooksRequest-Collection-Map) |  |  |






<a name="datapathplugins-LoadHooksRequest-Collection-Program"></a>

### LoadHooksRequest.Collection.Program
Would contain information about programs and maps in this collection
such as names, IDs, etc. This could be consumed by plugin programs
themselves, e.g., for sharing map state.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  |  |






<a name="datapathplugins-LoadHooksRequest-Collection-ProgramsEntry"></a>

### LoadHooksRequest.Collection.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [LoadHooksRequest.Collection.Program](#datapathplugins-LoadHooksRequest-Collection-Program) |  |  |






<a name="datapathplugins-LoadHooksRequest-Hook"></a>

### LoadHooksRequest.Hook



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  |  |
| target | [string](#string) |  |  |
| attach_target | [LoadHooksRequest.Hook.AttachTarget](#datapathplugins-LoadHooksRequest-Hook-AttachTarget) |  | Contains target metadata necessary for freplace program load. |
| pin_path | [string](#string) |  | The plugin must pin the program to this pin path before responding to Cilium. |






<a name="datapathplugins-LoadHooksRequest-Hook-AttachTarget"></a>

### LoadHooksRequest.Hook.AttachTarget



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| program_id | [uint32](#uint32) |  |  |
| subprog_name | [string](#string) |  |  |






<a name="datapathplugins-LoadHooksResponse"></a>

### LoadHooksResponse







<a name="datapathplugins-LocalNodeConfig"></a>

### LocalNodeConfig
LocalNodeConfig is Cilium&#39;s current config for this node. It may be used
by plugins to decide which hooks to load, how to configure them, etc.

TBD






<a name="datapathplugins-PrepareHooksRequest"></a>

### PrepareHooksRequest
Phase 1: As Cilium loads and prepares a collection for a particular
attachment point, it sends a PrepareHooksRequest to each plugin with context
about the attachment point, collection, and local node config. The plugin
decides which hooks it would like to insert, where it would like to insert
them, and informs Cilium in the PrepareHooksResponse.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| collection | [PrepareHooksRequest.CollectionSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec) |  |  |
| local_node_config | [LocalNodeConfig](#datapathplugins-LocalNodeConfig) |  |  |
| attachment_context | [AttachmentContext](#datapathplugins-AttachmentContext) |  |  |






<a name="datapathplugins-PrepareHooksRequest-CollectionSpec"></a>

### PrepareHooksRequest.CollectionSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| programs | [PrepareHooksRequest.CollectionSpec.ProgramsEntry](#datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramsEntry) | repeated |  |
| maps | [PrepareHooksRequest.CollectionSpec.MapsEntry](#datapathplugins-PrepareHooksRequest-CollectionSpec-MapsEntry) | repeated |  |






<a name="datapathplugins-PrepareHooksRequest-CollectionSpec-MapSpec"></a>

### PrepareHooksRequest.CollectionSpec.MapSpec







<a name="datapathplugins-PrepareHooksRequest-CollectionSpec-MapsEntry"></a>

### PrepareHooksRequest.CollectionSpec.MapsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareHooksRequest.CollectionSpec.MapSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec-MapSpec) |  |  |






<a name="datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramSpec"></a>

### PrepareHooksRequest.CollectionSpec.ProgramSpec







<a name="datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramsEntry"></a>

### PrepareHooksRequest.CollectionSpec.ProgramsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [PrepareHooksRequest.CollectionSpec.ProgramSpec](#datapathplugins-PrepareHooksRequest-CollectionSpec-ProgramSpec) |  |  |






<a name="datapathplugins-PrepareHooksResponse"></a>

### PrepareHooksResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hooks | [PrepareHooksResponse.HookSpec](#datapathplugins-PrepareHooksResponse-HookSpec) | repeated |  |
| cookie | [string](#string) |  | May be used by a plugin to associate a LoadHooksRequest with its preceding PrepareHooksRequest or carry other metadata between phases that may be helpful. |






<a name="datapathplugins-PrepareHooksResponse-HookSpec"></a>

### PrepareHooksResponse.HookSpec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [HookType](#datapathplugins-HookType) |  | PRE/POST (for now) |
| target | [string](#string) |  | Which program are we instrumenting? |
| constraints | [PrepareHooksResponse.HookSpec.OrderingConstraint](#datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint) | repeated |  |






<a name="datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint"></a>

### PrepareHooksResponse.HookSpec.OrderingConstraint
An OrderingConstraint is a constraint about where this hook should
go at this hook point relative to other plugins&#39; hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| order | [PrepareHooksResponse.HookSpec.OrderingConstraint.Order](#datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint-Order) |  |  |
| plugin | [string](#string) |  |  |





 


<a name="datapathplugins-HookType"></a>

### HookType


| Name | Number | Description |
| ---- | ------ | ----------- |
| PRE | 0 |  |
| POST | 1 |  |



<a name="datapathplugins-PrepareHooksResponse-HookSpec-OrderingConstraint-Order"></a>

### PrepareHooksResponse.HookSpec.OrderingConstraint.Order


| Name | Number | Description |
| ---- | ------ | ----------- |
| BEFORE | 0 |  |
| AFTER | 1 |  |


 

 


<a name="datapathplugins-DatapathPlugin"></a>

### DatapathPlugin


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| PrepareHooks | [PrepareHooksRequest](#datapathplugins-PrepareHooksRequest) | [PrepareHooksResponse](#datapathplugins-PrepareHooksResponse) |  |
| LoadHooks | [LoadHooksRequest](#datapathplugins-LoadHooksRequest) | [LoadHooksResponse](#datapathplugins-LoadHooksResponse) |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

