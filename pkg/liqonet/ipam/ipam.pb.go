// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.15.5
// source: pkg/liqonet/ipam/ipam.proto

package ipam

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MapRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClusterID string `protobuf:"bytes,1,opt,name=clusterID,proto3" json:"clusterID,omitempty"`
	Ip        string `protobuf:"bytes,2,opt,name=ip,proto3" json:"ip,omitempty"`
}

func (x *MapRequest) Reset() {
	*x = MapRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MapRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapRequest) ProtoMessage() {}

func (x *MapRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapRequest.ProtoReflect.Descriptor instead.
func (*MapRequest) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{0}
}

func (x *MapRequest) GetClusterID() string {
	if x != nil {
		return x.ClusterID
	}
	return ""
}

func (x *MapRequest) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

type MapResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ip string `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
}

func (x *MapResponse) Reset() {
	*x = MapResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MapResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MapResponse) ProtoMessage() {}

func (x *MapResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MapResponse.ProtoReflect.Descriptor instead.
func (*MapResponse) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{1}
}

func (x *MapResponse) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

type UnmapRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClusterID string `protobuf:"bytes,1,opt,name=clusterID,proto3" json:"clusterID,omitempty"`
	Ip        string `protobuf:"bytes,2,opt,name=ip,proto3" json:"ip,omitempty"`
}

func (x *UnmapRequest) Reset() {
	*x = UnmapRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnmapRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnmapRequest) ProtoMessage() {}

func (x *UnmapRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnmapRequest.ProtoReflect.Descriptor instead.
func (*UnmapRequest) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{2}
}

func (x *UnmapRequest) GetClusterID() string {
	if x != nil {
		return x.ClusterID
	}
	return ""
}

func (x *UnmapRequest) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

type UnmapResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *UnmapResponse) Reset() {
	*x = UnmapResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UnmapResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnmapResponse) ProtoMessage() {}

func (x *UnmapResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnmapResponse.ProtoReflect.Descriptor instead.
func (*UnmapResponse) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{3}
}

type GetHomePodIPRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ClusterID string `protobuf:"bytes,1,opt,name=clusterID,proto3" json:"clusterID,omitempty"`
	Ip        string `protobuf:"bytes,2,opt,name=ip,proto3" json:"ip,omitempty"`
}

func (x *GetHomePodIPRequest) Reset() {
	*x = GetHomePodIPRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHomePodIPRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHomePodIPRequest) ProtoMessage() {}

func (x *GetHomePodIPRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHomePodIPRequest.ProtoReflect.Descriptor instead.
func (*GetHomePodIPRequest) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{4}
}

func (x *GetHomePodIPRequest) GetClusterID() string {
	if x != nil {
		return x.ClusterID
	}
	return ""
}

func (x *GetHomePodIPRequest) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

type GetHomePodIPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HomeIP string `protobuf:"bytes,1,opt,name=homeIP,proto3" json:"homeIP,omitempty"`
}

func (x *GetHomePodIPResponse) Reset() {
	*x = GetHomePodIPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHomePodIPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHomePodIPResponse) ProtoMessage() {}

func (x *GetHomePodIPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_liqonet_ipam_ipam_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHomePodIPResponse.ProtoReflect.Descriptor instead.
func (*GetHomePodIPResponse) Descriptor() ([]byte, []int) {
	return file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP(), []int{5}
}

func (x *GetHomePodIPResponse) GetHomeIP() string {
	if x != nil {
		return x.HomeIP
	}
	return ""
}

var File_pkg_liqonet_ipam_ipam_proto protoreflect.FileDescriptor

var file_pkg_liqonet_ipam_ipam_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x70, 0x6b, 0x67, 0x2f, 0x6c, 0x69, 0x71, 0x6f, 0x6e, 0x65, 0x74, 0x2f, 0x69, 0x70,
	0x61, 0x6d, 0x2f, 0x69, 0x70, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3a, 0x0a,
	0x0a, 0x4d, 0x61, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x63,
	0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x44, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x70, 0x22, 0x1d, 0x0a, 0x0b, 0x4d, 0x61, 0x70,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x70, 0x22, 0x3c, 0x0a, 0x0c, 0x55, 0x6e, 0x6d, 0x61,
	0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6c, 0x75, 0x73,
	0x74, 0x65, 0x72, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6c, 0x75,
	0x73, 0x74, 0x65, 0x72, 0x49, 0x44, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x70, 0x22, 0x0f, 0x0a, 0x0d, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x43, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x48, 0x6f,
	0x6d, 0x65, 0x50, 0x6f, 0x64, 0x49, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c,
	0x0a, 0x09, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x49, 0x44, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x70, 0x22, 0x2e, 0x0a, 0x14,
	0x47, 0x65, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x6f, 0x64, 0x49, 0x50, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x68, 0x6f, 0x6d, 0x65, 0x49, 0x50, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x68, 0x6f, 0x6d, 0x65, 0x49, 0x50, 0x32, 0xa1, 0x01, 0x0a,
	0x04, 0x69, 0x70, 0x61, 0x6d, 0x12, 0x2a, 0x0a, 0x0d, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x64, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x49, 0x50, 0x12, 0x0b, 0x2e, 0x4d, 0x61, 0x70, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x0c, 0x2e, 0x4d, 0x61, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x30, 0x0a, 0x0f, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x49, 0x50, 0x12, 0x0d, 0x2e, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x0e, 0x2e, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x0c, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x6f,
	0x64, 0x49, 0x50, 0x12, 0x14, 0x2e, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x6f, 0x64,
	0x49, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x15, 0x2e, 0x47, 0x65, 0x74, 0x48,
	0x6f, 0x6d, 0x65, 0x50, 0x6f, 0x64, 0x49, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2f, 0x69, 0x70, 0x61, 0x6d, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_pkg_liqonet_ipam_ipam_proto_rawDescOnce sync.Once
	file_pkg_liqonet_ipam_ipam_proto_rawDescData = file_pkg_liqonet_ipam_ipam_proto_rawDesc
)

func file_pkg_liqonet_ipam_ipam_proto_rawDescGZIP() []byte {
	file_pkg_liqonet_ipam_ipam_proto_rawDescOnce.Do(func() {
		file_pkg_liqonet_ipam_ipam_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_liqonet_ipam_ipam_proto_rawDescData)
	})
	return file_pkg_liqonet_ipam_ipam_proto_rawDescData
}

var file_pkg_liqonet_ipam_ipam_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_pkg_liqonet_ipam_ipam_proto_goTypes = []interface{}{
	(*MapRequest)(nil),           // 0: MapRequest
	(*MapResponse)(nil),          // 1: MapResponse
	(*UnmapRequest)(nil),         // 2: UnmapRequest
	(*UnmapResponse)(nil),        // 3: UnmapResponse
	(*GetHomePodIPRequest)(nil),  // 4: GetHomePodIPRequest
	(*GetHomePodIPResponse)(nil), // 5: GetHomePodIPResponse
}
var file_pkg_liqonet_ipam_ipam_proto_depIdxs = []int32{
	0, // 0: ipam.MapEndpointIP:input_type -> MapRequest
	2, // 1: ipam.UnmapEndpointIP:input_type -> UnmapRequest
	4, // 2: ipam.GetHomePodIP:input_type -> GetHomePodIPRequest
	1, // 3: ipam.MapEndpointIP:output_type -> MapResponse
	3, // 4: ipam.UnmapEndpointIP:output_type -> UnmapResponse
	5, // 5: ipam.GetHomePodIP:output_type -> GetHomePodIPResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_pkg_liqonet_ipam_ipam_proto_init() }
func file_pkg_liqonet_ipam_ipam_proto_init() {
	if File_pkg_liqonet_ipam_ipam_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MapRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MapResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnmapRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UnmapResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHomePodIPRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_liqonet_ipam_ipam_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHomePodIPResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_liqonet_ipam_ipam_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_liqonet_ipam_ipam_proto_goTypes,
		DependencyIndexes: file_pkg_liqonet_ipam_ipam_proto_depIdxs,
		MessageInfos:      file_pkg_liqonet_ipam_ipam_proto_msgTypes,
	}.Build()
	File_pkg_liqonet_ipam_ipam_proto = out.File
	file_pkg_liqonet_ipam_ipam_proto_rawDesc = nil
	file_pkg_liqonet_ipam_ipam_proto_goTypes = nil
	file_pkg_liqonet_ipam_ipam_proto_depIdxs = nil
}
