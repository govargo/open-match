// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.0
// source: internal/api/messages.proto

package ipb

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	pb "open-match.dev/open-match/pkg/pb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type BackfillInternal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Represents a backfill entity which is used to fill partially full matches
	Backfill *pb.Backfill `protobuf:"bytes,1,opt,name=backfill,proto3" json:"backfill,omitempty"`
	// List of ticket IDs associated with a current backfill
	TicketIds []string `protobuf:"bytes,2,rep,name=ticket_ids,json=ticketIds,proto3" json:"ticket_ids,omitempty"`
}

func (x *BackfillInternal) Reset() {
	*x = BackfillInternal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_api_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BackfillInternal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BackfillInternal) ProtoMessage() {}

func (x *BackfillInternal) ProtoReflect() protoreflect.Message {
	mi := &file_internal_api_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BackfillInternal.ProtoReflect.Descriptor instead.
func (*BackfillInternal) Descriptor() ([]byte, []int) {
	return file_internal_api_messages_proto_rawDescGZIP(), []int{0}
}

func (x *BackfillInternal) GetBackfill() *pb.Backfill {
	if x != nil {
		return x.Backfill
	}
	return nil
}

func (x *BackfillInternal) GetTicketIds() []string {
	if x != nil {
		return x.TicketIds
	}
	return nil
}

var File_internal_api_messages_proto protoreflect.FileDescriptor

var file_internal_api_messages_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x6f,
	0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x1a, 0x12, 0x61, 0x70, 0x69, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x62, 0x0a, 0x10, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c,
	0x6c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x12, 0x2f, 0x0a, 0x08, 0x62, 0x61, 0x63,
	0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6f, 0x70,
	0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c,
	0x52, 0x08, 0x62, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x69,
	0x63, 0x6b, 0x65, 0x74, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09,
	0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x49, 0x64, 0x73, 0x42, 0x28, 0x5a, 0x26, 0x6f, 0x70, 0x65,
	0x6e, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x64, 0x65, 0x76, 0x2f, 0x6f, 0x70, 0x65, 0x6e,
	0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f,
	0x69, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_api_messages_proto_rawDescOnce sync.Once
	file_internal_api_messages_proto_rawDescData = file_internal_api_messages_proto_rawDesc
)

func file_internal_api_messages_proto_rawDescGZIP() []byte {
	file_internal_api_messages_proto_rawDescOnce.Do(func() {
		file_internal_api_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_api_messages_proto_rawDescData)
	})
	return file_internal_api_messages_proto_rawDescData
}

var file_internal_api_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_internal_api_messages_proto_goTypes = []interface{}{
	(*BackfillInternal)(nil), // 0: openmatch.internal.BackfillInternal
	(*pb.Backfill)(nil),      // 1: openmatch.Backfill
}
var file_internal_api_messages_proto_depIdxs = []int32{
	1, // 0: openmatch.internal.BackfillInternal.backfill:type_name -> openmatch.Backfill
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_internal_api_messages_proto_init() }
func file_internal_api_messages_proto_init() {
	if File_internal_api_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_api_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BackfillInternal); i {
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
			RawDescriptor: file_internal_api_messages_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_internal_api_messages_proto_goTypes,
		DependencyIndexes: file_internal_api_messages_proto_depIdxs,
		MessageInfos:      file_internal_api_messages_proto_msgTypes,
	}.Build()
	File_internal_api_messages_proto = out.File
	file_internal_api_messages_proto_rawDesc = nil
	file_internal_api_messages_proto_goTypes = nil
	file_internal_api_messages_proto_depIdxs = nil
}
