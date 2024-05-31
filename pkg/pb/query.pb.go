// Copyright 2019 Google LLC
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
// source: api/query.proto

package pb

import (
	reflect "reflect"
	sync "sync"

	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type QueryTicketsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Pool representing the set of Filters to be queried.
	Pool *Pool `protobuf:"bytes,1,opt,name=pool,proto3" json:"pool,omitempty"`
}

func (x *QueryTicketsRequest) Reset() {
	*x = QueryTicketsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryTicketsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryTicketsRequest) ProtoMessage() {}

func (x *QueryTicketsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryTicketsRequest.ProtoReflect.Descriptor instead.
func (*QueryTicketsRequest) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{0}
}

func (x *QueryTicketsRequest) GetPool() *Pool {
	if x != nil {
		return x.Pool
	}
	return nil
}

type QueryTicketsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Tickets that meet all the filtering criteria requested by the pool.
	Tickets []*Ticket `protobuf:"bytes,1,rep,name=tickets,proto3" json:"tickets,omitempty"`
}

func (x *QueryTicketsResponse) Reset() {
	*x = QueryTicketsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryTicketsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryTicketsResponse) ProtoMessage() {}

func (x *QueryTicketsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryTicketsResponse.ProtoReflect.Descriptor instead.
func (*QueryTicketsResponse) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{1}
}

func (x *QueryTicketsResponse) GetTickets() []*Ticket {
	if x != nil {
		return x.Tickets
	}
	return nil
}

type QueryTicketIdsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Pool representing the set of Filters to be queried.
	Pool *Pool `protobuf:"bytes,1,opt,name=pool,proto3" json:"pool,omitempty"`
}

func (x *QueryTicketIdsRequest) Reset() {
	*x = QueryTicketIdsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryTicketIdsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryTicketIdsRequest) ProtoMessage() {}

func (x *QueryTicketIdsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryTicketIdsRequest.ProtoReflect.Descriptor instead.
func (*QueryTicketIdsRequest) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{2}
}

func (x *QueryTicketIdsRequest) GetPool() *Pool {
	if x != nil {
		return x.Pool
	}
	return nil
}

type QueryTicketIdsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// TicketIDs that meet all the filtering criteria requested by the pool.
	Ids []string `protobuf:"bytes,1,rep,name=ids,proto3" json:"ids,omitempty"`
}

func (x *QueryTicketIdsResponse) Reset() {
	*x = QueryTicketIdsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryTicketIdsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryTicketIdsResponse) ProtoMessage() {}

func (x *QueryTicketIdsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryTicketIdsResponse.ProtoReflect.Descriptor instead.
func (*QueryTicketIdsResponse) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{3}
}

func (x *QueryTicketIdsResponse) GetIds() []string {
	if x != nil {
		return x.Ids
	}
	return nil
}

// BETA FEATURE WARNING:  This Request messages are not finalized and
// still subject to possible change or removal.
type QueryBackfillsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Pool representing the set of Filters to be queried.
	Pool *Pool `protobuf:"bytes,1,opt,name=pool,proto3" json:"pool,omitempty"`
}

func (x *QueryBackfillsRequest) Reset() {
	*x = QueryBackfillsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryBackfillsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryBackfillsRequest) ProtoMessage() {}

func (x *QueryBackfillsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryBackfillsRequest.ProtoReflect.Descriptor instead.
func (*QueryBackfillsRequest) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{4}
}

func (x *QueryBackfillsRequest) GetPool() *Pool {
	if x != nil {
		return x.Pool
	}
	return nil
}

// BETA FEATURE WARNING:  This Request messages are not finalized and
// still subject to possible change or removal.
type QueryBackfillsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Backfills that meet all the filtering criteria requested by the pool.
	Backfills []*Backfill `protobuf:"bytes,1,rep,name=backfills,proto3" json:"backfills,omitempty"`
}

func (x *QueryBackfillsResponse) Reset() {
	*x = QueryBackfillsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_query_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryBackfillsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryBackfillsResponse) ProtoMessage() {}

func (x *QueryBackfillsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_query_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryBackfillsResponse.ProtoReflect.Descriptor instead.
func (*QueryBackfillsResponse) Descriptor() ([]byte, []int) {
	return file_api_query_proto_rawDescGZIP(), []int{5}
}

func (x *QueryBackfillsResponse) GetBackfills() []*Backfill {
	if x != nil {
		return x.Backfills
	}
	return nil
}

var File_api_query_proto protoreflect.FileDescriptor

var file_api_query_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x61, 0x70, 0x69, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x1a, 0x12, 0x61, 0x70,
	0x69, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x2d, 0x67, 0x65, 0x6e, 0x2d, 0x6f, 0x70, 0x65, 0x6e, 0x61,
	0x70, 0x69, 0x76, 0x32, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x3a,
	0x0a, 0x13, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x23, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e,
	0x50, 0x6f, 0x6f, 0x6c, 0x52, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x22, 0x43, 0x0a, 0x14, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x2b, 0x0a, 0x07, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e,
	0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x52, 0x07, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x22,
	0x3c, 0x0a, 0x15, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x49, 0x64,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x23, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x2e, 0x50, 0x6f, 0x6f, 0x6c, 0x52, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x22, 0x2a, 0x0a,
	0x16, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x49, 0x64, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x64, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x03, 0x69, 0x64, 0x73, 0x22, 0x3c, 0x0a, 0x15, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x23, 0x0a, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x50, 0x6f, 0x6f,
	0x6c, 0x52, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x22, 0x4b, 0x0a, 0x16, 0x51, 0x75, 0x65, 0x72, 0x79,
	0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x31, 0x0a, 0x09, 0x62, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x2e, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x52, 0x09, 0x62, 0x61, 0x63, 0x6b, 0x66,
	0x69, 0x6c, 0x6c, 0x73, 0x32, 0x9a, 0x03, 0x0a, 0x0c, 0x51, 0x75, 0x65, 0x72, 0x79, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x7c, 0x0a, 0x0c, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x12, 0x1e, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x29, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x23, 0x3a, 0x01,
	0x2a, 0x22, 0x1e, 0x2f, 0x76, 0x31, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2f, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x3a, 0x71, 0x75, 0x65, 0x72,
	0x79, 0x30, 0x01, 0x12, 0x84, 0x01, 0x0a, 0x0e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63,
	0x6b, 0x65, 0x74, 0x49, 0x64, 0x73, 0x12, 0x20, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x49, 0x64,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d,
	0x61, 0x74, 0x63, 0x68, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x54, 0x69, 0x63, 0x6b, 0x65, 0x74,
	0x49, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2b, 0x82, 0xd3, 0xe4,
	0x93, 0x02, 0x25, 0x3a, 0x01, 0x2a, 0x22, 0x20, 0x2f, 0x76, 0x31, 0x2f, 0x71, 0x75, 0x65, 0x72,
	0x79, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x69,
	0x64, 0x73, 0x3a, 0x71, 0x75, 0x65, 0x72, 0x79, 0x30, 0x01, 0x12, 0x84, 0x01, 0x0a, 0x0e, 0x51,
	0x75, 0x65, 0x72, 0x79, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x12, 0x20, 0x2e,
	0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x42,
	0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x21, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x42, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x2b, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x25, 0x3a, 0x01, 0x2a, 0x22, 0x20, 0x2f,
	0x76, 0x31, 0x2f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2f,
	0x62, 0x61, 0x63, 0x6b, 0x66, 0x69, 0x6c, 0x6c, 0x73, 0x3a, 0x71, 0x75, 0x65, 0x72, 0x79, 0x30,
	0x01, 0x42, 0x98, 0x03, 0x92, 0x41, 0xe6, 0x02, 0x12, 0xbf, 0x01, 0x0a, 0x15, 0x4d, 0x4d, 0x20,
	0x4c, 0x6f, 0x67, 0x69, 0x63, 0x20, 0x28, 0x44, 0x61, 0x74, 0x61, 0x20, 0x4c, 0x61, 0x79, 0x65,
	0x72, 0x29, 0x22, 0x49, 0x0a, 0x0a, 0x4f, 0x70, 0x65, 0x6e, 0x20, 0x4d, 0x61, 0x74, 0x63, 0x68,
	0x12, 0x16, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6d,
	0x61, 0x74, 0x63, 0x68, 0x2e, 0x64, 0x65, 0x76, 0x1a, 0x23, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6d,
	0x61, 0x74, 0x63, 0x68, 0x2d, 0x64, 0x69, 0x73, 0x63, 0x75, 0x73, 0x73, 0x40, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2a, 0x56, 0x0a,
	0x12, 0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x20, 0x32, 0x2e, 0x30, 0x20, 0x4c, 0x69, 0x63, 0x65,
	0x6e, 0x73, 0x65, 0x12, 0x40, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x66, 0x6f,
	0x72, 0x67, 0x61, 0x6d, 0x65, 0x73, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x2f, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x4c, 0x49,
	0x43, 0x45, 0x4e, 0x53, 0x45, 0x32, 0x03, 0x31, 0x2e, 0x30, 0x2a, 0x02, 0x01, 0x02, 0x32, 0x10,
	0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e,
	0x3a, 0x10, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73,
	0x6f, 0x6e, 0x52, 0x3b, 0x0a, 0x03, 0x34, 0x30, 0x34, 0x12, 0x34, 0x0a, 0x2a, 0x52, 0x65, 0x74,
	0x75, 0x72, 0x6e, 0x65, 0x64, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74,
	0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x2e, 0x12, 0x06, 0x0a, 0x04, 0x9a, 0x02, 0x01, 0x07, 0x72,
	0x3d, 0x0a, 0x18, 0x4f, 0x70, 0x65, 0x6e, 0x20, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x20, 0x44, 0x6f,
	0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x21, 0x68, 0x74, 0x74,
	0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e,
	0x64, 0x65, 0x76, 0x2f, 0x73, 0x69, 0x74, 0x65, 0x2f, 0x64, 0x6f, 0x63, 0x73, 0x2f, 0x5a, 0x20,
	0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2e, 0x64, 0x65, 0x76, 0x2f, 0x6f,
	0x70, 0x65, 0x6e, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x62,
	0xaa, 0x02, 0x09, 0x4f, 0x70, 0x65, 0x6e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_query_proto_rawDescOnce sync.Once
	file_api_query_proto_rawDescData = file_api_query_proto_rawDesc
)

func file_api_query_proto_rawDescGZIP() []byte {
	file_api_query_proto_rawDescOnce.Do(func() {
		file_api_query_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_query_proto_rawDescData)
	})
	return file_api_query_proto_rawDescData
}

var file_api_query_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_api_query_proto_goTypes = []interface{}{
	(*QueryTicketsRequest)(nil),    // 0: openmatch.QueryTicketsRequest
	(*QueryTicketsResponse)(nil),   // 1: openmatch.QueryTicketsResponse
	(*QueryTicketIdsRequest)(nil),  // 2: openmatch.QueryTicketIdsRequest
	(*QueryTicketIdsResponse)(nil), // 3: openmatch.QueryTicketIdsResponse
	(*QueryBackfillsRequest)(nil),  // 4: openmatch.QueryBackfillsRequest
	(*QueryBackfillsResponse)(nil), // 5: openmatch.QueryBackfillsResponse
	(*Pool)(nil),                   // 6: openmatch.Pool
	(*Ticket)(nil),                 // 7: openmatch.Ticket
	(*Backfill)(nil),               // 8: openmatch.Backfill
}
var file_api_query_proto_depIdxs = []int32{
	6, // 0: openmatch.QueryTicketsRequest.pool:type_name -> openmatch.Pool
	7, // 1: openmatch.QueryTicketsResponse.tickets:type_name -> openmatch.Ticket
	6, // 2: openmatch.QueryTicketIdsRequest.pool:type_name -> openmatch.Pool
	6, // 3: openmatch.QueryBackfillsRequest.pool:type_name -> openmatch.Pool
	8, // 4: openmatch.QueryBackfillsResponse.backfills:type_name -> openmatch.Backfill
	0, // 5: openmatch.QueryService.QueryTickets:input_type -> openmatch.QueryTicketsRequest
	2, // 6: openmatch.QueryService.QueryTicketIds:input_type -> openmatch.QueryTicketIdsRequest
	4, // 7: openmatch.QueryService.QueryBackfills:input_type -> openmatch.QueryBackfillsRequest
	1, // 8: openmatch.QueryService.QueryTickets:output_type -> openmatch.QueryTicketsResponse
	3, // 9: openmatch.QueryService.QueryTicketIds:output_type -> openmatch.QueryTicketIdsResponse
	5, // 10: openmatch.QueryService.QueryBackfills:output_type -> openmatch.QueryBackfillsResponse
	8, // [8:11] is the sub-list for method output_type
	5, // [5:8] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_api_query_proto_init() }
func file_api_query_proto_init() {
	if File_api_query_proto != nil {
		return
	}
	file_api_messages_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_api_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryTicketsRequest); i {
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
		file_api_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryTicketsResponse); i {
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
		file_api_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryTicketIdsRequest); i {
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
		file_api_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryTicketIdsResponse); i {
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
		file_api_query_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryBackfillsRequest); i {
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
		file_api_query_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryBackfillsResponse); i {
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
			RawDescriptor: file_api_query_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_query_proto_goTypes,
		DependencyIndexes: file_api_query_proto_depIdxs,
		MessageInfos:      file_api_query_proto_msgTypes,
	}.Build()
	File_api_query_proto = out.File
	file_api_query_proto_rawDesc = nil
	file_api_query_proto_goTypes = nil
	file_api_query_proto_depIdxs = nil
}
