// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: policy.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	PolicyService_CreatePolicy_FullMethodName  = "/superjcd.policyservice.v1.PolicyService/CreatePolicy"
	PolicyService_ListPolicy_FullMethodName    = "/superjcd.policyservice.v1.PolicyService/ListPolicy"
	PolicyService_DeletePolicy_FullMethodName  = "/superjcd.policyservice.v1.PolicyService/DeletePolicy"
	PolicyService_AddSubGroup_FullMethodName   = "/superjcd.policyservice.v1.PolicyService/AddSubGroup"
	PolicyService_AddObjGroup_FullMethodName   = "/superjcd.policyservice.v1.PolicyService/AddObjGroup"
	PolicyService_FilterAllowed_FullMethodName = "/superjcd.policyservice.v1.PolicyService/FilterAllowed"
)

// PolicyServiceClient is the client API for PolicyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PolicyServiceClient interface {
	CreatePolicy(ctx context.Context, in *CreatePolicyRequest, opts ...grpc.CallOption) (*CreatePolicyResponse, error)
	ListPolicy(ctx context.Context, in *ListPolicyRequest, opts ...grpc.CallOption) (*ListPolicyResponse, error)
	DeletePolicy(ctx context.Context, in *DeletePolicyRequest, opts ...grpc.CallOption) (*DeletePolicyResponse, error)
	AddSubGroup(ctx context.Context, in *AddSubGroupRequest, opts ...grpc.CallOption) (*AddSubGroupResponse, error)
	AddObjGroup(ctx context.Context, in *AddObjGroupRequest, opts ...grpc.CallOption) (*AddObjGroupResponse, error)
	FilterAllowed(ctx context.Context, in *FilterAllowedRequest, opts ...grpc.CallOption) (*FilterAllowedResponse, error)
}

type policyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPolicyServiceClient(cc grpc.ClientConnInterface) PolicyServiceClient {
	return &policyServiceClient{cc}
}

func (c *policyServiceClient) CreatePolicy(ctx context.Context, in *CreatePolicyRequest, opts ...grpc.CallOption) (*CreatePolicyResponse, error) {
	out := new(CreatePolicyResponse)
	err := c.cc.Invoke(ctx, PolicyService_CreatePolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) ListPolicy(ctx context.Context, in *ListPolicyRequest, opts ...grpc.CallOption) (*ListPolicyResponse, error) {
	out := new(ListPolicyResponse)
	err := c.cc.Invoke(ctx, PolicyService_ListPolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) DeletePolicy(ctx context.Context, in *DeletePolicyRequest, opts ...grpc.CallOption) (*DeletePolicyResponse, error) {
	out := new(DeletePolicyResponse)
	err := c.cc.Invoke(ctx, PolicyService_DeletePolicy_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) AddSubGroup(ctx context.Context, in *AddSubGroupRequest, opts ...grpc.CallOption) (*AddSubGroupResponse, error) {
	out := new(AddSubGroupResponse)
	err := c.cc.Invoke(ctx, PolicyService_AddSubGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) AddObjGroup(ctx context.Context, in *AddObjGroupRequest, opts ...grpc.CallOption) (*AddObjGroupResponse, error) {
	out := new(AddObjGroupResponse)
	err := c.cc.Invoke(ctx, PolicyService_AddObjGroup_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) FilterAllowed(ctx context.Context, in *FilterAllowedRequest, opts ...grpc.CallOption) (*FilterAllowedResponse, error) {
	out := new(FilterAllowedResponse)
	err := c.cc.Invoke(ctx, PolicyService_FilterAllowed_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PolicyServiceServer is the server API for PolicyService service.
// All implementations must embed UnimplementedPolicyServiceServer
// for forward compatibility
type PolicyServiceServer interface {
	CreatePolicy(context.Context, *CreatePolicyRequest) (*CreatePolicyResponse, error)
	ListPolicy(context.Context, *ListPolicyRequest) (*ListPolicyResponse, error)
	DeletePolicy(context.Context, *DeletePolicyRequest) (*DeletePolicyResponse, error)
	AddSubGroup(context.Context, *AddSubGroupRequest) (*AddSubGroupResponse, error)
	AddObjGroup(context.Context, *AddObjGroupRequest) (*AddObjGroupResponse, error)
	FilterAllowed(context.Context, *FilterAllowedRequest) (*FilterAllowedResponse, error)
	mustEmbedUnimplementedPolicyServiceServer()
}

// UnimplementedPolicyServiceServer must be embedded to have forward compatible implementations.
type UnimplementedPolicyServiceServer struct {
}

func (UnimplementedPolicyServiceServer) CreatePolicy(context.Context, *CreatePolicyRequest) (*CreatePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreatePolicy not implemented")
}
func (UnimplementedPolicyServiceServer) ListPolicy(context.Context, *ListPolicyRequest) (*ListPolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPolicy not implemented")
}
func (UnimplementedPolicyServiceServer) DeletePolicy(context.Context, *DeletePolicyRequest) (*DeletePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeletePolicy not implemented")
}
func (UnimplementedPolicyServiceServer) AddSubGroup(context.Context, *AddSubGroupRequest) (*AddSubGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddSubGroup not implemented")
}
func (UnimplementedPolicyServiceServer) AddObjGroup(context.Context, *AddObjGroupRequest) (*AddObjGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddObjGroup not implemented")
}
func (UnimplementedPolicyServiceServer) FilterAllowed(context.Context, *FilterAllowedRequest) (*FilterAllowedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FilterAllowed not implemented")
}
func (UnimplementedPolicyServiceServer) mustEmbedUnimplementedPolicyServiceServer() {}

// UnsafePolicyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PolicyServiceServer will
// result in compilation errors.
type UnsafePolicyServiceServer interface {
	mustEmbedUnimplementedPolicyServiceServer()
}

func RegisterPolicyServiceServer(s grpc.ServiceRegistrar, srv PolicyServiceServer) {
	s.RegisterService(&PolicyService_ServiceDesc, srv)
}

func _PolicyService_CreatePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_CreatePolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, req.(*CreatePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_ListPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).ListPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_ListPolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).ListPolicy(ctx, req.(*ListPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_DeletePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeletePolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_DeletePolicy_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, req.(*DeletePolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_AddSubGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddSubGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).AddSubGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_AddSubGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).AddSubGroup(ctx, req.(*AddSubGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_AddObjGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddObjGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).AddObjGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_AddObjGroup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).AddObjGroup(ctx, req.(*AddObjGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_FilterAllowed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FilterAllowedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).FilterAllowed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyService_FilterAllowed_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).FilterAllowed(ctx, req.(*FilterAllowedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PolicyService_ServiceDesc is the grpc.ServiceDesc for PolicyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PolicyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "superjcd.policyservice.v1.PolicyService",
	HandlerType: (*PolicyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreatePolicy",
			Handler:    _PolicyService_CreatePolicy_Handler,
		},
		{
			MethodName: "ListPolicy",
			Handler:    _PolicyService_ListPolicy_Handler,
		},
		{
			MethodName: "DeletePolicy",
			Handler:    _PolicyService_DeletePolicy_Handler,
		},
		{
			MethodName: "AddSubGroup",
			Handler:    _PolicyService_AddSubGroup_Handler,
		},
		{
			MethodName: "AddObjGroup",
			Handler:    _PolicyService_AddObjGroup_Handler,
		},
		{
			MethodName: "FilterAllowed",
			Handler:    _PolicyService_FilterAllowed_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "policy.proto",
}
