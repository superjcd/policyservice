package policy

import (
	"context"

	v1 "github.com/superjcd/policyservice/genproto/v1"
)

type Policy interface {
	Rbac() RbacPolicy
}

type RbacPolicy interface {
	Create(_ context.Context, _ *v1.CreatePolicyRequest) error
	List(_ context.Context, _ *v1.ListPolicyRequest) (*RbacPolicyList, error)
	Delete(_ context.Context, _ *v1.DeletePolicyRequest) error
	AddGroup(_ context.Context, _ *v1.AddGroupRequest) error
	FilterAllowed(_ context.Context, _ *v1.FilterAllowedRequest) (*AlloweResource, error)
}
