package service

import (
	"context"

	"github.com/HooYa-Bigdata/policyservice/config"
	v1 "github.com/HooYa-Bigdata/policyservice/genproto/v1"
	"github.com/HooYa-Bigdata/policyservice/pkg/database"
	policy "github.com/HooYa-Bigdata/policyservice/service/pkg/casbin"
	"gorm.io/gorm"
)

var _DB *gorm.DB

// Server Server struct
type Server struct {
	v1.UnimplementedPolicyServiceServer
	policy policy.Policy
	client v1.PolicyServiceClient
	conf   *config.Config
}

// NewServer New service grpc server
func NewServer(conf *config.Config, client v1.PolicyServiceClient) (v1.PolicyServiceServer, error) {
	_DB = database.MustPreParePostgresqlDb(&conf.Pg)
	policy, err := policy.NewRbacPolicy(_DB)

	if err != nil {
		return nil, err
	}

	server := &Server{
		client: client,
		policy: policy,
		conf:   conf,
	}

	return server, nil
}

func (s *Server) CreatePolicy(ctx context.Context, rq *v1.CreatePolicyRequest) (*v1.CreatePolicyResponse, error) {
	if err := s.policy.Rbac().Create(ctx, rq); err != nil {
		return &v1.CreatePolicyResponse{Msg: "Create policy failed", Status: v1.Status_failure}, err
	}

	return &v1.CreatePolicyResponse{Msg: "Create policy successed", Status: v1.Status_success}, nil
}

func (s *Server) ListPolicy(ctx context.Context, rq *v1.ListPolicyRequest) (*v1.ListPolicyResponse, error) {
	list, err := s.policy.Rbac().List(ctx, rq)
	if err != nil {
		return &v1.ListPolicyResponse{Msg: "Get policy filed", Status: v1.Status_failure}, err
	}

	result := list.ConvertToListPolicyResponse("Get policy successed", v1.Status_success)

	return &result, nil
}

func (s *Server) DeletePolicy(ctx context.Context, rq *v1.DeletePolicyRequest) (*v1.DeletePolicyResponse, error) {
	if err := s.policy.Rbac().Delete(ctx, rq); err != nil {
		return &v1.DeletePolicyResponse{Msg: "Delete policy failed", Status: v1.Status_failure}, err
	}

	return &v1.DeletePolicyResponse{Msg: "Delet policy successed", Status: v1.Status_success}, nil
}

func (s *Server) AddGroup(ctx context.Context, rq *v1.AddGroupRequest) (*v1.AddGroupResponse, error) {
	if err := s.policy.Rbac().AddGroup(ctx, rq); err != nil {
		return &v1.AddGroupResponse{Msg: "Add group failed", Status: v1.Status_failure}, err
	}

	return &v1.AddGroupResponse{Msg: "Add group successed", Status: v1.Status_success}, nil
}

func (s *Server) FilterAllowed(ctx context.Context, rq *v1.FilterAllowedRequest) (*v1.FilterAllowedResponse, error) {
	list, err := s.policy.Rbac().FilterAllowed(ctx, rq)
	if err != nil {
		return &v1.FilterAllowedResponse{Msg: "Get filtered objects filed", Status: v1.Status_failure}, err
	}

	result := list.ConvertToFilterAllowedResponse("Get filtered objects successed", v1.Status_success)

	return &result, nil
}
