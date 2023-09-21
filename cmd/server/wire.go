//go:build wireinject
// +build wireinject

package server

import (
	"github.com/google/wire"
	"github.com/superjcd/policyservice/config"
	v1 "github.com/superjcd/policyservice/genproto/v1"
	"github.com/superjcd/policyservice/service"
)

// InitServer Inject service's component
func InitServer(conf *config.Config) (v1.PolicyServiceServer, error) {

	wire.Build(
		service.NewClient,
		service.NewServer,
	)

	return &service.Server{}, nil

}
