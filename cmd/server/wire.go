//go:build wireinject
// +build wireinject

package server

import (
	"github.com/HooYa-Bigdata/policyservice/config"
	v1 "github.com/HooYa-Bigdata/policyservice/genproto/v1"
	"github.com/HooYa-Bigdata/policyservice/service"
	"github.com/google/wire"
)

// InitServer Inject service's component
func InitServer(conf *config.Config) (v1.PolicyServiceServer, error) {

	wire.Build(
		service.NewClient,
		service.NewServer,
	)

	return &service.Server{}, nil

}
