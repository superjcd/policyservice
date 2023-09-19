package service

import (
	"context"
	"time"

	"github.com/HooYa-Bigdata/policyservice/config"
	v1 "github.com/HooYa-Bigdata/policyservice/genproto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NewClient New service's client
func NewClient(conf *config.Config) (v1.PolicyServiceClient, error) {

	serverAddress := conf.Grpc.Host + conf.Grpc.Port
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := v1.NewPolicyServiceClient(conn)
	return client, nil

}
