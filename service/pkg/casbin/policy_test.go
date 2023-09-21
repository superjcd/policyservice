package casbin

import (
	"context"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "github.com/superjcd/policyservice/genproto/v1"
	"gorm.io/gorm"
)

var dbFile = "fake.db"
var db *gorm.DB

type FakePolicyTestSuite struct {
	suite.Suite
	Dbfile     string
	FakePolicy Policy
}

func (suite *FakePolicyTestSuite) SetupSuite() {
	file, err := os.Create(dbFile)
	assert.Nil(suite.T(), err)
	defer file.Close()

	suite.Dbfile = dbFile

	var err2 error
	db, err2 = gorm.Open(sqlite.Open(dbFile), &gorm.Config{})
	assert.Nil(suite.T(), err2)

	rbac_policy, err3 := NewRbacPolicy(db)
	assert.Nil(suite.T(), err3)
	suite.FakePolicy = rbac_policy
}

func (suite *FakePolicyTestSuite) TearDownSuite() {
	_db, _ := db.DB()
	err := _db.Close()
	assert.Nil(suite.T(), err)

	err2 := os.Remove(dbFile)
	assert.Nil(suite.T(), err2)
}

func (suite *FakePolicyTestSuite) TestAddPolicyGroup() {
	rq := &v1.AddGroupRequest{User: "Jack", Group: "group1", Domain: "outperform"}
	err := suite.FakePolicy.Rbac().AddGroup(context.Background(), rq)
	assert.Nil(suite.T(), err)
}

func (suite *FakePolicyTestSuite) TestCreatePolicy() {
	rq := &v1.CreatePolicyRequest{
		User:   "group1",
		Domain: "outperform", // domain: 一个app就只有一个， 可以在全局设置， 可以使app名称
		Obj:    "giantex",
		Act:    "read",
	}
	err := suite.FakePolicy.Rbac().Create(context.Background(), rq)
	assert.Nil(suite.T(), err)

}

func (suite *FakePolicyTestSuite) TestFilterAllowedObj() {
	rq := &v1.FilterAllowedRequest{
		ResourceList: []string{"giantex", "superbuy", "tangkula"},
		User:         "Jack",
		Domain:       "outperform",
		Act:          "read",
	}
	allowedResource, err := suite.FakePolicy.Rbac().FilterAllowed(context.Background(), rq)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 1, allowedResource.TotalCount)
	assert.Equal(suite.T(), "giantex", allowedResource.Items[0])
}

func (suite *FakePolicyTestSuite) TestXDeletePolicy() {
	rq := &v1.DeletePolicyRequest{
		User:   "group1",
		Domain: "outperform",
		Obj:    "giantex",
		Act:    "read",
	}
	err := suite.FakePolicy.Rbac().Delete(context.Background(), rq)
	assert.Nil(suite.T(), err)

	rq2 := &v1.FilterAllowedRequest{
		ResourceList: []string{"giantex", "superbuy", "tangkula"},
		User:         "Jack",
		Domain:       "outperform",
		Act:          "read",
	}
	allowedResource, err := suite.FakePolicy.Rbac().FilterAllowed(context.Background(), rq2)
	assert.Nil(suite.T(), err)
	assert.Equal(suite.T(), 0, allowedResource.TotalCount)
}

func TestFakePolicySuite(t *testing.T) {
	suite.Run(t, new(FakePolicyTestSuite))
}
