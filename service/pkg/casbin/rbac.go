package casbin

import (
	"context"
	"fmt"
	"sync"

	casbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	v1 "github.com/superjcd/policyservice/genproto/v1"
	"gorm.io/gorm"
)

type policy struct {
	enforcer *casbin.Enforcer
}

func (p *policy) Rbac() RbacPolicy {
	return &rbacpolicy{enforcer: p.enforcer}
}

type rbacpolicy struct {
	enforcer *casbin.Enforcer
}

type RbacPolicyItem struct {
	User   string
	Domain string
	Obj    string
	Act    string
}

type RbacPolicyList struct {
	TotalCount int               `json:"totalCount"`
	Items      []*RbacPolicyItem `json:"items"`
}

func (rpl *RbacPolicyList) ConvertToListPolicyResponse(msg string, status v1.Status) v1.ListPolicyResponse {
	policies := make([]*v1.Policy, 0, 16)

	for _, item := range rpl.Items {
		policies = append(policies, &v1.Policy{
			User:   item.User,
			Domain: item.Domain,
			Obj:    item.Obj,
			Act:    item.Act,
		})
	}

	return v1.ListPolicyResponse{
		Msg:      msg,
		Status:   status,
		Policies: policies,
	}
}

type AlloweResource struct {
	TotalCount int `json:"totalCount"`
	Items      []string
}

func (ar *AlloweResource) ConvertToFilterAllowedResponse(msg string, status v1.Status) v1.FilterAllowedResponse {
	return v1.FilterAllowedResponse{
		Msg:                 msg,
		Status:              status,
		AllowedResourceList: ar.Items,
	}
}

var (
	rbac_policy Policy
	once        sync.Once
	rbac_model  = `
	[request_definition]
	r = sub, dom, obj, act
	
	[policy_definition]
	p = sub, dom, obj, act
	
	[role_definition]
	g = _, _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act || r.sub=="%s"
	`
) // 注意， superadmin会拥有所有权限

func NewRbacPolicy(db *gorm.DB, superadmin string) (Policy, error) {
	var enforcer *casbin.Enforcer
	var err error

	if db == nil && rbac_policy == nil {
		return nil, fmt.Errorf("failed to get rbac policy")
	}

	once.Do(func() {
		adapter, _ := gormadapter.NewAdapterByDB(db) // This will create a table caller casbin-rule
		rbac_model := fmt.Sprintf(rbac_model, superadmin)
		m, _ := model.NewModelFromString(rbac_model)
		enforcer, err = casbin.NewEnforcer(m, adapter)
		rbac_policy = &policy{enforcer: enforcer}
	})

	if err != nil {
		return nil, err
	}
	return rbac_policy, nil
}

func (rp *rbacpolicy) Create(ctx context.Context, rq *v1.CreatePolicyRequest) error {
	if hasPolicy := rp.enforcer.HasPolicy(rq.User, rq.Domain, rq.Obj, rq.Act); hasPolicy {
		return fmt.Errorf("Policy已经存在")
	}
	if ok, err := rp.enforcer.AddPolicy(rq.User, rq.Domain, rq.Obj, rq.Act); !ok {
		return fmt.Errorf("policy创建失败, 失败原因: %s", err.Error())
	} else {
		return nil
	}

}

// list用户不同资源组别的
func (rp *rbacpolicy) List(ctx context.Context, rq *v1.ListPolicyRequest) (*RbacPolicyList, error) {
	var result RbacPolicyList
	policies := rp.enforcer.GetPolicy()
	items := make([]*RbacPolicyItem, 0, 16)

	for _, pol := range policies {
		item := RbacPolicyItem{
			User:   pol[0],
			Domain: pol[1],
			Obj:    pol[2],
			Act:    pol[3],
		}

		items = append(items, &item)
	}
	result.Items = items
	result.TotalCount = len(items)

	return &result, nil
}

func (rp *rbacpolicy) Delete(ctx context.Context, rq *v1.DeletePolicyRequest) error {
	if hasPolicy := rp.enforcer.HasPolicy(rq.User, rq.Domain, rq.Obj, rq.Act); !hasPolicy {
		return fmt.Errorf("Policy不存在")
	}
	if ok, err := rp.enforcer.RemovePolicy(rq.User, rq.Domain, rq.Obj, rq.Act); !ok {
		return err
	} else {
		return nil
	}
}

// add usr groups
func (rp *rbacpolicy) AddGroup(ctx context.Context, rq *v1.AddGroupRequest) error {

	if hasPolicy := rp.enforcer.HasGroupingPolicy(rq.User, rq.Group, rq.Domain); hasPolicy {
		return fmt.Errorf("用户已添加到该group")
	}
	if ok, err := rp.enforcer.AddGroupingPolicy(rq.User, rq.Group, rq.Domain); !ok {
		return err
	} else {
		return nil
	}
}

// TODO: add resource group , 比如所有按站点区分店铺， （metabase目前的问题是没资源组， 我需要对所有资源一一进行赋值） 资源组别的命名, 例如: shop_allshops(这个最好在一开始的时候init一下), group

func (rp *rbacpolicy) FilterAllowed(ctx context.Context, rq *v1.FilterAllowedRequest) (*AlloweResource, error) {
	filtered := make([]string, 0, 16)

	for _, obj := range rq.ResourceList {
		if isAllowed, err := rp.enforcer.Enforce(rq.User, rq.Domain, obj, rq.Act); err != nil {
			return nil, err
		} else {
			if isAllowed {
				filtered = append(filtered, obj)
			}
		}
	}

	return &AlloweResource{
		TotalCount: len(filtered),
		Items:      filtered,
	}, nil

}
