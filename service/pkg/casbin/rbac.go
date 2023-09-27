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
	Sub string
	Obj string
	Act string
}

type RbacPolicyList struct {
	TotalCount int               `json:"totalCount"`
	Items      []*RbacPolicyItem `json:"items"`
}

func (rpl *RbacPolicyList) ConvertToListPolicyResponse(msg string, status v1.Status) v1.ListPolicyResponse {
	policies := make([]*v1.Policy, 0, 16)

	for _, item := range rpl.Items {
		policies = append(policies, &v1.Policy{
			Sub: item.Sub,
			Obj: item.Obj,
			Act: item.Act,
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
	r = sub, obj, act
	
	[policy_definition]
	p = sub, obj, act
	
	[role_definition]
	g = _, _
	g2 = _, _
	
	[policy_effect]
	e = some(where (p.eft == allow))
	
	[matchers]
	m = g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act || r.sub=="%s"
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
	if hasPolicy := rp.enforcer.HasPolicy(rq.Sub, rq.Obj, rq.Act); hasPolicy {
		return fmt.Errorf("policy alread exists")
	}
	if ok, err := rp.enforcer.AddPolicy(rq.Sub, rq.Obj, rq.Act); !ok {
		return fmt.Errorf("failed to create policy create, details: %s", err.Error())
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
			Sub: pol[0],
			Obj: pol[1],
			Act: pol[2],
		}

		items = append(items, &item)
	}
	result.Items = items
	result.TotalCount = len(items)

	return &result, nil
}

func (rp *rbacpolicy) Delete(ctx context.Context, rq *v1.DeletePolicyRequest) error {
	if hasPolicy := rp.enforcer.HasPolicy(rq.Sub, rq.Obj, rq.Act); !hasPolicy {
		return fmt.Errorf("policy not found")
	}
	if ok, err := rp.enforcer.RemovePolicy(rq.Sub, rq.Obj, rq.Act); !ok {
		return err
	} else {
		return nil
	}
}

// add user to role
func (rp *rbacpolicy) AddSubGroup(ctx context.Context, rq *v1.AddSubGroupRequest) error {
	if hasPolicy := rp.enforcer.HasNamedGroupingPolicy("g", rq.Sub, rq.Group); hasPolicy {
		return fmt.Errorf("user: %s already belong to the group: %s", rq.Sub, rq.Group)
	}
	if ok, err := rp.enforcer.AddNamedGroupingPolicy("g", rq.Sub, rq.Group); !ok {
		return err
	} else {
		return nil
	}

}

func (rp *rbacpolicy) RemoveSubGroup(ctx context.Context, rq *v1.RemoveSubGroupRequest) error {
	if hasPolicy := rp.enforcer.HasNamedGroupingPolicy("g", rq.Sub, rq.Group); !hasPolicy {
		return fmt.Errorf("user: %s not belongs to the group: %s", rq.Sub, rq.Group)
	}
	if ok, err := rp.enforcer.RemoveNamedGroupingPolicy("g", rq.Sub, rq.Group); !ok {
		return err
	} else {
		return nil
	}

}

// resource group
func (rp *rbacpolicy) AddObjGroup(ctx context.Context, rq *v1.AddObjGroupRequest) error {
	if hasPolicy := rp.enforcer.HasNamedGroupingPolicy("g2", rq.Obj, rq.Group); hasPolicy {
		return fmt.Errorf("resource:%s  alread belong to the group: %s", rq.Obj, rq.Group)
	}
	if ok, err := rp.enforcer.AddNamedGroupingPolicy("g2", rq.Obj, rq.Group); !ok {
		return err
	} else {
		return nil
	}
}

func (rp *rbacpolicy) RemoveObjGroup(ctx context.Context, rq *v1.RemoveObjGroupRequest) error {
	if hasPolicy := rp.enforcer.HasNamedGroupingPolicy("g2", rq.Obj, rq.Group); !hasPolicy {
		return fmt.Errorf("resource:%s  not belong to the group: %s", rq.Obj, rq.Group)
	}
	if ok, err := rp.enforcer.RemoveNamedGroupingPolicy("g2", rq.Obj, rq.Group); !ok {
		return err
	} else {
		return nil
	}
}

func (rp *rbacpolicy) FilterAllowed(ctx context.Context, rq *v1.FilterAllowedRequest) (*AlloweResource, error) {
	filtered := make([]string, 0, 16)

	for _, obj := range rq.ResourceList {
		if isAllowed, err := rp.enforcer.Enforce(rq.Sub, obj, rq.Act); err != nil {
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
