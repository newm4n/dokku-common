package dokku_common

import (
	"strings"
)

// UserIsAllowedInAudience make sure that a JWT aud array can be accepted by a certain
// tenant and role requirement.
// The audiene array must contains string with the pattern of 'role1,role2@tenant' for each string.
// The tenant must contains the tenant identifier as mentioned in the audience array.
// The role must contains on of the role mentioned in the Audience array.
// Please check the relevant test to see how it work.
func UserIsAllowedInAudience(audiene []string, tenant, role string) bool {
	for _, aud := range audiene {
		if userIsAllowed(aud, tenant, role) {
			return true
		}
	}
	return false
}

func userIsAllowed(tenantRole, tenant, role string) bool {
	if len(tenant) == 0 || len(role) == 0 || len(tenantRole) == 0 {
		return false
	}
	trSplit := strings.Split(tenantRole, "@")
	if len(trSplit) != 2 {
		return false
	}
	if len(trSplit[0]) == 0 || len(trSplit[1]) == 0 {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(trSplit[1]), strings.TrimSpace(tenant)) {
		return false
	}
	for _, str := range strings.Split(trSplit[0], ",") {
		if strings.EqualFold(strings.TrimSpace(role), strings.TrimSpace(str)) {
			return true
		}
	}
	return false
}

func StringInArray(arr []string, check string) bool {
	if arr == nil {
		return false
	}
	if len(check) == 0 {
		return true
	}
	for _, el := range arr {
		if el == check {
			return true
		}
	}
	return false
}
