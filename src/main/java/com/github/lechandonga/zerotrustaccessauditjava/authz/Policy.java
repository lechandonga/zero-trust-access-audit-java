package com.github.lechandonga.zerotrustaccessauditjava.authz;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 授权策略的不可变快照。更新时整体替换，保证并发读要么看到旧策略、
 * 要么看到新策略，绝不出现半更新状态。
 *
 * @param rules 规则列表，按顺序匹配，任一规则允许则允许；默认拒绝
 */
public record Policy(List<Rule> rules) {

    public Policy {
        rules = List.copyOf(rules);
    }

    /**
     * 一条授权规则：角色 + 资源属性约束 + 动作。
     *
     * @param role          适用角色
     * @param action        动作，如 read / write / audit:read
     * @param resourceType  资源类型，如 document / audit
     * @param requiredAttrs 资源必须满足的属性约束（key -> 期望值，支持 "*" 通配）
     */
    public record Rule(String role, String action, String resourceType, Map<String, String> requiredAttrs) {

        public Rule {
            requiredAttrs = requiredAttrs == null ? Map.of() : Map.copyOf(requiredAttrs);
        }

        public boolean matches(Set<String> roles, String reqAction, String reqResourceType,
                               Map<String, String> resourceAttrs) {
            if (!roles.contains(role) || !action.equals(reqAction) || !resourceType.equals(reqResourceType)) {
                return false;
            }
            for (Map.Entry<String, String> e : requiredAttrs.entrySet()) {
                String actual = resourceAttrs.get(e.getKey());
                if (actual == null || (!e.getValue().equals("*") && !e.getValue().equals(actual))) {
                    return false;
                }
            }
            return true;
        }
    }

    public boolean isAllowed(Set<String> roles, String action, String resourceType,
                             Map<String, String> resourceAttrs) {
        return rules.stream().anyMatch(r -> r.matches(roles, action, resourceType, resourceAttrs));
    }
}
