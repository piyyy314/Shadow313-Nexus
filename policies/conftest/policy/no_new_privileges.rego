# Shadow313 NEXUS — OPA Policy: No New Privileges
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("Container '%s' in Deployment '%s' must set allowPrivilegeEscalation: false",
    [container.name, input.metadata.name])
}
