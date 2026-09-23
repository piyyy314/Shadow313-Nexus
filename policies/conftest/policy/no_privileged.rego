# Shadow313 NEXUS — OPA Policy: No Privileged Containers
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Container '%s' in Deployment '%s' must not run as privileged",
    [container.name, input.metadata.name])
}

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Container '%s' in Pod '%s' must not run as privileged",
    [container.name, input.metadata.name])
}
