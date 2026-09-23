# Shadow313 NEXUS — OPA Policy: Require Resource Limits
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container '%s' in Deployment '%s' must have memory limits",
    [container.name, input.metadata.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container '%s' in Deployment '%s' must have CPU limits",
    [container.name, input.metadata.name])
}
