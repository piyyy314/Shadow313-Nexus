# Shadow313 NEXUS — OPA Policy: Read-Only Root Filesystem
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container '%s' in Deployment '%s' must have readOnlyRootFilesystem: true",
    [container.name, input.metadata.name])
}
