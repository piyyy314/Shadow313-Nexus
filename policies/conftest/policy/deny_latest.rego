# Shadow313 NEXUS — OPA Policy: Deny :latest image tag
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container '%s' uses ':latest' tag — pin to a specific digest or version",
    [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not contains(container.image, ":")
  msg := sprintf("Container '%s' has no image tag — pin to a specific digest or version",
    [container.name])
}
