# Register the returns-processor agent: identity bound to the container image digest
spire-server entry create \
  -spiffeID spiffe://corp.example/agents/returns-processor \
  -parentID spiffe://corp.example/spire/agent/k8s_psat/prod-cluster/node-7 \
  -selector k8s:ns:agents \
  -selector k8s:sa:returns-processor \
  -selector docker:image_id:sha256:9f2c...e1 \
  -x509SVIDTTL 3600
