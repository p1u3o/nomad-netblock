# Read-only Consul ACL policy for one job's netblock tasks.
#   consul acl policy create -name netblock-<job> -rules @consul-policy.hcl
#   consul acl token create -policy-name netblock-<job> -description "netblock <job>"
# Store the token SecretID in the task-scoped Nomad variables
#   nomad/jobs/<job>/<group>/netblock-init   key consul_token
#   nomad/jobs/<job>/<group>/netblock-watch  key consul_token

service "postgres" { policy = "read" }   # one block per entry in allow_services
service "redis"    { policy = "read" }
node_prefix ""     { policy = "read" }   # node address fallback
