{{- /* nomad-netblock config from the job variable nomad/jobs/<job>. Only netblock keys are rendered (never other keys such as tokens). */ -}}
{{- $p := printf "nomad/jobs/%s" (env "NOMAD_JOB_NAME") -}}
{{- if nomadVarExists $p -}}{{- with nomadVar $p -}}
{{- range $k, $v := . }}{{ if (or (eq $k "mode") (eq $k "allow_cidrs") (eq $k "egress_allow") (eq $k "allow_services") (eq $k "dns_resolver") (eq $k "include_critical") (eq $k "removal_grace") (eq $k "consul_addr") (eq $k "consul_addrs") (eq $k "run_as") (eq $k "allow_nomad_services") (eq $k "nomad_addr") (eq $k "consul_tls_server_name") (eq $k "init_require_consul") (eq $k "exempt_match")) }}
{{ $k }} = {{ $v }}
{{- end }}{{ end }}
{{- end -}}{{- end }}
