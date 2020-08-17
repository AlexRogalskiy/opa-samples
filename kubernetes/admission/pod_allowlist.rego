package kubernetes.admission

allowlist = {"banzaicloud": {
	"banzaicloud/pipeline",
	"banzaicloud/backyards",
}}

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	# input.request.namespace == "opa-example"
	serviceAccount := input.request.object.spec.serviceAccountName
	image := input.request.object.spec.containers[_].image
	not allowlist[serviceAccount][image]

	# allowedImages := allowlist[serviceAccount]
	# not glob_match_one_of(allowlist, serviceAccount)
	msg := sprintf("pod serviceAccount %q with image %q is not allowed", [serviceAccount, image])
}
