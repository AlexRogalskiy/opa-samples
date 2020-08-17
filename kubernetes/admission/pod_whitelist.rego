package kubernetes.admission

whitelist = {"banzaicloud": {
	"banzaicloud/pipeline",
	"banzaicloud/backyards",
}}

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	# input.request.namespace == "opa-example"
	serviceAccount := input.request.object.spec.serviceAccountName
	image := input.request.object.spec.containers[_].image
	not whitelist[serviceAccount][image]

	# allowedImages := whitelist[serviceAccount]
	# not glob_match_one_of(whitelist, serviceAccount)
	msg := sprintf("pod serviceAccount %q with image %q is not allowed", [serviceAccount, image])
}
