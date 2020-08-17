package kubernetes.admission

allowlist = [{
	"serviceAccount": "banzaicloud",
	"images": {"banzaicloud/pipeline", "banzaicloud/backyards"},
	"nodeSelector": {},
}]

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	# input.request.namespace == "opa-example"
	serviceAccount := input.request.object.spec.serviceAccountName
	image := input.request.object.spec.containers[_].image

	not imageWithServiceAccountAllowed(serviceAccount, image)

	# not allowlist[serviceAccount][image]

	# allowedImages := allowlist[serviceAccount]
	# not glob_match_one_of(allowlist, serviceAccount)
	msg := sprintf("pod serviceAccount %q with image %q is not allowed", [serviceAccount, image])
}

imageWithServiceAccountAllowed(serviceAccount, image) {
	allowlist[_].serviceAccount == serviceAccount
	allowlist[_].images[image]
}
