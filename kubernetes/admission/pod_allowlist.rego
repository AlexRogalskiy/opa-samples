package kubernetes.admission

allowlist = [{
	"serviceAccount": "banzaicloud",
	"images": {"banzaicloud/pipeline", "banzaicloud/backyards"},
	"nodeSelector": [{"failure-domain.beta.kubernetes.io/region": "europe-west1"}], # possible nodeSelector combinations we allow
}]

deny[msg] {
	input.request.kind.kind == "Pod"
	input.request.operation == "CREATE"

	# input.request.namespace == "opa-example"
	serviceAccount := input.request.object.spec.serviceAccountName
	image := input.request.object.spec.containers[_].image

	nodeSelector := object.get(input.request.object.spec, "nodeSelector", {})

	not imageWithServiceAccountAllowed(serviceAccount, image, nodeSelector)

	msg := sprintf("pod serviceAccount %q with image %q is not allowed", [serviceAccount, image])
}

imageWithServiceAccountAllowed(serviceAccount, image, nodeSelector) {
	allowlist[a].serviceAccount == serviceAccount
	allowlist[a].images[image]
	selcount := count(allowlist[a].nodeSelector[ns])
	count({k | allowlist[a].nodeSelector[s][k] == nodeSelector[k]}) == selcount
}
