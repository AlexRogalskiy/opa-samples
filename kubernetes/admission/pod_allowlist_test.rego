package kubernetes.admission_test

import data.kubernetes.admission

test_allow_happy_path {
	admission.deny == set() with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "banzaicloud",
			"containers": [{"image": "banzaicloud/pipeline"}],
			"nodeSelector": {"failure-domain.beta.kubernetes.io/region": "europe-west1"},
		}},
	}}
}

test_deny_bad_node_selector {
	admission.deny["pod with serviceAccount \"banzaicloud\", image \"banzaicloud/pipeline\" is not allowed at the specified location"] with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "banzaicloud",
			"containers": [{"image": "banzaicloud/pipeline"}],
			"nodeSelector": {"failure-domain.beta.kubernetes.io/region": "us-west2"},
		}},
	}}
}

test_deny_non_whitelisted_service_account {
	admission.deny["pod with serviceAccount \"default\", image \"banzaicloud/pipeline\" is not allowed"] with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "default",
			"containers": [{"image": "banzaicloud/pipeline"}],
		}},
	}}
}

test_deny_whitelisted_service_account_with_non_whitelisted_image {
	admission.deny["pod with serviceAccount \"banzaicloud\", image \"banzaicloud/not-allowed-app\" is not allowed"] with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "banzaicloud",
			"containers": [
				{"image": "banzaicloud/pipeline"},
				{"image": "banzaicloud/not-allowed-app"},
			],
		}},
	}}
}
