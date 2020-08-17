package kubernetes.admission_test

import data.kubernetes.admission

test_allow_whitelisted_service_account {
	admission.deny == set() with input as {"request": {
		"operation": "CREATE",
		"kind": {"kind": "Pod"},
		"namespace": "default",
		"object": {"spec": {
			"serviceAccountName": "banzaicloud",
			"containers": [{"image": "banzaicloud/pipeline"}],
		}},
	}}
}

test_deny_non_whitelisted_service_account {
	admission.deny["pod serviceAccount \"default\" with image \"banzaicloud/pipeline\" is not allowed"] with input as {"request": {
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
	admission.deny["pod serviceAccount \"banzaicloud\" with image \"banzaicloud/not-allowed-app\" is not allowed"] with input as {"request": {
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
