#!/bin/bash

kubectl create namespace opa

kubectl label namespaces opa openpolicyagent.org/webhook=ignore

helm upgrade --install opa stable/opa --namespace opa \
    --values helm-values.yaml

kubectl create configmap opa-main --from-file=./kubernetes/admission/main.rego -n opa

kubectl label -n opa configmap opa-main openpolicyagent.org/policy=rego

kubectl create configmap opa-pod-allowlist --from-file=./kubernetes/admission/pod_allowlist.rego -n opa

kubectl label -n opa configmap opa-pod-allowlist openpolicyagent.org/policy=rego

