#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./tf.sh dev plan
#   ./tf.sh stage apply
#   ./tf.sh prod plan
#   ./tf.sh prod apply
#
# Requires:
# - backend.lower.hcl / backend.prod.hcl
# - env/dev.tfvars env/stage.tfvars env/prod.tfvars

ENVIRONMENT="${1:-}"
CMD="${2:-}"
shift 2 || true

if [[ -z "${ENVIRONMENT}" || -z "${CMD}" ]]; then
  echo "Usage: $0 <dev|stage|prod> <init|plan|apply|destroy|output> [extra terraform args...]"
  exit 1
fi

if [[ "${ENVIRONMENT}" != "dev" && "${ENVIRONMENT}" != "stage" && "${ENVIRONMENT}" != "prod" ]]; then
  echo "Environment must be one of: dev, stage, prod"
  exit 1
fi

BACKEND_FILE="backend.lower.hcl"
AWS_PROFILE="lower"

if [[ "${ENVIRONMENT}" == "prod" ]]; then
  BACKEND_FILE="backend.prod.hcl"
  AWS_PROFILE="prod"
fi

# Guardrails:
# - prod workspace must only be used with prod backend/profile
# - lower backends must never run prod workspace
if [[ "${ENVIRONMENT}" == "prod" && "${AWS_PROFILE}" != "prod" ]]; then
  echo "Guardrail: prod environment must use AWS profile 'prod'"
  exit 1
fi
if [[ "${ENVIRONMENT}" != "prod" && "${ENVIRONMENT}" == "prod" ]]; then
  echo "Guardrail: unexpected environment logic"
  exit 1
fi

export AWS_PROFILE="${AWS_PROFILE}"
export AWS_SDK_LOAD_CONFIG=1

TFVARS="env/${ENVIRONMENT}.tfvars"

if [[ ! -f "${TFVARS}" ]]; then
  echo "Missing tfvars file: ${TFVARS}"
  exit 1
fi

# Choose init behavior:
# - If you switch between prod/lower, you MUST reconfigure.
# - We'll always use -reconfigure to be safe; it's not harmful, just slightly slower.
init() {
  terraform init -reconfigure -backend-config="${BACKEND_FILE}"
}

select_workspace() {
  # In separate accounts, same workspace names are safe.
  terraform workspace select "${ENVIRONMENT}" >/dev/null 2>&1 || terraform workspace new "${ENVIRONMENT}" >/dev/null
}

case "${CMD}" in
  init)
    init
    select_workspace
    echo "Ready: env=${ENVIRONMENT} profile=${AWS_PROFILE} backend=${BACKEND_FILE} workspace=${ENVIRONMENT}"
    ;;

  plan)
    init
    select_workspace
    terraform plan -var-file="${TFVARS}" "$@"
    ;;

  apply)
    init
    select_workspace
    terraform apply -var-file="${TFVARS}" "$@"
    ;;

  destroy)
    init
    select_workspace
    terraform destroy -var-file="${TFVARS}" "$@"
    ;;

  output)
    init
    select_workspace
    terraform output "$@"
    ;;

  *)
    echo "Unknown command: ${CMD}"
    echo "Allowed: init, plan, apply, destroy, output"
    exit 1
    ;;
esac
