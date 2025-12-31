TF=cd infra/terraform && ./tf.sh

plan-dev:
	$(TF) dev plan

apply-dev:
	$(TF) dev apply

plan-stage:
	$(TF) stage plan

apply-stage:
	$(TF) stage apply

plan-prod:
	$(TF) prod plan

apply-prod:
	$(TF) prod apply
