# METADATA
# title: Minimum VME Manager Version
# description: The VM Essentials Appliance must be running a recent version 
# related_resources:
# - ref: https://example.com
# custom:
#  severity: MEDIUM
#  tags: ["demo","sec1"]
package ore
import rego.v1

policy_title := rego.metadata.chain()[1].annotations.title
policy_description := rego.metadata.chain()[1].annotations.description
policy_severity := rego.metadata.chain()[1].annotations.custom.severity
policy_requirement := "8.0.12"

violations contains message if {

	input.manager_version == policy_requirement

	annotation := rego.metadata.rule()
	message := {
		"object": "appliance",
		"severity": policy_severity,
		"message": policy_description,
		"details": sprintf("The VM Essentials manager appliace is running %s which is lower than the version configured in the policy of %s", [input.manager_version, policy_requirement]),
	}
}