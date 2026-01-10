# METADATA
# title: Allow Ones
# description: Lockout
# related_resources:
# - ref: https://example.com
# custom:
#  severity: HIGH
#  tags: ["demo","sec1"]
package ore
import rego.v1

policy_title := rego.metadata.chain()[1].annotations.title
policy_description := rego.metadata.chain()[1].annotations.description
policy_severity := rego.metadata.chain()[1].annotations.custom.severity
policy_requirement := "6"

violations contains message if {

	input.appliance_settings.disableAfterAttempts < policy_requirement

	annotation := rego.metadata.rule()
	message := {
		"object": "user",
		"severity": policy_severity,
		"message": policy_description,
		"details": sprintf("The disable user login after of %s attempts is lower than the configured policy of %s", [input.appliance_settings.disableAfterAttempts, policy_requirement]),
	}
}