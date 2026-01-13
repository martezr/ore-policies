# METADATA
# title: Require Instance Tags
# description: All instances must have assigned tags
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

violations contains message if {
    some instance in input.instances
    instance.tags == []
	
	annotation := rego.metadata.rule()
	message := {
		"object": "instance",
		"severity": policy_severity,
		"message": policy_description,
		"details": sprintf("The instance name %s does not have any tags assigned", [instance.name]),
	}
}



