# METADATA
# title: Enforce Instance Tags
# description: A set of rules that determines if x is allowed.
package ore
import rego.v1

policy_title := rego.metadata.chain()[1].annotations.title
policy_description := rego.metadata.chain()[1].annotations.description

# METADATA
# title: Allow Ones
# description: MFA required for users
# custom:
#  severity: HIGH
violations contains message if {
    some instance in input.instances # it exists in the input.servers collection and...
    instance.tags == [] # it contains the "telnet" protocol.
	
	annotation := rego.metadata.rule()
	message := {
		"object": "user",
		"severity": annotation.custom.severity,
		"message": annotation.description,
		"details": sprintf("User %s does not have MFA configured", [instance.name]),
	}
}



