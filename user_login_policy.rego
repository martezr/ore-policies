# METADATA
# title: Enforce Instance Tags
# description: A set of rules that determines if x is allowed.
package ore
import rego.v1

policy_title := rego.metadata.chain()[1].annotations.title
policy_description := rego.metadata.chain()[1].annotations.description

# METADATA
# title: Allow Ones
# description: Users that have not logged in within the last 90 days
# custom:
#  severity: HIGH
violations contains message if {
    some user in input.users # it exists in the input.servers collection and...
	now := time.now_ns()
	event_ns := time.parse_rfc3339_ns(user.lastLoginDate)

	# Calculate time difference (in nanoseconds)
	time_diff_ns := now - event_ns

	# Define one hour in nanoseconds
	one_hour_ns := time.parse_duration_ns("10m")

	time_diff_ns > one_hour_ns

	annotation := rego.metadata.rule()
	message := {
		"object": "user",
		"severity": annotation.custom.severity,
		"message": annotation.description,
		"details": sprintf("User %s has not logged in within the last 90 days", [user.username]),
	}
}



