package authz

import rego.v1

default compliant = false

compliant if {
	input.manager_version == "8.0.7-2"
}