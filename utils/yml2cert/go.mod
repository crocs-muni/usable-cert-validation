module github.com/crocs-muni/usable-cert-validation/utils/yml2cert

go 1.13

require (
	github.com/crocs-muni/usable-cert-validation/utils/yml2cert/cryptobyte v0.0.0
	github.com/crocs-muni/usable-cert-validation/utils/yml2cert/cryptobyte/asn1 v0.0.0
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace (
	github.com/crocs-muni/usable-cert-validation/utils/yml2cert/cryptobyte => ./cryptobyte
	github.com/crocs-muni/usable-cert-validation/utils/yml2cert/cryptobyte/asn1 => ./cryptobyte/asn1
)
