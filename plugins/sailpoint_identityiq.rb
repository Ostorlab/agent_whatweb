Plugin.define do
  name "SailPoint IdentityIQ"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "SailPoint IdentityIQ is an identity and access management software platform custom-built for complex enterprises."
  website "https://www.sailpoint.com/products/identity-security-software/identity-iq"

  matches [
    {
      :search => "head",
      :regexp => /<title>SailPoint IdentityIQ<\/title>/,
      :name => "SailPoint IdentityIQ Title Tag"
    },
  ]
end