Plugin.define do
  name "fortinet fortipam"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "FortiPAM provides tightly controlled privileged access to the most sensitive resources within an organization. "
  website "https://www.fortinet.com/products/fortipam"

  matches [
    {
      :search => "body",
      :regexp => /FortiPAM/,
      :name => "FortiPAM Body Content"
    }
  ]
end
