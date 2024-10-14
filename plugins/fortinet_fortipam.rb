Plugin.define do
  name "Fortinet FortiPAM"
  authors [
    "Ostorlab",
  ]
  version "0.2"
  description "FortiPAM provides tightly controlled privileged access to the most sensitive resources within an organization."
  website "https://www.fortinet.com/products/fortipam"

  matches [
    {
      :regexp => /<img[^>]*src="[^"]*\/FortiPAM\.png"[^>]*>/,
      :name => "FortiPAM Image"
    },
    {
      :regexp => /<img[^>]*class="navbar-brand"[^>]*src="[^"]*\/FortiPAM\.png"[^>]*>/,
      :name => "FortiPAM Navbar Image"
    }
  ]
end