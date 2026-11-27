##
# VirtueMart fingerprint for the asset inventory and vulnerable-component
# matching.
#
# VirtueMart is a Joomla ecommerce component. Every page that loads the
# component also loads its public assets through vmJsApi::cssSite(), so the
# landing carries a stable product marker:
#
#   <link href="/components/com_virtuemart/assets/css/vm-ltr-site.css?vmver=..."
#
# The `vmver` query value is a crc32 of the install path and revision, not a
# release, so this plugin identifies the product without claiming a version.
# The Asteroid CVE-2026-133335 rule reads the same storefront assets and then
# exercises the controller-fallback include; this plugin performs no extra
# request.
##
Plugin.define do
  name "VirtueMart"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies the VirtueMart ecommerce component for Joomla from its public asset path."
  website "https://virtuemart.net/"

  matches [
    {
      :search => "body",
      :regexp => %r{(?:/components/com_virtuemart/assets/|vmCartModule)},
      :name => "VirtueMart asset path",
      :certainty => 75,
    },
  ]
end
