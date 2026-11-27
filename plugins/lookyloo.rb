##
# Lookyloo fingerprint for the asset inventory and vulnerable-component
# matching.
#
# Lookyloo is a web forensics tool. Its default footer carries the product
# name and the installed release:
#
#   <strong>Lookyloo</strong> <span class="lk-footer-version">v1.43.1</span>
#
# The release is the authoritative package version rendered by the footer, so
# the inventory gets a version for component matching. The Asteroid
# CVE-2026-137826 rule reads the same footer and then exercises the public
# pull route; this plugin performs no extra request.
#
# WhatWeb precompiles the :version regexp as the match regexp, so this single
# expression must both identify the product and capture the release.
##
Plugin.define do
  name "Lookyloo"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Lookyloo, a web forensics tool, and its release from the versioned product footer."
  website "https://www.lookyloo.eu"

  matches [
    {
      :search => "body",
      :version => /<strong>\s*Lookyloo\s*<\/strong>\s*<span\s+class=["']lk-footer-version["']\s*>\s*v?([0-9]+(?:\.[0-9]+)+)\s*<\/span>/mi,
      :name => "Lookyloo footer version",
    },
  ]
end
