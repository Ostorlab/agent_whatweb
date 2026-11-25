##
# cnpmcore fingerprint for the asset inventory and vulnerable-component
# matching.
#
# cnpmcore is a private npm registry server. Its public `/` total-data document
# is a JSON object that carries `instance_start_time`, `app_version`, `engine`,
# `sync_model`, `source_registry` and an integer `doc_count`. A plain npm
# registry document and an arbitrary JSON API do not carry that combination.
#
# The release is the authoritative `app_version` field, so the inventory gets
# a version for component matching. The Asteroid rule reads the same document
# and then checks `/-/registry`; this plugin performs no extra request.
#
# WhatWeb precompiles the `:version` regexp as the match regexp, so this single
# expression must both identify the product and capture the release.
##
Plugin.define do
  name "cnpmcore"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies cnpmcore, a private npm registry server, from its public total-data JSON document and extracts the app_version release."
  website "https://github.com/cnpm/cnpmcore"

  matches [
    {
      :search => "body",
      :version => /\A\s*\{[\s\S]{0,4000}?"doc_count"\s*:\s*[0-9]+[\s\S]{0,4000}?"sync_model"\s*:\s*"[^"]*"[\s\S]{0,4000}?"instance_start_time"\s*:\s*"[^"]+"[\s\S]{0,4000}?"app_version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"[\s\S]{0,4000}?"engine"\s*:\s*"[^"]+"[\s\S]{0,4000}?"source_registry"\s*:\s*"[^"]+"/,
      :name => "cnpmcore total-data document",
    },
  ]
end
