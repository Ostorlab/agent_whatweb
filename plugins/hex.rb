Plugin.define do
  name "Hex"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Hex (hexpm), the package manager for the Erlang and Elixir ecosystem, from its landing document title and the exact Erlang-ecosystem package-manager meta description. The landing carries no release, and the CVE-2026-129514 rule is behavioural rather than version-gated, so version extraction is not required."
  website "https://hex.pm"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Hex\s*<\/title>)(?=.*<meta[^>]+name=["']description["'][^>]+content=["']A package manager for the Erlang ecosystem["'])/mi,
      :name => "Hex landing title and Erlang ecosystem description",
    },
  ]
end
