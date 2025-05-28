Plugin.define do
  name "Fortinet FortiNDR"
  authors [
    "Ostorlab"
    ]
  version "0.1"
  description "FortiNDR (Network Detection and Response) provides AI-powered breach protection, identifying and stopping threats that bypass traditional security controls."
  website "https://www.fortinet.com/products/network-detection-and-response"

  matches [
    {
      :regexp => /<title>FortiNDR<\/title>/,
      :name => "FortiNDR Title"
    }
  ]
end