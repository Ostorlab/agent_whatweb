Plugin.define do
  name "Fortinet FortiVoice"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "FortiVoice enterprise IP-PBX voice solutions provide total call control and sophisticated communication features for excellent customer service."
  website "https://www.fortinet.com/products/business-phone-systems/fortivoice-fortifone"

  matches [
    {
      :regexp => /<title>FortiVoice<\/title>/,
      :name => "FortiVoice Title"
    }
  ]
end