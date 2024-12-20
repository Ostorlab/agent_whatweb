Plugin.define do
  name "Fortinet FortiWLM"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Fortinet Wireless Manager (FortiWLM) is used to monitor, operate, and administer wireless networks on FortiGates that are managed by FortiManager."
  website "https://docs.fortinet.com/document/fortimanager/6.4.0/administration-guide/679601/wireless-manager-fortiwlm"

  matches [
    {
      :regexp => /<title>FortiWLM Login<\/title>/,
      :name => "FortiWLM Title tag"
    }
  ]
end
