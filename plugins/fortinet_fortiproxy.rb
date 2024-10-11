Plugin.define do
  name "fortinet_fortiproxy"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "FortiProxy delivers broad protection and visibility to every network segment, device, and appliance, whether deployed virtually, in the cloud, or on-premises."
  website "https://www.fortinet.com/products/secure-web-gateway/fortiproxy"

  matches [
    {
      :search => "body",
      :regexp => /FortiProxy/,
      :name => "FortiProxy Body Content"
    }
  ]
end
