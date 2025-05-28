Plugin.define do
  name "Fortinet FortiCamera"
  authors [
    "Threat Intel Platform User (Adapted by AI)"
  ]
  version "0.1"
  description "FortiCameras are network-connected IP surveillance cameras that integrate with FortiRecorder NVRs and FortiCentral for centralized management."
  website "https://www.fortinet.com/products/network-based-video-security/forticam-fortirecorder"

  matches [
    {
      :search => "headers[www-authenticate]",
      :regexp => /realm="FortiCamera"/,
      :name => "FortiCamera WWW-Authenticate Realm"
    }
  ]
end