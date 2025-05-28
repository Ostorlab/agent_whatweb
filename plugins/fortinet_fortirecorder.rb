Plugin.define do
  name "Fortinet FortiRecorder"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "FortiRecorder network video recorders (NVRs) capture, store, and analyze video from FortiCameras, providing comprehensive video surveillance."
  website "https://www.fortinet.com/products/network-based-video-security/forticam-fortirecorder"

  matches [
    {
      :regexp => /<title>FortiRecorder Admin<\/title>/,
      :name => "FortiRecorder Admin Title"
    }
  ]
end