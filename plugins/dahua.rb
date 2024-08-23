Plugin.define do
  name "Dahua IP Cameras"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Dahua network IP cameras are the preferred brand among most security and IT professionals due to the low price point, high reliability, and wide compatibility with most NVRs and VMS platforms. "
  website "https://www.dahuasecurity.com/"

  matches [
    {
      :search => "body",
      :regexp => /<script\s+src="jsBase\/lib\/jquery\.js\?version=@WebVersion@"><\/script>/,
      :name => "jQuery Script Tag with @WebVersion@ Parameter"
    }
  ]
end
