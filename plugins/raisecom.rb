Plugin.define do
  name "RAISECOM Gateway"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Raisecom is a global leading vendor providing comprehensive access solutions and network devices. "
  website "https://www.raisecom.com/"

  matches [
    {
      :search => "head",
      :regexp => /<META content="MSHTML \d+\.\d+\.\d+\.\d+" name=GENERATOR>/,
      :name => "MSHTML Generator Meta Tag"
    },
  ]
end
