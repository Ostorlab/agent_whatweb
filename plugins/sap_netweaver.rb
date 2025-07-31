Plugin.define do
  name "SAP NetWeaver"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "SAP NetWeaver is an application and integration platform that serves as the technical foundation for many SAP applications. It provides a comprehensive set of technologies for building and integrating enterprise applications."
  website "https://www.sap.com/products/netweaver-platform.html"

  matches [
    {
      :search => "headers[server]",
      :regexp => /SAP NetWeaver Application Server/i,
      :name => "SAP NetWeaver Server Header"
    },
    {
      :search => "headers[server]",
      :regexp => /AS Java/i,
      :name => "SAP NetWeaver AS Java"
    },
    {
      :search => "body",
      :regexp => /SAP NetWeaver/i,
      :name => "SAP NetWeaver in Body"
    },
    {
      :search => "head",
      :regexp => /<title>.*SAP NetWeaver.*<\/title>/i,
      :name => "SAP in Title"
    },
  ]

  # Version detection for SAP NetWeaver
  version [
    {
      :search => "headers[server]",
      :regexp => /SAP NetWeaver Application Server ([\d\.]+)/i,
      :offset => 0
    }
  ]
end
