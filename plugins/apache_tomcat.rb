Plugin.define do
  name "Apache Tomcat"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Apache Tomcat (called Tomcat for short) is a free and open-source implementation of the Jakarta Servlet, Jakarta Expression Language, and WebSocket technologies."
  website "https://tomcat.apache.org/"

  matches [
    {
      :search => "head",
      :regexp => /<title>Apache Tomcat/,
      :name => "On-Prem License Workspace Generator Title Tag"
    },
  ]
end