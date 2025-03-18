Plugin.define do
  name "Jetty - Apache Camel"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Apache Camel is an open source framework for message-oriented middleware. Apache Camel is the industry standard for reducing boilerplate code for complex integrations — while maintaining features like: Automatic error handling. Redelivery policies."
  website "https://camel.apache.org/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /jetty/i,
      :name => "Jetty Server Header"
    }
  ]
end
