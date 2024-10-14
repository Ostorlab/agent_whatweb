Plugin.define do
  name "Fortinet FortiOS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "FortiOS enables the convergence of security and networking to close security gaps and simplify management. "
  website "https://www.fortinet.com/products/fortigate/fortios"

  matches [
    {
      :search => "headers[Server]",
      :regexp => /Fortinet FortiOS/,
      :name => "FortiOS Server Header"
    }
  ]
end
