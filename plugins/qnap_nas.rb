Plugin.define do
  name "QNAP Turbo NAS"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "QNAP Turbo NAS (Network Attached Storage) is the high performance and reliable storage designed to provide an affordable and easy-to-manage solution with iSCSI service for virtualized and clustered environment and reduce the total cost of ownership (TCO)."
  website "https://www.qnap.com/en/product"

  matches [
    {
      :search => "title",
      :regexp => /<title>QNAP Turbo NAS<\/title>/,
      :name => "QNAP Turbo NAS Title Tag"
    },
  ]
end