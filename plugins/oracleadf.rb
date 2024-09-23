Plugin.define do
  name "OracleADF"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Oracle ADF is an end-to-end Java EE framework that simplifies application development by providing out-of-the-box infrastructure services and a visual and declarative development experience."
  website "https://www.oracle.com/database/technologies/developer-tools/adf/"

  matches [
    {
      :search => "headers[X-ORACLE-DMS-ECID]",
      :regexp => /.+/,
      :name => "X-ORACLE-DMS-ECID Header Present"
    },
  ]
end