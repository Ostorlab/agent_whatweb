Plugin.define do
  name "ServiceNow"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "ServiceNow is a cloud computing platform that helps companies manage digital workflows for global enterprises."
  website "https://www.servicenow.com/"

  matches [
    {
      :search => "body",
      :regexp => /<span class="sr-only">ServiceNow Home Page<\/span>/i,
      :name => "ServiceNow Home Page Span Text"
    },
  ]
end
