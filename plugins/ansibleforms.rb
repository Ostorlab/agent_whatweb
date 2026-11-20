Plugin.define do
  name "AnsibleForms"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies AnsibleForms, a self-hosted web application that turns Ansible automation into self-service forms. The landing document is the Vue client; the product's release is served separately on its API and is not extracted here."
  website "https://github.com/ansibleforms/ansibleforms"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*Ansible Forms\s*<\/title>/i,
      :name => "AnsibleForms landing title",
    },
  ]
end
