Plugin.define do
  name "Interstellar"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Interstellar, an open-source web proxy front end, from the anonymous landing shell it serves: a data-shell marker, the /assets/js/main.js application script and the thesaurus decoy favicon. The shell is served by both the static and the built deployment, but it carries no release, so version extraction is a gap."
  website "https://github.com/UseInterstellar/Interstellar"

  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*data-shell=["']true["'])(?=.*src=["']\/assets\/js\/main\.js["'])(?=.*href=["']\/assets\/media\/favicon\/thesaurus\.png["'])/mi,
      :name => "Interstellar landing shell (data-shell, application script, decoy favicon)",
    },
  ]
end
