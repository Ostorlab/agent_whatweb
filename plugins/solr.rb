Plugin.define do
  name "Apache Solr"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Apache Solr, the open-source search platform, from the admin application served at the standard /solr/ context. The landing document carries no release, and the version document (/solr/admin/info/system) is not fetched at default aggression, so version extraction is a gap."
  website "https://solr.apache.org"

  # Both markers are required so a page that only reuses the title or the
  # Angular application name is not reported as Solr.
  matches [
    {
      :search => "body",
      :regexp => /\A(?=.*<title[^>]*>\s*Solr Admin\s*<\/title>)(?=.*ng-app=["']solrAdminApp["'])/mi,
      :name => "Solr Admin title and application marker",
    },
  ]
end
