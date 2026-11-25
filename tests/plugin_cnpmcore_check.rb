# Behavioral check for the cnpmcore plugin's total-data document markers.
#
# Usage: ruby plugin_cnpmcore_check.rb <plugins directory>
# Exits 1 if a genuine cnpmcore document does not match, the version is not
# extracted, or a lookalike matches.

class Plugin
  @plugins = []
  ALLOWED = %i[name authors version description website dorks matches passive aggressive].freeze

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  ALLOWED.each do |attribute|
    define_method(attribute) do |value = nil|
      instance_variable_set("@#{attribute}", value) unless value.nil?
      instance_variable_get("@#{attribute}")
    end
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(name, *_args, &_block)
    raise NoMethodError, "unknown WhatWeb Plugin DSL attribute: #{name}"
  end

  def respond_to_missing?(_name, _include_private = false)
    ALLOWED.include?(_name)
  end
end

PRODUCT_3X = '{"last_package":"","last_package_version":"","doc_count":0,"doc_version_count":0,"download":{"today":0},"update_seq":0,"sync_model":"none","sync_changes_steam":{},"sync_binary":false,"instance_start_time":"2026-11-25T17:38:50.723Z","node_version":"v22.23.5","app_version":"3.84.2","engine":"pg","source_registry":"https://registry.npmjs.org","changes_stream_registry":"https://replicate.npmjs.com","cache_time":"2026-11-25T17:38:51.228Z","upstream_registries":[]}'
PRODUCT_4X = <<~JSON
  {
    "doc_count": 12,
    "sync_model": "all",
    "instance_start_time": "2026-11-25T17:38:50.723Z",
    "node_version": "v22.23.5",
    "app_version": "4.37.2",
    "engine": "mysql",
    "source_registry": "https://registry.npmmirror.com",
    "changes_stream_registry": "https://replicate.npmjs.com"
  }
JSON

NPM_REGISTRY_LOOKALIKE = '{"db_name":"registry","doc_count":0,"engine":"npm"}'
PARTIAL_JSON_LOOKALIKE = '{"app_version":"3.84.2","doc_count":0,"source_registry":"https://registry.npmjs.org"}'
HTML_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>cnpmcore - a private npm registry</title></head>
  <body><p>Install cnpmcore 3.84.2 from npm.</p></body></html>
HTML
GITHUB_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>GitHub - cnpm/cnpmcore</title></head>
  <body><p>A private npm registry. app_version: 3.84.2 engine: pg doc_count: 0</p></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "cnpmcore.rb")
plugin = Plugin.plugins.last

def match_for(plugin, page)
  plugin.matches.find do |match|
    next false if match[:url]

    hit = false
    hit ||= page.match?(match[:regexp]) if match[:regexp].is_a?(Regexp)
    hit ||= page.match?(match[:version]) if match[:version].is_a?(Regexp)
    hit ||= page.include?(match[:text]) if match[:text].is_a?(String)
    hit
  end
end

def page_matched?(plugin, page)
  !match_for(plugin, page).nil?
end

def version_for(plugin, page)
  match = match_for(plugin, page)
  return nil if match.nil? || !match[:version].is_a?(Regexp)

  hit = page.match(match[:version])
  hit && hit[1]
end

failures = []
failures << "3.x document did not match" unless page_matched?(plugin, PRODUCT_3X)
failures << "4.x document did not match" unless page_matched?(plugin, PRODUCT_4X)
failures << "3.x version was not extracted" unless version_for(plugin, PRODUCT_3X) == "3.84.2"
failures << "4.x version was not extracted" unless version_for(plugin, PRODUCT_4X) == "4.37.2"
failures << "npm registry lookalike matched" if page_matched?(plugin, NPM_REGISTRY_LOOKALIKE)
failures << "partial JSON lookalike matched" if page_matched?(plugin, PARTIAL_JSON_LOOKALIKE)
failures << "HTML lookalike matched" if page_matched?(plugin, HTML_LOOKALIKE)
failures << "GitHub lookalike matched" if page_matched?(plugin, GITHUB_LOOKALIKE)

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
