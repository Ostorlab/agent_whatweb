# Behavioral check for the Apache Solr plugin's dual-marker requirement.
#
# Usage: ruby plugin_solr_check.rb <plugins directory>
# Exits 1 if the Solr-like page does not match or a lookalike does.

class Plugin
  @plugins = []

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  def name(value = nil)
    @name = value unless value.nil?
    @name
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(*_args, &_block)
    nil
  end

  def respond_to_missing?(*_args)
    true
  end
end

SOLR_LANDING = <<~HTML
  <!doctype html>
  <html ng-app="solrAdminApp">
  <head><title>Solr Admin</title></head>
  <body><div id="solr-admin"></div></body>
  </html>
HTML

TITLE_ONLY = <<~HTML
  <!doctype html>
  <html><head><title>Solr Admin</title></head>
  <body>title only</body></html>
HTML

APP_ONLY = <<~HTML
  <!doctype html>
  <html ng-app="solrAdminApp"><head><title>Dashboard</title></head>
  <body>app only</body></html>
HTML

DASHBOARD = <<~HTML
  <!doctype html>
  <html><head><title>Operations Dashboard</title></head>
  <body>hello</body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "solr.rb")
plugin = Plugin.plugins.last
patterns = plugin.matches.flat_map { |match| match.values.grep(Regexp) }

def matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "Solr-like landing did not match" unless matched?(patterns, SOLR_LANDING)
failures << "title-only lookalike matched" if matched?(patterns, TITLE_ONLY)
failures << "ng-app-only lookalike matched" if matched?(patterns, APP_ONLY)
failures << "unrelated dashboard matched" if matched?(patterns, DASHBOARD)

puts failures
exit(failures.empty? ? 0 : 1)
