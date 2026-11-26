# Behavioral check for the Xen Orchestra plugin's product-specific markers.
#
# Usage: ruby plugin_xen_orchestra_check.rb <plugins directory>
# Exits 1 if a genuine Xen Orchestra landing does not match or a lookalike does.

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

  def respond_to_missing?(name, _include_private = false)
    ALLOWED.include?(name)
  end
end

XEN_ORCHESTRA_LANDING = <<~HTML
  <!DOCTYPE html><html class="no-js" dir="ltr" lang="en"><head><meta charset="utf-8">
  <title>Xen Orchestra</title><link rel="stylesheet" href="index.css">
  <link rel="manifest" href="assets/manifest.webmanifest"></head>
  <body><div id="xo-app"><img src="assets/loading.svg"></div>
  <script src="index.js"></script></body></html>
HTML

TITLE_ONLY = <<~HTML
  <!DOCTYPE html><html><head><title>Xen Orchestra</title></head>
  <body>Xen Orchestra documentation and a mention of the project.</body></html>
HTML

CONTAINER_ONLY = <<~HTML
  <!DOCTYPE html><html><head><title>Acme Console</title></head>
  <body><div id="xo-app">Unrelated application.</div></body></html>
HTML

OTHER_PRODUCT = <<~HTML
  <!DOCTYPE html><html><head><title>XenServer Console</title></head>
  <body><div id="app">A different virtualization product.</div></body></html>
HTML

plugins_directory = ARGV[0] or abort "usage: ruby plugin_xen_orchestra_check.rb <plugins directory>"
load File.join(plugins_directory, "xen_orchestra.rb")

plugin = Plugin.plugins.fetch(0)
regexp = plugin.matches.fetch(0).fetch(:regexp)

cases = {
  "Xen Orchestra landing" => [XEN_ORCHESTRA_LANDING, true],
  "title-only page" => [TITLE_ONLY, false],
  "container-only page" => [CONTAINER_ONLY, false],
  "other product" => [OTHER_PRODUCT, false],
}

failures = cases.filter_map do |name, (body, expected)|
  actual = !regexp.match(body).nil?
  "#{name}: expected #{expected}, got #{actual}" if actual != expected
end

if failures.empty?
  puts "plugin_xen_orchestra_check: all #{cases.length} cases passed"
else
  warn failures.join("\n")
  exit 1
end
