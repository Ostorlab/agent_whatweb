# Behavioral check for the VirtueMart plugin's product-specific asset marker.
#
# Usage: ruby plugin_virtuemart_check.rb <plugins directory>
# Exits 1 if a genuine VirtueMart landing does not match or a lookalike does.

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

VULNERABLE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Demo store</title>
  <link rel="stylesheet" href="/components/com_virtuemart/assets/css/vm-bs5-common.css?vmver=1a2b3c4d">
  <link rel="stylesheet" href="/components/com_virtuemart/assets/css/vm-ltr-site.css?vmver=1a2b3c4d">
  </head><body class="com-virtuemart">
  <div class="vm-cart-module" id="vmCartModule">Cart is empty</div>
  <a href="/index.php?option=com_virtuemart">Shop</a>
  </body></html>
HTML

OLD = VULNERABLE.sub("vm-bs5-common.css", "vm-bs3-common.css")

FIXED = VULNERABLE

JOOMLA_ONLY = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>A Joomla site</title>
  <link rel="stylesheet" href="/media/templates/site/cassiopeia/css/template.css">
  </head><body class="com-content">A Joomla article with no shop.</body></html>
HTML

PROSE_ONLY = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Migration notes</title></head>
  <body><p>We migrated from VirtueMart to another cart last year.</p></body></html>
HTML

OTHER_COMPONENT = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Another shop</title>
  <link rel="stylesheet" href="/components/com_othercart/assets/css/shop.css">
  </head><body><div id="cartModule">Cart</div></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "virtuemart.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "vulnerable VirtueMart landing did not match" unless body_matched?(body_patterns, VULNERABLE)
failures << "old VirtueMart landing did not match" unless body_matched?(body_patterns, OLD)
failures << "fixed VirtueMart landing did not match" unless body_matched?(body_patterns, FIXED)
failures << "plain Joomla page matched" if body_matched?(body_patterns, JOOMLA_ONLY)
failures << "prose-only lookalike matched" if body_matched?(body_patterns, PROSE_ONLY)
failures << "other-component lookalike matched" if body_matched?(body_patterns, OTHER_COMPONENT)

puts failures
exit(failures.empty? ? 0 : 1)
