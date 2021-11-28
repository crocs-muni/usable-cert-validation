require "jekyll"
require "htmlbeautifier"

module Jekyll
  module Beautify
    def self.init(site)
      config = site.config
      @include_paths = (config["html-beautify"] && config["html-beautify"]["include"]) || []
    end

    def self.include?(path)
      return @include_paths.any? { |pattern| File.fnmatch(pattern, path) }
    end

    def self.process_file(file)
      if Beautify.include?(file.relative_path)
        file.output = HtmlBeautifier.beautify(file.output)
      end
    end

    def self.process_site(site)
      Jekyll.logger.info  "                  * Beautifying HTML ..."

      site.documents.each do |doc|
        Beautify.process_file(doc)
      end

      site.pages.each do |page|
        Beautify.process_file(page)
      end
    end
  end

  Hooks.register :site, :after_reset do |site|
    Jekyll::Beautify.init(site)
  end

  Hooks.register :site, :post_render do |site|
    Jekyll::Beautify.process_site(site)
  end
end
