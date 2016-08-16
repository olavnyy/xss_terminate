class CoupaSanitize
  CUSTOM_MATCHERS = [
    # can be proc or regexp
    /<svg[\/\s]+onload/
  ]

  # Performs full sanitization + uses custom matchers to detect XSS
  def self.perform(unsanitized)
    value = RailsSanitize.white_list_sanitizer.sanitize(unsanitized.dup)
    unescaped = CGI::unescapeHTML(value.to_str)
    unless CUSTOM_MATCHERS.any? { |matcher| matcher.is_a?(Proc) ? matcher.call(unescaped) : (unescaped =~ matcher).present? }
      value = unescaped
    end
    WithoutEncodingSpecialCharsSanitizer.new.sanitize(value)
  end

  # Special Sanitizer that sets encode_special_chars: false for Loofah in order
  # to skip encoding of characters like & when outputting sanitized text.
  #
  # CAVEAT LECTOR: Use of this sanitizer is vulnerable to CVE-2015-7579. The
  # Rails::Html::FullSanitizer class was patched in version 1.0.3 to remove the
  # option to use encode_special_chars: false in order to address this
  # vulnerability. Use of encode_special_chars: false is the direct cause of
  # CVE-2015-7579.
  #
  # See: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7579
  # https://github.com/rails/rails-html-sanitizer/commit/49dfc1584c5b8e35a4ffabf8356ba3df025e8d3f
  class WithoutEncodingSpecialCharsSanitizer < ::Rails::Html::Sanitizer
    def sanitize(html, options = {})
      return unless html
      return html if html.empty?

      Loofah.fragment(html).tap do |fragment|
        remove_xpaths(fragment, ::Rails::Html::XPATHS_TO_REMOVE)
      end.text({encode_special_chars: false}.merge(options))
    end
  end

  # Performs white-list sanitization, keeps tags/attributes used by RichText editors
  def self.perform_safe(unsanitized)
    RailsSanitize.white_list_sanitizer.sanitize(unsanitized)
  end

  def self.full_document_sanitize(html, options = {})
    FullDocumentWhiteListSanitizer.new.sanitize(html, options)
  end

  # default white list sanitizer works with HTML fragment only but sometimes we need to sanitize full HTML document
  # copied from https://github.com/rails/rails-html-sanitizer/blob/v1.0.3/lib/rails/html/sanitizer.rb#L116:L132 and edited
  class FullDocumentWhiteListSanitizer < ::Rails::Html::WhiteListSanitizer
    def sanitize(html, options = {})
      return unless html
      return html if html.empty?

      loofah_document, scrubber = Loofah.document(html), options[:scrubber]

      if scrubber
        # No duck typing, Loofah ensures subclass of Loofah::Scrubber
        loofah_document.scrub!(scrubber)
      elsif allowed_tags(options) || allowed_attributes(options)
        @permit_scrubber.tags = allowed_tags(options)
        @permit_scrubber.attributes = allowed_attributes(options)
        loofah_document.scrub!(@permit_scrubber)
      else
        remove_xpaths(loofah_document, XPATHS_TO_REMOVE)
        loofah_document.scrub!(:strip)
      end

      properly_encode(loofah_document, encoding: 'UTF-8')
    end
  end

  class << self
    # This tries its best to sanitize any execution of Javascript code. That
    # includes <script> tag, href/src=javascript:xxx, onxxx mouse events
    def sanitize_script(html_text)
      doc = Nokogiri::HTML::DocumentFragment.parse(html_text)
      doc = remove_script_tags(doc)
      doc = remove_attr_with_js_protos(doc)
      doc.to_s
    end

    private

    # Removes any attribute that either has the 'onxxx' name or whose value contains
    # the "javascript:" protocol string
    def remove_attr_with_js_protos(doc)
      doc.traverse do |ele|
        ele.attributes.each do |key, attr|
          remove_js_attr(ele, key)
        end
      end
      doc
    end

    def remove_js_attr(ele, key)
      if key.start_with?('on') || ele[key] =~ /\bjavascript:/i
        ele.remove_attribute(key)
      end
    end

    # Removes all script tags
    def remove_script_tags(doc)
      doc.css(*%w(script)).each { |ele| ele.remove }
      doc
    end
  end
end
